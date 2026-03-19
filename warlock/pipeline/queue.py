"""Production message queue backends for the Warlock pipeline.

Drop-in replacements for the in-memory EventBus. All implementations
conform to the same interface so the pipeline orchestrator doesn't
need to change.

Backends:
  - RedisStreamBus — Redis Streams (persistent, supports consumer groups)
  - KafkaBus — Apache Kafka (high-throughput, partitioned)
  - SQSBus — AWS SQS (serverless, managed)
  - InMemoryBus — the existing EventBus (re-exported for convenience)

All backends use the same PipelineEvent dataclass from bus.py.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from warlock.pipeline.bus import EventBus, Handler, PipelineEvent

log = logging.getLogger(__name__)

# Re-export for convenience — callers can import everything from queue.py.
InMemoryBus = EventBus

# ---------------------------------------------------------------------------
# Optional dependency probes
# ---------------------------------------------------------------------------

_redis_available = False
try:
    import redis as _redis_mod  # type: ignore[import-untyped]

    _redis_available = True
except ImportError:
    _redis_mod = None  # type: ignore[assignment]

_kafka_available = False
_kafka_flavour: str | None = None
try:
    import confluent_kafka as _confluent_kafka  # type: ignore[import-untyped]

    _kafka_available = True
    _kafka_flavour = "confluent"
except ImportError:
    _confluent_kafka = None  # type: ignore[assignment]

if not _kafka_available:
    try:
        import kafka as _kafka_python  # type: ignore[import-untyped]

        _kafka_available = True
        _kafka_flavour = "kafka-python"
    except ImportError:
        _kafka_python = None  # type: ignore[assignment]

_boto3_available = False
try:
    import boto3 as _boto3  # type: ignore[import-untyped]

    _boto3_available = True
except ImportError:
    _boto3 = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class QueueConfig:
    """Configuration for a queue backend."""

    backend: str = "memory"  # "memory", "redis", "kafka", "sqs"
    url: str = ""  # connection URL / bootstrap servers / SQS region endpoint
    stream_prefix: str = "warlock"
    consumer_group: str = "warlock-pipeline"
    max_retries: int = 3
    batch_size: int = 100


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _event_to_dict(event: PipelineEvent) -> dict[str, str]:
    """Serialise a PipelineEvent to a flat string dict (for Redis hash fields)."""
    return {
        "id": event.id,
        "event_type": event.event_type,
        "payload_id": event.payload_id,
        "timestamp": event.timestamp.isoformat(),
        "metadata": json.dumps(event.metadata),
    }


def _event_to_json(event: PipelineEvent) -> str:
    """Serialise a PipelineEvent to a JSON string."""
    return json.dumps(
        {
            "id": event.id,
            "event_type": event.event_type,
            "payload_id": event.payload_id,
            "timestamp": event.timestamp.isoformat(),
            "metadata": event.metadata,
        }
    )


def _event_from_dict(data: dict[str, Any]) -> PipelineEvent:
    """Deserialise a PipelineEvent from a dict (string values, as from Redis)."""
    raw_ts = data.get("timestamp", "")
    if isinstance(raw_ts, str) and raw_ts:
        ts = datetime.fromisoformat(raw_ts)
    else:
        ts = datetime.now(timezone.utc)

    raw_meta = data.get("metadata", "{}")
    if isinstance(raw_meta, str):
        meta = json.loads(raw_meta)
    else:
        meta = raw_meta

    return PipelineEvent(
        event_type=str(data.get("event_type", "")),
        payload_id=str(data.get("payload_id", "")),
        timestamp=ts,
        metadata=meta,
        id=str(data.get("id", "")),
    )


def _event_from_json(raw: str | bytes) -> PipelineEvent:
    """Deserialise a PipelineEvent from a JSON string or bytes."""
    data = json.loads(raw)
    return _event_from_dict(data)


def _safe_call(handler: Handler, event: PipelineEvent) -> None:
    """Run a handler, swallowing exceptions so one bad handler can't stall the bus."""
    try:
        handler(event)
    except Exception:
        log.exception(
            "Handler %s failed for event %s", handler.__name__, event.event_type
        )


# ---------------------------------------------------------------------------
# RedisStreamBus
# ---------------------------------------------------------------------------


class RedisStreamBus:
    """EventBus backed by Redis Streams.

    Each event type maps to a stream named ``{prefix}:{event_type}``.
    Subscribers join a consumer group and read via XREADGROUP; messages
    are acknowledged with XACK after successful handler dispatch.
    """

    def __init__(self, config: QueueConfig) -> None:
        if not _redis_available:
            raise RuntimeError(
                "redis package is not installed — run `pip install redis`"
            )

        self._config = config
        self._client: _redis_mod.Redis = _redis_mod.Redis.from_url(  # type: ignore[union-attr]
            config.url or "redis://localhost:6379/0",
            decode_responses=True,
        )
        self._prefix = config.stream_prefix
        self._group = config.consumer_group
        self._consumer_name = f"consumer-{os.getpid()}-{threading.get_ident()}"

        self._handlers: dict[str, list[Handler]] = {}
        self._wildcard_handlers: list[Handler] = []
        self._lock = threading.Lock()

        self._listeners: list[threading.Thread] = []
        self._running = True

        # Streams we know about (for clear / wildcard).
        self._known_streams: set[str] = set()

    # -- Stream name helpers -------------------------------------------------

    def _stream_name(self, event_type: str) -> str:
        return f"{self._prefix}:{event_type}"

    # -- Consumer group setup ------------------------------------------------

    def _ensure_group(self, stream: str) -> None:
        """Create the consumer group if it doesn't exist yet."""
        try:
            self._client.xgroup_create(stream, self._group, id="0", mkstream=True)
        except _redis_mod.ResponseError as exc:  # type: ignore[union-attr]
            if "BUSYGROUP" not in str(exc):
                raise

    # -- Public interface (mirrors EventBus) ---------------------------------

    def subscribe(self, event_type: str, handler: Handler) -> None:
        stream = self._stream_name(event_type)
        self._ensure_group(stream)
        with self._lock:
            self._known_streams.add(stream)
            self._handlers.setdefault(event_type, []).append(handler)

        # One listener thread per stream is sufficient; deduplicate.
        if not any(t.name == f"redis-{stream}" for t in self._listeners):
            t = threading.Thread(
                target=self._listen,
                args=(stream, event_type),
                name=f"redis-{stream}",
                daemon=True,
            )
            self._listeners.append(t)
            t.start()

    def subscribe_all(self, handler: Handler) -> None:
        with self._lock:
            self._wildcard_handlers.append(handler)
        # Start a discovery thread that watches for new streams.
        if not any(t.name == "redis-wildcard" for t in self._listeners):
            t = threading.Thread(
                target=self._listen_wildcard,
                name="redis-wildcard",
                daemon=True,
            )
            self._listeners.append(t)
            t.start()

    def publish(self, event: PipelineEvent) -> None:
        stream = self._stream_name(event.event_type)
        with self._lock:
            self._known_streams.add(stream)
        self._client.xadd(stream, _event_to_dict(event))

    def clear(self) -> None:
        with self._lock:
            streams = list(self._known_streams)
            self._handlers.clear()
            self._wildcard_handlers.clear()
            self._known_streams.clear()
        for stream in streams:
            try:
                self._client.delete(stream)
            except Exception:
                log.debug("Failed to delete stream %s", stream)

    def close(self) -> None:
        """Stop consumer threads and close the Redis connection."""
        self._running = False
        for t in self._listeners:
            t.join(timeout=2.0)
        self._listeners.clear()
        try:
            self._client.close()
        except Exception:
            pass

    # -- Internal listener loops ---------------------------------------------

    def _listen(self, stream: str, event_type: str) -> None:
        """Read from a single stream in a consumer group."""
        self._ensure_group(stream)
        while self._running:
            try:
                results = self._client.xreadgroup(
                    self._group,
                    self._consumer_name,
                    {stream: ">"},
                    count=self._config.batch_size,
                    block=1000,
                )
            except Exception:
                if not self._running:
                    return
                log.exception("Redis XREADGROUP error on %s", stream)
                time.sleep(1)
                continue

            if not results:
                continue

            for _stream_key, messages in results:
                for msg_id, fields in messages:
                    event = _event_from_dict(fields)
                    self._dispatch(event)
                    try:
                        self._client.xack(stream, self._group, msg_id)
                    except Exception:
                        log.exception("Redis XACK failed for %s", msg_id)

    def _listen_wildcard(self) -> None:
        """Periodically scan for new streams matching the prefix and read them."""
        seen_ids: dict[str, str] = {}  # stream -> last_id
        while self._running:
            try:
                cursor: int | str = 0
                streams: list[str] = []
                while True:
                    cursor, keys = self._client.scan(
                        cursor=int(cursor), match=f"{self._prefix}:*", count=200
                    )
                    streams.extend(keys)
                    if cursor == 0:
                        break

                for stream in streams:
                    last_id = seen_ids.get(stream, "0-0")
                    try:
                        results = self._client.xread(
                            {stream: last_id},
                            count=self._config.batch_size,
                            block=0,
                        )
                    except Exception:
                        continue
                    if not results:
                        continue
                    for _stream_key, messages in results:
                        for msg_id, fields in messages:
                            event = _event_from_dict(fields)
                            self._dispatch_wildcard(event)
                            seen_ids[stream] = msg_id

            except Exception:
                if not self._running:
                    return
                log.exception("Redis wildcard listener error")

            # Poll interval for new stream discovery.
            time.sleep(1)

    def _dispatch(self, event: PipelineEvent) -> None:
        with self._lock:
            handlers = list(self._handlers.get(event.event_type, []))
            wildcard = list(self._wildcard_handlers)
        for h in wildcard:
            _safe_call(h, event)
        for h in handlers:
            _safe_call(h, event)

    def _dispatch_wildcard(self, event: PipelineEvent) -> None:
        with self._lock:
            wildcard = list(self._wildcard_handlers)
        for h in wildcard:
            _safe_call(h, event)


# ---------------------------------------------------------------------------
# KafkaBus
# ---------------------------------------------------------------------------


class KafkaBus:
    """EventBus backed by Apache Kafka.

    Supports both ``confluent-kafka`` and ``kafka-python`` as the
    underlying driver (prefers confluent if both are installed).
    """

    def __init__(self, config: QueueConfig) -> None:
        if not _kafka_available:
            raise RuntimeError(
                "Neither confluent-kafka nor kafka-python is installed "
                "— run `pip install confluent-kafka` or `pip install kafka-python`"
            )

        self._config = config
        self._prefix = config.stream_prefix
        self._group = config.consumer_group
        self._lock = threading.Lock()
        self._running = True

        self._handlers: dict[str, list[Handler]] = {}
        self._wildcard_handlers: list[Handler] = []
        self._consumers: list[threading.Thread] = []

        self._bootstrap = config.url or "localhost:9092"

        # Initialise producer once.
        if _kafka_flavour == "confluent":
            self._producer = _confluent_kafka.Producer(  # type: ignore[union-attr]
                {"bootstrap.servers": self._bootstrap}
            )
        else:
            self._producer = _kafka_python.KafkaProducer(  # type: ignore[union-attr]
                bootstrap_servers=self._bootstrap,
                value_serializer=lambda v: v.encode("utf-8") if isinstance(v, str) else v,
            )

    def _topic_name(self, event_type: str) -> str:
        return f"{self._prefix}.{event_type}"

    # -- Public interface ----------------------------------------------------

    def subscribe(self, event_type: str, handler: Handler) -> None:
        topic = self._topic_name(event_type)
        with self._lock:
            self._handlers.setdefault(event_type, []).append(handler)

        if not any(t.name == f"kafka-{topic}" for t in self._consumers):
            t = threading.Thread(
                target=self._consume,
                args=([topic],),
                name=f"kafka-{topic}",
                daemon=True,
            )
            self._consumers.append(t)
            t.start()

    def subscribe_all(self, handler: Handler) -> None:
        topic = f"{self._prefix}.all"
        with self._lock:
            self._wildcard_handlers.append(handler)
        if not any(t.name == "kafka-wildcard" for t in self._consumers):
            t = threading.Thread(
                target=self._consume,
                args=([topic],),
                name="kafka-wildcard",
                daemon=True,
            )
            self._consumers.append(t)
            t.start()

    def publish(self, event: PipelineEvent) -> None:
        topic = self._topic_name(event.event_type)
        payload = _event_to_json(event)
        all_topic = f"{self._prefix}.all"

        if _kafka_flavour == "confluent":
            self._producer.produce(topic, value=payload.encode("utf-8"))
            self._producer.produce(all_topic, value=payload.encode("utf-8"))
            self._producer.flush()
        else:
            self._producer.send(topic, value=payload)
            self._producer.send(all_topic, value=payload)
            self._producer.flush()

    def clear(self) -> None:
        with self._lock:
            self._handlers.clear()
            self._wildcard_handlers.clear()

    def close(self) -> None:
        self._running = False
        for t in self._consumers:
            t.join(timeout=5.0)
        self._consumers.clear()
        if _kafka_flavour == "confluent":
            # confluent Producer has no explicit close; flush suffices.
            try:
                self._producer.flush(timeout=2.0)
            except Exception:
                pass
        else:
            try:
                self._producer.close(timeout=2)
            except Exception:
                pass

    # -- Internal consumer ---------------------------------------------------

    def _consume(self, topics: list[str]) -> None:
        if _kafka_flavour == "confluent":
            self._consume_confluent(topics)
        else:
            self._consume_kafka_python(topics)

    def _consume_confluent(self, topics: list[str]) -> None:
        consumer = _confluent_kafka.Consumer(  # type: ignore[union-attr]
            {
                "bootstrap.servers": self._bootstrap,
                "group.id": self._group,
                "auto.offset.reset": "earliest",
                "enable.auto.commit": True,
            }
        )
        consumer.subscribe(topics)
        try:
            while self._running:
                msg = consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    log.warning("Kafka consumer error: %s", msg.error())
                    continue
                try:
                    event = _event_from_json(msg.value())
                except Exception:
                    log.exception("Failed to deserialise Kafka message")
                    continue
                self._dispatch(event)
        finally:
            consumer.close()

    def _consume_kafka_python(self, topics: list[str]) -> None:
        consumer = _kafka_python.KafkaConsumer(  # type: ignore[union-attr]
            *topics,
            bootstrap_servers=self._bootstrap,
            group_id=self._group,
            auto_offset_reset="earliest",
            enable_auto_commit=True,
            value_deserializer=lambda v: v.decode("utf-8") if isinstance(v, bytes) else v,
            consumer_timeout_ms=1000,
        )
        try:
            while self._running:
                try:
                    for msg in consumer:
                        if not self._running:
                            return
                        try:
                            event = _event_from_json(msg.value)
                        except Exception:
                            log.exception("Failed to deserialise Kafka message")
                            continue
                        self._dispatch(event)
                except StopIteration:
                    # consumer_timeout_ms reached, loop and poll again.
                    pass
        finally:
            consumer.close()

    def _dispatch(self, event: PipelineEvent) -> None:
        with self._lock:
            handlers = list(self._handlers.get(event.event_type, []))
            wildcard = list(self._wildcard_handlers)
        for h in wildcard:
            _safe_call(h, event)
        for h in handlers:
            _safe_call(h, event)


# ---------------------------------------------------------------------------
# SQSBus
# ---------------------------------------------------------------------------


class SQSBus:
    """EventBus backed by AWS SQS.

    Each event type maps to a queue named ``{prefix}-{event_type}``.
    Dots in event types are replaced with dashes (SQS queue name constraints).
    """

    def __init__(self, config: QueueConfig) -> None:
        if not _boto3_available:
            raise RuntimeError(
                "boto3 package is not installed — run `pip install boto3`"
            )

        self._config = config
        self._prefix = config.stream_prefix
        self._lock = threading.Lock()
        self._running = True

        self._handlers: dict[str, list[Handler]] = {}
        self._wildcard_handlers: list[Handler] = []
        self._pollers: list[threading.Thread] = []

        # SQS client — region derived from URL or default.
        kwargs: dict[str, Any] = {}
        if config.url:
            kwargs["endpoint_url"] = config.url
        self._sqs = _boto3.client("sqs", **kwargs)  # type: ignore[union-attr]

        # Cache queue URLs we've resolved or created.
        self._queue_urls: dict[str, str] = {}

    def _queue_name(self, event_type: str) -> str:
        safe = event_type.replace(".", "-")
        return f"{self._prefix}-{safe}"

    def _ensure_queue(self, event_type: str) -> str:
        """Return the queue URL, creating the queue if necessary."""
        name = self._queue_name(event_type)
        with self._lock:
            if name in self._queue_urls:
                return self._queue_urls[name]

        try:
            resp = self._sqs.get_queue_url(QueueName=name)
            url = resp["QueueUrl"]
        except self._sqs.exceptions.QueueDoesNotExist:
            resp = self._sqs.create_queue(
                QueueName=name,
                Attributes={
                    "VisibilityTimeout": str(self._config.batch_size),
                    "MessageRetentionPeriod": "345600",  # 4 days
                },
            )
            url = resp["QueueUrl"]
        except Exception:
            # Some localstack/moto versions raise ClientError instead.
            resp = self._sqs.create_queue(
                QueueName=name,
                Attributes={
                    "VisibilityTimeout": str(self._config.batch_size),
                    "MessageRetentionPeriod": "345600",
                },
            )
            url = resp["QueueUrl"]

        with self._lock:
            self._queue_urls[name] = url
        return url

    # -- Public interface ----------------------------------------------------

    def subscribe(self, event_type: str, handler: Handler) -> None:
        queue_url = self._ensure_queue(event_type)
        with self._lock:
            self._handlers.setdefault(event_type, []).append(handler)

        thread_name = f"sqs-{self._queue_name(event_type)}"
        if not any(t.name == thread_name for t in self._pollers):
            t = threading.Thread(
                target=self._poll,
                args=(queue_url, event_type),
                name=thread_name,
                daemon=True,
            )
            self._pollers.append(t)
            t.start()

    def subscribe_all(self, handler: Handler) -> None:
        # SQS has no native wildcard subscription.  We use a dedicated
        # ``{prefix}-all`` queue; publish() mirrors every event to it.
        queue_url = self._ensure_queue("all")
        with self._lock:
            self._wildcard_handlers.append(handler)

        if not any(t.name == "sqs-wildcard" for t in self._pollers):
            t = threading.Thread(
                target=self._poll,
                args=(queue_url, None),
                name="sqs-wildcard",
                daemon=True,
            )
            self._pollers.append(t)
            t.start()

    def publish(self, event: PipelineEvent) -> None:
        queue_url = self._ensure_queue(event.event_type)
        body = _event_to_json(event)
        self._sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=body,
            MessageAttributes={
                "event_type": {
                    "DataType": "String",
                    "StringValue": event.event_type,
                },
                "payload_id": {
                    "DataType": "String",
                    "StringValue": event.payload_id,
                },
            },
        )
        # Mirror to the ``all`` queue for wildcard subscribers.
        with self._lock:
            has_wildcard = bool(self._wildcard_handlers)
        if has_wildcard:
            all_url = self._ensure_queue("all")
            self._sqs.send_message(
                QueueUrl=all_url,
                MessageBody=body,
                MessageAttributes={
                    "event_type": {
                        "DataType": "String",
                        "StringValue": event.event_type,
                    },
                    "payload_id": {
                        "DataType": "String",
                        "StringValue": event.payload_id,
                    },
                },
            )

    def clear(self) -> None:
        with self._lock:
            urls = list(self._queue_urls.values())
            self._handlers.clear()
            self._wildcard_handlers.clear()
            self._queue_urls.clear()
        for url in urls:
            try:
                self._sqs.purge_queue(QueueUrl=url)
            except Exception:
                log.debug("Failed to purge SQS queue %s", url)

    def close(self) -> None:
        self._running = False
        for t in self._pollers:
            t.join(timeout=5.0)
        self._pollers.clear()

    # -- Internal poller -----------------------------------------------------

    def _poll(self, queue_url: str, event_type: str | None) -> None:
        """Long-poll a single SQS queue and dispatch to handlers."""
        while self._running:
            try:
                resp = self._sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=min(self._config.batch_size, 10),  # SQS max is 10
                    WaitTimeSeconds=5,
                    MessageAttributeNames=["All"],
                )
            except Exception:
                if not self._running:
                    return
                log.exception("SQS receive_message error on %s", queue_url)
                time.sleep(2)
                continue

            messages = resp.get("Messages", [])
            for msg in messages:
                try:
                    event = _event_from_json(msg["Body"])
                except Exception:
                    log.exception("Failed to deserialise SQS message")
                    self._delete_message(queue_url, msg)
                    continue

                retries = 0
                success = False
                while retries <= self._config.max_retries:
                    try:
                        self._dispatch(event, event_type)
                        success = True
                        break
                    except Exception:
                        retries += 1
                        log.warning(
                            "Handler retry %d/%d for event %s",
                            retries,
                            self._config.max_retries,
                            event.id,
                        )

                if success:
                    self._delete_message(queue_url, msg)

    def _delete_message(self, queue_url: str, msg: dict[str, Any]) -> None:
        try:
            self._sqs.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=msg["ReceiptHandle"],
            )
        except Exception:
            log.exception("SQS delete_message failed")

    def _dispatch(self, event: PipelineEvent, event_type: str | None) -> None:
        with self._lock:
            if event_type is not None:
                handlers = list(self._handlers.get(event_type, []))
            else:
                # Wildcard poller — resolve type from event itself.
                handlers = list(self._handlers.get(event.event_type, []))
            wildcard = list(self._wildcard_handlers)

        # For the type-specific poller, run both wildcard and typed handlers.
        # For the wildcard poller (event_type is None), run only wildcard.
        if event_type is not None:
            for h in wildcard:
                _safe_call(h, event)
            for h in handlers:
                _safe_call(h, event)
        else:
            for h in wildcard:
                _safe_call(h, event)


# ---------------------------------------------------------------------------
# Factory functions
# ---------------------------------------------------------------------------

_BACKEND_MAP: dict[str, type] = {
    "memory": EventBus,
    "redis": RedisStreamBus,
    "kafka": KafkaBus,
    "sqs": SQSBus,
}


def create_bus(config: QueueConfig | None = None) -> EventBus | RedisStreamBus | KafkaBus | SQSBus:
    """Create an EventBus from a QueueConfig.

    Returns an InMemoryBus if *config* is ``None`` or if the required
    third-party package for the chosen backend is not installed (with a
    warning logged).
    """
    if config is None:
        return EventBus()

    backend = config.backend.lower()
    cls = _BACKEND_MAP.get(backend)
    if cls is None:
        log.warning("Unknown queue backend %r — falling back to in-memory", backend)
        return EventBus()

    if cls is EventBus:
        return EventBus()

    try:
        return cls(config)
    except RuntimeError as exc:
        # Missing optional dependency — fall back gracefully.
        log.warning("%s — falling back to in-memory EventBus", exc)
        return EventBus()


def create_bus_from_settings() -> EventBus | RedisStreamBus | KafkaBus | SQSBus:
    """Create an EventBus from environment variables.

    Reads:
      - ``WLK_QUEUE_BACKEND`` — "memory", "redis", "kafka", "sqs"
      - ``WLK_QUEUE_URL`` — backend-specific connection string
      - ``WLK_QUEUE_PREFIX`` — stream/topic/queue name prefix
      - ``WLK_QUEUE_CONSUMER_GROUP`` — consumer group name
      - ``WLK_QUEUE_MAX_RETRIES`` — max handler retries
      - ``WLK_QUEUE_BATCH_SIZE`` — messages per poll

    All variables are optional. If ``WLK_QUEUE_BACKEND`` is unset or
    ``"memory"``, returns the in-memory EventBus.
    """
    from warlock.config import get_settings
    settings = get_settings()

    backend = settings.queue_backend.lower()
    if backend == "memory":
        return EventBus()

    config = QueueConfig(
        backend=backend,
        url=settings.queue_url,
        stream_prefix=settings.queue_prefix,
        consumer_group=settings.queue_consumer_group,
        max_retries=settings.queue_max_retries,
        batch_size=settings.queue_batch_size,
    )
    return create_bus(config)
