"""
GRC Control Posture Telemetry Datalake -- Architecture Design
=============================================================

This module defines the architecture for real-time telemetry collection from
an enterprise GRC environment into the Warlock data lake. It extends the
existing lake infrastructure (zones.py, writer.py, storage.py, schema.py)
with purpose-built ingestion for infrastructure telemetry sources.

The design integrates with Warlock's existing pipeline:
  - EventBus (bus.py) for internal event routing
  - Queue backends (queue.py) for Kafka/Redis/NATS/SQS transport
  - Lake zones (zones.py) for raw/enrichment/curated Parquet materialization
  - Schema registry (schema_registry.py) for event type validation
  - Iceberg schema generation (schema.py) for table format management

Sources targeted:
  - JBoss EAP6/7 (JMX telemetry, multi-region)
  - Oracle databases (CDC via LogMiner/GoldenGate)
  - MySQL (Canadian instance, binlog CDC)
  - RabbitMQ + ZooKeeper (AMQP taps, queue metrics)
  - Docker containers (stats API, log drivers)
  - Apache Camel/ServiceMix ESB (route metrics, exchange traces)
  - F5 / Azure LB (iControl REST, ARM metrics)
  - DMZ/Internal segmentation (syslog, flow logs)
  - Jackrabbit (JCR observation events)
  - Email (James mailet metrics, SMTP logs)
  - OpTool workstations (Windows event log forwarding)
  - Salt (event bus reactor)
  - BIRT (report execution telemetry)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ============================================================================
# 1. UNIFIED TELEMETRY EVENT SCHEMA
# ============================================================================
#
# Every telemetry source emits events normalized to this schema before
# entering the streaming layer. This is the contract between collectors
# and the lake.


class PostureState(str, Enum):
    """Control posture states aligned with Warlock's 5-value enum."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIAL = "partial"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


class EvidenceType(str, Enum):
    """Classification of telemetry evidence for GRC evaluation."""
    CONFIGURATION = "configuration"       # Static config state (JBoss XML, F5 rules)
    RUNTIME_METRIC = "runtime_metric"     # Gauge/counter (JMX MBeans, Docker stats)
    LOG_EVENT = "log_event"               # Discrete occurrence (syslog, Windows event)
    CHANGE_DATA = "change_data"           # CDC row mutation (Oracle/MySQL)
    HEARTBEAT = "heartbeat"               # Liveness signal (Salt minion ping)
    QUEUE_STATE = "queue_state"           # Message broker state (RabbitMQ)
    NETWORK_FLOW = "network_flow"         # Traffic observation (F5, firewall)
    REPOSITORY_EVENT = "repository_event" # Content change (Jackrabbit)
    REPORT_EXECUTION = "report_execution" # Report lifecycle (BIRT)
    ESB_EXCHANGE = "esb_exchange"         # Integration message trace (Camel)


@dataclass(frozen=True)
class TelemetryEvent:
    """Canonical telemetry event structure.

    This is the Parquet row schema for the raw telemetry zone. Every
    collector must produce events conforming to this shape.

    Fields:
        event_id        UUID, generated at collection point
        control_id      GRC control reference (e.g., "ac-2", "sc-7"), nullable
                        until enrichment stage maps it
        evidence_type   EvidenceType enum value
        source_system   Identifier for the emitting system (e.g., "jboss-us-prod-01")
        source_type     Category of source (e.g., "jboss_eap", "oracle_db", "f5_ltm")
        region          Geographic region (us, uk, au, ca)
        environment     Deployment tier (prod, staging, dr)
        timestamp       When the observation was made (source clock, UTC)
        ingested_at     When Warlock received the event (pipeline clock, UTC)
        posture_state   Assessed posture at collection time, or not_assessed
        resource_id     Specific resource identifier (JBoss instance, DB SID, etc.)
        resource_type   Resource classification (server, database, loadbalancer, etc.)
        severity        Severity if relevant (critical, high, medium, low, info)
        raw_payload     Original telemetry payload as JSON string
        sha256          Hash of raw_payload for integrity verification
        collector_id    Which collector instance produced this event
        correlation_id  Links related events across systems
        tags            Key-value metadata (framework hints, custom labels)
    """
    event_id: str
    evidence_type: str            # EvidenceType value
    source_system: str
    source_type: str
    region: str
    environment: str
    timestamp: str                # ISO 8601 UTC
    ingested_at: str              # ISO 8601 UTC
    resource_id: str
    resource_type: str
    raw_payload: str              # JSON string
    sha256: str
    collector_id: str
    control_id: str | None = None
    posture_state: str = "not_assessed"
    severity: str = "info"
    correlation_id: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


# ============================================================================
# 2. INGESTION LAYER -- COLLECTOR ARCHITECTURE
# ============================================================================
#
# Each source type gets a dedicated collector that runs as a sidecar,
# agent, or scheduled task. Collectors normalize to TelemetryEvent and
# push to the streaming layer. Warlock's existing BaseConnector pattern
# is extended to support continuous/streaming collection modes.
#
# DESIGN PRINCIPLE: Collectors are stateless event producers. They do
# NOT evaluate compliance -- that happens in the processing layer.
# The pipeline IS the product; consumers are TBD.


COLLECTOR_SPECS: dict[str, dict[str, Any]] = {

    # --- JBoss EAP 6/7 (JMX) ---
    # Deploy Jolokia WAR (JMX-over-HTTP) on each instance. Avoids RMI
    # firewall issues across regions. Collector polls Jolokia REST API.
    "jboss_jmx": {
        "protocol": "HTTP/REST (Jolokia)",
        "collection_mode": "poll",
        "poll_interval_seconds": 30,
        "evidence_types": ["runtime_metric", "configuration"],
        "mbeans_targeted": [
            # Connection pools -- maps to NIST SC-5 (denial of service protection)
            "jboss.as:subsystem=datasources,data-source=*",
            # Deployment health -- maps to SA-10 (developer config management)
            "jboss.as:deployment=*",
            # Web/HTTP sessions -- maps to AC-12 (session termination)
            "jboss.as:subsystem=undertow,server=*,http-listener=*",
            # Thread pools -- maps to SC-6 (resource availability)
            "jboss.as:subsystem=threads,thread-pool=*",
            # JVM memory -- capacity planning evidence
            "java.lang:type=Memory",
            "java.lang:type=GarbageCollector,name=*",
            # Security subsystem -- maps to IA-5 (authenticator management)
            "jboss.as:subsystem=security,security-domain=*",
            # Transactions -- maps to AU-12 (audit generation)
            "jboss.as:subsystem=transactions",
        ],
        "regions": ["us", "uk", "au"],
        "deployment": (
            "Jolokia WAR deployed to each JBoss instance. "
            "Collector runs as a lightweight Python process (or container) "
            "per region, polling all instances in that region. "
            "Uses Jolokia bulk requests to minimize HTTP round-trips."
        ),
        "auth": "Jolokia role-based access via jboss-web.xml + JAAS realm",
    },

    # --- Oracle CDC (hr2, coldb, hr2rep, hr2lt, lssdb) ---
    # LogMiner for real-time redo log parsing. GoldenGate if already licensed.
    # Debezium (Oracle connector) as the preferred CDC engine -- produces
    # Kafka-native change events without custom code.
    "oracle_cdc": {
        "protocol": "Debezium Oracle Connector -> Kafka Connect",
        "collection_mode": "streaming",
        "evidence_types": ["change_data"],
        "databases": ["hr2", "coldb", "hr2rep", "hr2lt", "lssdb"],
        "tables_of_interest": [
            # Access control changes -- maps to AC-2 (account management)
            "HR2.USER_ACCOUNTS", "HR2.ROLE_ASSIGNMENTS", "HR2.ACCESS_GRANTS",
            # Configuration changes -- maps to CM-3 (configuration change control)
            "COLDB.SYSTEM_PARAMETERS", "COLDB.POLICY_DEFINITIONS",
            # Audit trail -- maps to AU-3 (content of audit records)
            "HR2.AUDIT_LOG", "LSSDB.SECURITY_EVENTS",
        ],
        "deployment": (
            "Debezium Oracle connector running in Kafka Connect cluster. "
            "Uses Oracle LogMiner (no GoldenGate license required). "
            "Supplemental logging enabled on target tables. "
            "Replication instances (hr2rep) excluded from CDC -- read from primary only. "
            "Schema history stored in a dedicated Kafka topic."
        ),
        "auth": "Oracle LOGMINING role + SELECT on monitored tables",
    },

    # --- MySQL (Canadian instance) ---
    # Debezium MySQL connector, reading binlog.
    "mysql_cdc": {
        "protocol": "Debezium MySQL Connector -> Kafka Connect",
        "collection_mode": "streaming",
        "evidence_types": ["change_data"],
        "databases": ["ca_instance"],
        "deployment": (
            "Debezium MySQL connector in same Kafka Connect cluster as Oracle. "
            "Reads MySQL binlog (ROW format required). "
            "Separate connector instance with its own offsets topic. "
            "Canadian data residency: if Kafka cluster is outside CA, use a "
            "dedicated CA-region Kafka broker or route through regional proxy."
        ),
        "auth": "MySQL REPLICATION SLAVE + REPLICATION CLIENT privileges",
        "data_residency_note": (
            "Canadian PII regulations (PIPEDA) may require that raw CDC events "
            "from this instance never leave CA region. Partition strategy must "
            "account for this -- see storage layer."
        ),
    },

    # --- RabbitMQ + ZooKeeper ---
    # Two collection vectors: (1) Management API for queue/exchange metrics,
    # (2) Shovel/Federation or firehose tracer for message-level taps.
    "rabbitmq": {
        "protocol": "RabbitMQ Management HTTP API + Firehose Tracer",
        "collection_mode": "poll (metrics) + streaming (firehose)",
        "poll_interval_seconds": 15,
        "evidence_types": ["queue_state", "runtime_metric"],
        "metrics_collected": [
            # Queue depth -- maps to SC-5 (denial of service / backpressure)
            "queue.messages_ready", "queue.messages_unacknowledged",
            # Consumer health -- maps to CP-2 (contingency plan, failover readiness)
            "queue.consumers", "queue.consumer_utilisation",
            # Exchange throughput -- maps to AU-6 (audit review / anomaly)
            "exchange.message_stats.publish_in",
            "exchange.message_stats.publish_out",
            # Connection state -- maps to AC-17 (remote access)
            "connection.state", "connection.channels",
        ],
        "zookeeper_metrics": [
            # ZK health affects RabbitMQ clustering decisions
            "zk_avg_latency", "zk_outstanding_requests",
            "zk_num_alive_connections", "zk_server_state",
        ],
        "deployment": (
            "Collector polls RabbitMQ Management API (/api/queues, /api/exchanges). "
            "For message-level auditing, enable rabbitmq_tracing plugin and tap "
            "the amq.rabbitmq.trace exchange into a dedicated audit queue. "
            "ZooKeeper metrics via the 4-letter-word commands (mntr) or Admin Server."
        ),
        "auth": "RabbitMQ management user (monitoring tag) + ZK digest auth",
    },

    # --- Docker containers (log_service, selenium) ---
    # Docker Engine API for stats + container events. Log driver ships
    # container stdout/stderr.
    "docker": {
        "protocol": "Docker Engine API (unix socket or TCP)",
        "collection_mode": "streaming (events) + poll (stats)",
        "poll_interval_seconds": 10,
        "evidence_types": ["runtime_metric", "log_event"],
        "containers_targeted": ["log_service", "selenium"],
        "stats_collected": [
            # Resource usage -- maps to SC-6 (resource availability)
            "cpu_stats.cpu_usage.total_usage",
            "memory_stats.usage", "memory_stats.limit",
            # Network I/O -- maps to SC-7 (boundary protection)
            "networks.*.rx_bytes", "networks.*.tx_bytes",
            # Container health -- maps to SI-6 (security function verification)
            "State.Health.Status",
        ],
        "events_collected": [
            # Container lifecycle -- maps to CM-3 (configuration change control)
            "start", "stop", "die", "kill", "oom", "restart",
            # Image events -- maps to SA-10 (developer configuration management)
            "pull", "push", "tag",
        ],
        "deployment": (
            "Collector reads from Docker socket (/var/run/docker.sock). "
            "For stats: GET /containers/{id}/stats?stream=true. "
            "For events: GET /events?filters={...}. "
            "Log collection via Fluent Bit sidecar with forward output to Kafka. "
            "Avoids the json-file log driver retention issues."
        ),
    },

    # --- Apache Camel / ServiceMix ESB ---
    # Camel exposes route metrics via JMX and can be tapped via
    # the Camel Tracer or wiretap EIP.
    "camel_esb": {
        "protocol": "JMX (via Jolokia on ServiceMix) + Camel Tracer",
        "collection_mode": "poll (metrics) + streaming (traced exchanges)",
        "poll_interval_seconds": 30,
        "evidence_types": ["esb_exchange", "runtime_metric"],
        "mbeans_targeted": [
            # Route performance -- maps to SC-5 (DoS / throughput)
            "org.apache.camel:context=*,type=routes,name=*",
            # Exchange counts -- maps to AU-12 (audit generation)
            "org.apache.camel:context=*,type=processors,name=*",
            # Error handler -- maps to SI-11 (error handling)
            "org.apache.camel:context=*,type=errorhandlers,name=*",
        ],
        "deployment": (
            "Jolokia deployed in ServiceMix (same approach as JBoss). "
            "For exchange-level tracing, configure Camel BacklogTracer or "
            "add a wiretap to a dedicated audit route that publishes to Kafka. "
            "Trace sampling rate configurable (default 10%) to avoid overhead."
        ),
    },

    # --- F5 Load Balancers / Azure LB ---
    # F5: iControl REST API. Azure: Azure Monitor / ARM metrics API.
    "f5_azure_lb": {
        "protocol": "F5 iControl REST + Azure Monitor REST API",
        "collection_mode": "poll",
        "poll_interval_seconds": 60,
        "evidence_types": ["network_flow", "configuration"],
        "f5_endpoints": [
            # VIP status -- maps to SC-7 (boundary protection)
            "/mgmt/tm/ltm/virtual",
            # Pool member health -- maps to CP-2 (contingency plan)
            "/mgmt/tm/ltm/pool/members/stats",
            # SSL profiles -- maps to SC-8 (transmission confidentiality)
            "/mgmt/tm/ltm/profile/client-ssl",
            # iRules -- maps to AC-4 (information flow enforcement)
            "/mgmt/tm/ltm/rule",
            # WAF policy (ASM) -- maps to SI-3 (malicious code protection)
            "/mgmt/tm/asm/policies",
        ],
        "azure_lb_metrics": [
            # Health probe status -- maps to CP-2
            "HealthProbeStatus",
            # Packet/byte counts -- maps to AU-6 (audit review)
            "PacketCount", "ByteCount",
            # SNAT exhaustion -- maps to SC-5
            "SnatConnectionCount", "AllocatedSnatPorts",
        ],
        "deployment": (
            "F5 collector authenticates via iControl REST token auth. "
            "Azure collector uses managed identity or service principal with "
            "Reader role on LB resource group. "
            "Both collectors run centrally; F5 API is reachable from management VLAN."
        ),
        "auth": "F5: token auth (admin role). Azure: AAD service principal",
    },

    # --- DMZ / Internal Network (syslog + flow logs) ---
    # Syslog for firewall/IDS events. NetFlow/IPFIX for traffic analysis.
    "network_syslog": {
        "protocol": "Syslog (RFC 5424) over TLS + NetFlow v9/IPFIX",
        "collection_mode": "streaming",
        "evidence_types": ["log_event", "network_flow"],
        "deployment": (
            "Syslog collector (rsyslog or syslog-ng) listens on TCP/TLS 6514. "
            "Firewalls and IDS appliances forward syslog to collector. "
            "Collector parses CEF/LEEF/RFC5424 and publishes to Kafka topic. "
            "NetFlow: nfcapd or GoFlow2 receives flows, converts to JSON, ships to Kafka. "
            "DMZ collectors are isolated -- they push to a Kafka broker in the "
            "DMZ that mirrors to internal Kafka via MirrorMaker 2."
        ),
        "dmz_architecture": (
            "DMZ hosts run their own local Kafka broker (single node, retention=1h). "
            "MirrorMaker 2 replicates from DMZ Kafka to internal Kafka cluster. "
            "This avoids opening inbound connections from internal to DMZ. "
            "All cross-zone traffic is TLS-encrypted."
        ),
    },

    # --- Jackrabbit Content Repository (IDMS + OAK) ---
    # JCR Observation API for content change events.
    "jackrabbit": {
        "protocol": "JCR Observation API (EventListener) + JMX",
        "collection_mode": "streaming (observation) + poll (JMX metrics)",
        "poll_interval_seconds": 60,
        "evidence_types": ["repository_event", "runtime_metric"],
        "events_observed": [
            # Node changes -- maps to CM-3 (configuration change control)
            "NODE_ADDED", "NODE_REMOVED", "NODE_MOVED",
            # Property changes -- maps to AC-3 (access enforcement)
            "PROPERTY_ADDED", "PROPERTY_CHANGED", "PROPERTY_REMOVED",
            # For OAK specifically:
            "PERSIST",  # commit events
        ],
        "deployment": (
            "Deploy a thin EventListener servlet in the Jackrabbit webapp that "
            "captures observation events and publishes to Kafka. "
            "For OAK, use the oak-run tooling to expose observation events. "
            "JMX metrics (session counts, query stats) collected via Jolokia."
        ),
    },

    # --- Email (James server) ---
    "email_james": {
        "protocol": "James Mailet pipeline + JMX",
        "collection_mode": "streaming (mailet) + poll (JMX)",
        "poll_interval_seconds": 60,
        "evidence_types": ["log_event", "runtime_metric"],
        "deployment": (
            "Custom audit mailet inserted into James processing pipeline. "
            "Captures: sender, recipient domain, message-id, SPF/DKIM results, "
            "timestamp, size. No message body captured (PII). "
            "Mailet publishes to Kafka topic. "
            "JMX metrics for queue depth, processing latency via Jolokia."
        ),
        "pii_note": "Message bodies MUST NOT be captured. Headers only. Scrub via warlock.utils.pii.",
    },

    # --- OpTool Workstations (Windows) ---
    # Windows Event Log forwarding via WEF or Winlogbeat.
    "optool_windows": {
        "protocol": "Windows Event Forwarding (WEF) or Winlogbeat -> Kafka",
        "collection_mode": "streaming",
        "evidence_types": ["log_event", "configuration"],
        "event_channels": [
            # Security log -- maps to AU-2 (audit events)
            "Security",
            # Application log (operator.exe events) -- maps to AU-12
            "Application",
            # Sysmon (if deployed) -- maps to SI-4 (information system monitoring)
            "Microsoft-Windows-Sysmon/Operational",
        ],
        "event_ids_of_interest": [
            4624, 4625,  # Logon success/failure -- AC-7 (unsuccessful logon attempts)
            4648,        # Explicit credential use -- IA-2 (identification)
            4672,        # Special privileges assigned -- AC-6 (least privilege)
            4688,        # Process creation -- AU-12 (audit generation)
            4698, 4702,  # Scheduled task created/updated -- CM-3
            7045,        # Service installed -- CM-5 (access restrictions for change)
        ],
        "deployment": (
            "PREFERRED: Winlogbeat on each OpTool workstation, shipping directly to Kafka. "
            "ALTERNATIVE: Windows Event Forwarding (WEF) to a central collector, "
            "then Winlogbeat on the collector. WEF is lighter on endpoints but adds "
            "a collection hop. "
            "operator.exe application events captured via Application channel filter."
        ),
    },

    # --- Salt Configuration Management ---
    # Salt's event bus (0MQ) exposes every state change, command execution,
    # and minion response.
    "salt": {
        "protocol": "Salt Event Bus (ZeroMQ/TCP) + Salt API REST",
        "collection_mode": "streaming",
        "evidence_types": ["configuration", "heartbeat"],
        "events_captured": [
            # State apply results -- maps to CM-2 (baseline configuration)
            "salt/job/*/ret/*",
            # Minion start/stop -- maps to SI-6 (security function verification)
            "salt/minion/*/start",
            # Key acceptance -- maps to IA-3 (device identification)
            "salt/key",
            # Beacon events (file changes, service status) -- maps to SI-7
            "salt/beacon/*",
        ],
        "deployment": (
            "Salt Reactor or external engine (salt-event-to-kafka) subscribes to "
            "the Salt master event bus and forwards to Kafka. "
            "This runs on the Salt master itself. "
            "Salt API (CherryPy) can also be polled for job history as a backup "
            "collection path."
        ),
    },

    # --- BIRT Reporting ---
    "birt": {
        "protocol": "BIRT Engine event hooks + Servlet filter",
        "collection_mode": "streaming (hooks) + poll (execution logs)",
        "poll_interval_seconds": 300,
        "evidence_types": ["report_execution"],
        "deployment": (
            "Instrument BIRT viewer servlet with a filter that logs report execution "
            "events (report name, parameters, user, duration, row count) to Kafka. "
            "Alternatively, parse BIRT engine logs if instrumentation is not feasible. "
            "Maps to AU-12 (audit generation) for report access auditing."
        ),
    },
}


# ============================================================================
# 3. STREAMING LAYER -- TECHNOLOGY CHOICE AND TOPOLOGY
# ============================================================================
#
# CHOICE: Redpanda (Kafka-compatible, no JVM/ZooKeeper dependency)
#
# Justification:
#   - Warlock already has KafkaBus in queue.py with confluent-kafka support.
#     Redpanda is wire-compatible -- zero code changes to KafkaBus.
#   - No JVM means dramatically simpler operations for a GRC platform that
#     may deploy on-prem or air-gapped (AI-off mode).
#   - Single binary, ~10x lower tail latency than Kafka for sub-100MB/s
#     throughput (typical for GRC telemetry -- not adtech scale).
#   - Built-in Schema Registry (Redpanda Schema Registry, Avro/Protobuf/JSON
#     Schema compatible) -- no separate Confluent Schema Registry deployment.
#   - Built-in HTTP Proxy (Pandaproxy) for DMZ collectors that cannot run
#     the Kafka protocol directly.
#   - If the environment already runs Kafka: use it. The architecture is
#     Kafka-protocol-native. Redpanda is the recommendation for greenfield.
#
# ALTERNATIVE CONSIDERED: Apache Pulsar
#   - Better multi-tenancy and geo-replication story
#   - But: heavier operational burden (BookKeeper + ZooKeeper/etcd)
#   - Warlock's queue.py would need a new PulsarBus implementation
#   - Not justified unless tenant isolation is a hard requirement
#
# TOPIC TOPOLOGY:

KAFKA_TOPICS: dict[str, dict[str, Any]] = {
    # Raw telemetry by source type -- high volume, short retention
    "warlock.telemetry.jboss": {
        "partitions": 6,        # 2 per region (us, uk, au)
        "replication_factor": 3,
        "retention_ms": 7 * 24 * 3600 * 1000,  # 7 days
        "partition_key": "source_system",  # route by instance for ordering
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.oracle_cdc": {
        "partitions": 5,        # 1 per database (hr2, coldb, hr2rep, hr2lt, lssdb)
        "replication_factor": 3,
        "retention_ms": 14 * 24 * 3600 * 1000,  # 14 days (CDC needs longer replay)
        "partition_key": "database_name",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.mysql_cdc": {
        "partitions": 2,
        "replication_factor": 3,
        "retention_ms": 14 * 24 * 3600 * 1000,
        "partition_key": "table_name",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.rabbitmq": {
        "partitions": 3,
        "replication_factor": 3,
        "retention_ms": 7 * 24 * 3600 * 1000,
        "partition_key": "source_system",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.docker": {
        "partitions": 2,
        "replication_factor": 3,
        "retention_ms": 3 * 24 * 3600 * 1000,  # 3 days
        "partition_key": "container_name",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.camel_esb": {
        "partitions": 3,
        "replication_factor": 3,
        "retention_ms": 7 * 24 * 3600 * 1000,
        "partition_key": "route_id",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.network": {
        "partitions": 6,        # DMZ + internal per region
        "replication_factor": 3,
        "retention_ms": 3 * 24 * 3600 * 1000,  # high volume, short retention
        "partition_key": "source_system",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.f5": {
        "partitions": 3,
        "replication_factor": 3,
        "retention_ms": 7 * 24 * 3600 * 1000,
        "partition_key": "source_system",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.windows": {
        "partitions": 4,
        "replication_factor": 3,
        "retention_ms": 7 * 24 * 3600 * 1000,
        "partition_key": "source_system",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.salt": {
        "partitions": 2,
        "replication_factor": 3,
        "retention_ms": 14 * 24 * 3600 * 1000,  # config state needs longer replay
        "partition_key": "minion_id",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.jackrabbit": {
        "partitions": 2,
        "replication_factor": 3,
        "retention_ms": 7 * 24 * 3600 * 1000,
        "partition_key": "repository_name",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.email": {
        "partitions": 2,
        "replication_factor": 3,
        "retention_ms": 7 * 24 * 3600 * 1000,
        "partition_key": "source_system",
        "cleanup_policy": "delete",
    },
    "warlock.telemetry.birt": {
        "partitions": 1,
        "replication_factor": 3,
        "retention_ms": 7 * 24 * 3600 * 1000,
        "partition_key": "report_name",
        "cleanup_policy": "delete",
    },

    # --- Enriched / processed topics ---
    "warlock.telemetry.enriched": {
        "partitions": 12,
        "replication_factor": 3,
        "retention_ms": 30 * 24 * 3600 * 1000,  # 30 days
        "partition_key": "control_id",  # enables per-control stream processing
        "cleanup_policy": "delete",
        "description": (
            "Telemetry events after control_id mapping and posture evaluation. "
            "This is the primary topic for downstream consumers."
        ),
    },
    "warlock.telemetry.posture_changes": {
        "partitions": 6,
        "replication_factor": 3,
        "retention_ms": 90 * 24 * 3600 * 1000,  # 90 days
        "partition_key": "control_id",
        "cleanup_policy": "compact",  # keep latest state per control
        "description": (
            "Compacted topic of posture state transitions. "
            "Consumed by real-time dashboards and alert rules."
        ),
    },
    "warlock.telemetry.dead_letter": {
        "partitions": 3,
        "replication_factor": 3,
        "retention_ms": 30 * 24 * 3600 * 1000,
        "cleanup_policy": "delete",
        "description": "Events that failed processing after max retries.",
    },
}

# Schema Registry configuration
SCHEMA_REGISTRY_CONFIG = {
    "type": "Redpanda Schema Registry (built-in) or Confluent Schema Registry",
    "format": "JSON Schema",  # Not Avro -- aligns with Warlock's JSON-native pipeline
    "compatibility_mode": "BACKWARD",
    "rationale": (
        "JSON Schema chosen over Avro because: "
        "(1) Warlock pipeline is JSON-native (raw_data stored as JSON strings in Parquet), "
        "(2) Avro requires code generation or dynamic schema resolution which adds "
        "complexity for an on-prem/air-gapped deployment, "
        "(3) JSON Schema is human-readable for GRC auditors who need to understand "
        "what data is being collected. "
        "BACKWARD compatibility ensures old consumers can read new schemas."
    ),
}

# Exactly-once semantics configuration
EXACTLY_ONCE_CONFIG = {
    "producer": {
        "enable_idempotence": True,
        "acks": "all",
        "max_in_flight_requests_per_connection": 5,  # safe with idempotence
        "retries": 2147483647,  # infinite retries, bounded by delivery.timeout.ms
        "delivery_timeout_ms": 120000,
    },
    "consumer": {
        "isolation_level": "read_committed",
        "enable_auto_commit": False,  # manual commit after processing
        "auto_offset_reset": "earliest",
    },
    "rationale": (
        "Exactly-once for the streaming path (Kafka transactions + idempotent producer). "
        "For batch backfill, use at-least-once with deduplication on event_id + sha256 "
        "at the lake write layer (Iceberg's MERGE INTO handles this naturally)."
    ),
}


# ============================================================================
# 4. STORAGE LAYER -- DATALAKE FORMAT AND PARTITIONING
# ============================================================================
#
# CHOICE: Apache Iceberg
#
# Justification:
#   - Warlock ALREADY uses Iceberg (schema.py generates Iceberg schemas from
#     SQLAlchemy models, zones.py writes Parquet with Iceberg-aligned structure).
#   - Hidden partitioning: consumers query without knowing partition layout.
#     Critical for GRC analysts who write ad-hoc queries.
#   - Time travel: roll back to any snapshot. Essential for audit trails --
#     "show me the compliance posture as of DATE" without maintaining SCD tables.
#   - Schema evolution: add columns without rewriting existing Parquet files.
#     Telemetry schemas WILL evolve as new control mappings are discovered.
#   - Partition evolution: change partitioning strategy without rewriting data.
#     Start with day-level, switch to hour-level if volume justifies it.
#   - Open format: works with every query engine (Trino, Spark, DuckDB, Flink).
#   - Catalog options: REST catalog (Polaris, Gravitino), AWS Glue, Nessie,
#     or simple Hadoop-style (filesystem) for air-gapped deployments.
#
# ALTERNATIVES CONSIDERED:
#   Delta Lake:
#     - Stronger Spark integration, but Warlock is not Spark-centric
#     - Transaction log is a single JSON file per commit -- scales worse
#       than Iceberg's manifest-based approach for high-write telemetry
#   Apache Hudi:
#     - Best for upsert-heavy workloads (CDC), but adds operational complexity
#     - Compaction scheduling is manual and error-prone
#     - Iceberg v2 position deletes handle upserts adequately

LAKE_ZONE_LAYOUT = {
    "telemetry_raw": {
        "description": (
            "Immutable, append-only raw telemetry events. This is the source of truth. "
            "Never mutated after write. Retained for full replay capability."
        ),
        "path_template": "telemetry/raw/{source_type}/{region}/dt={date}/hr={hour}/",
        "iceberg_table": "warlock_telemetry.raw_events",
        "partition_spec": [
            ("source_type", "identity"),  # first-level: JBoss, Oracle, F5, etc.
            ("region", "identity"),        # second-level: us, uk, au, ca
            ("timestamp", "day"),          # third-level: date partition (hidden)
            ("timestamp", "hour"),         # fourth-level: hour partition (hidden)
        ],
        "sort_order": ["source_system", "timestamp"],
        "retention_days": 365,
        "format": "Parquet (Snappy compression, row group size 128MB)",
    },

    "telemetry_enriched": {
        "description": (
            "Telemetry events after control mapping, posture evaluation, and "
            "severity classification. This is the primary analytical table."
        ),
        "path_template": "telemetry/enriched/{framework}/{control_family}/dt={date}/",
        "iceberg_table": "warlock_telemetry.enriched_events",
        "partition_spec": [
            ("control_id", "truncate[4]"),  # first 4 chars groups by family (ac-, sc-, etc.)
            ("region", "identity"),
            ("timestamp", "day"),
        ],
        "sort_order": ["control_id", "source_system", "timestamp"],
        "retention_days": 730,  # 2 years for compliance audit trail
        "format": "Parquet (ZSTD compression, row group size 128MB)",
    },

    "telemetry_posture": {
        "description": (
            "Materialized posture snapshots -- one row per control per evaluation. "
            "This is the SCD Type 2 table that tracks posture state transitions."
        ),
        "path_template": "telemetry/posture/framework={framework}/dt={date}/",
        "iceberg_table": "warlock_telemetry.posture_snapshots",
        "partition_spec": [
            ("framework", "identity"),
            ("timestamp", "day"),
        ],
        "sort_order": ["control_id", "timestamp"],
        "retention_days": 2555,  # 7 years for regulatory compliance
        "format": "Parquet (ZSTD compression)",
    },

    "telemetry_metrics": {
        "description": (
            "Pre-aggregated metrics for dashboard performance. "
            "Hourly rollups of event counts, posture percentages, latency percentiles."
        ),
        "path_template": "telemetry/metrics/granularity={granularity}/dt={date}/",
        "iceberg_table": "warlock_telemetry.metrics_rollup",
        "partition_spec": [
            ("granularity", "identity"),  # hourly, daily, weekly
            ("timestamp", "day"),
        ],
        "retention_days": 365,
        "format": "Parquet (ZSTD compression)",
    },
}

# Retention and tiering policy
STORAGE_TIERING = {
    "hot": {
        "age_days": "0-30",
        "storage": "NVMe/SSD (local or S3 Standard / Azure Hot)",
        "description": "Active query and processing. All recent telemetry.",
    },
    "warm": {
        "age_days": "31-180",
        "storage": "S3 Standard-IA / Azure Cool / HDD",
        "description": "Queryable but less frequently accessed. Audit trail.",
    },
    "cold": {
        "age_days": "181-730",
        "storage": "S3 Glacier Instant Retrieval / Azure Archive",
        "description": "Compliance retention. Queries require minutes, not seconds.",
    },
    "archive": {
        "age_days": "731+",
        "storage": "S3 Glacier Deep Archive / tape",
        "description": "Regulatory hold. 7-year retention for posture snapshots.",
    },
    "implementation": (
        "Iceberg table properties control expiration. "
        "Use Iceberg's expire_snapshots and remove_orphan_files for lifecycle. "
        "AWS: S3 Lifecycle rules on prefixes matching Iceberg data paths. "
        "On-prem: scheduled job moves data directories between storage pools. "
        "Warlock's existing storage.py abstraction (LocalStorage, S3Storage, "
        "AzureBlobStorage) already supports this -- add a TieredStorage wrapper."
    ),
}

# Data residency constraints
DATA_RESIDENCY = {
    "ca_region": {
        "constraint": "Canadian data (MySQL CDC from CA instance) must not leave CA region",
        "implementation": (
            "Dedicated Kafka broker in CA region. Iceberg table partitioned by region. "
            "Queries from non-CA regions filter on region != 'ca' by default. "
            "Lake storage bucket per region with cross-region replication disabled for CA."
        ),
    },
    "implementation_pattern": (
        "Warlock storage.py create_storage() factory already supports per-region "
        "bucket URLs via WLK_LAKE_STORAGE_URL. Extend to accept a dict of "
        "region -> URL mappings for multi-region writes."
    ),
}


# ============================================================================
# 5. PROCESSING LAYER -- STREAM PROCESSING FOR COMPLIANCE EVALUATION
# ============================================================================
#
# CHOICE: Apache Flink (with Flink SQL for declarative rules)
#
# Justification:
#   - True streaming (event-at-a-time), not micro-batch. For GRC posture,
#     you need sub-minute detection of non-compliant state transitions.
#   - Exactly-once with Kafka via Flink's two-phase commit sink.
#   - Flink SQL enables GRC analysts to write compliance rules as SQL,
#     not Java/Scala. Example: "flag non_compliant when JBoss connection
#     pool exhaustion exceeds 90% for 5 consecutive observations."
#   - Savepoints enable rule deployment without data loss.
#   - Scales from 1 TaskManager (on-prem) to hundreds (cloud).
#
# ALTERNATIVES CONSIDERED:
#   Spark Structured Streaming:
#     - Micro-batch (100ms-1s granularity). Acceptable for most GRC use cases
#       but Flink is better for true event-time windowing.
#     - Better if the org already runs Spark for batch analytics.
#   Materialize:
#     - Excellent for incremental view maintenance (real-time SQL views).
#     - But: single-vendor, no on-prem/air-gapped option, smaller ecosystem.
#     - Consider as a complement to Flink for the query layer, not a replacement.
#   RisingWave:
#     - Open-source Materialize alternative. Worth evaluating if Flink
#       operational overhead is too high.
#
# AI-ON vs AI-OFF PROCESSING:
#   - AI-OFF (deterministic): Flink SQL rules evaluate boolean conditions
#     against telemetry thresholds. Pure logic, no model inference.
#   - AI-ON (interactive reasoning): Flink enriches events with context,
#     then routes ambiguous cases to an AI reasoning sidecar (via REST)
#     that returns posture_state + confidence + explanation. This matches
#     Warlock's existing assessment tier fallback pattern:
#     Tier 1 (assertions/Flink rules) -> Tier 2 (AI, if not_assessed).

FLINK_JOB_SPECS: dict[str, dict[str, Any]] = {
    "telemetry_enrichment": {
        "description": (
            "Consumes raw telemetry topics, maps each event to zero or more "
            "control_ids using Warlock framework YAML definitions, and produces "
            "enriched events to warlock.telemetry.enriched topic."
        ),
        "source_topics": list(KAFKA_TOPICS.keys())[:13],  # all raw topics
        "sink_topic": "warlock.telemetry.enriched",
        "processing": [
            "1. Deserialize TelemetryEvent from JSON",
            "2. Validate against schema registry",
            "3. Look up control mappings from broadcast state (loaded from framework YAMLs)",
            "4. For each matching control: emit enriched event with control_id populated",
            "5. If no control match: emit with control_id=null for manual triage",
        ],
        "state": "Broadcast state for control mapping rules (reloadable via control plane topic)",
        "parallelism": 4,
    },

    "posture_evaluation": {
        "description": (
            "Evaluates enriched telemetry against compliance rules to determine "
            "posture_state per control. Uses event-time windowing."
        ),
        "source_topic": "warlock.telemetry.enriched",
        "sink_topics": [
            "warlock.telemetry.posture_changes",
            "warlock.telemetry.dead_letter",
        ],
        "processing": [
            "1. Key by (control_id, source_system, region)",
            "2. Tumbling window (5 minutes, event time) with allowed lateness (1 hour)",
            "3. Evaluate assertion rules from broadcast state (Warlock assertions)",
            "4. Determine posture_state using majority vote across window observations",
            "5. Compare with previous posture state (from keyed state)",
            "6. If state changed: emit to posture_changes topic",
            "7. If AI-ON and state is ambiguous (partial): route to AI sidecar",
        ],
        "state": (
            "Keyed state per (control_id, source_system, region) storing last known "
            "posture_state. Broadcast state for assertion rule definitions."
        ),
        "parallelism": 6,
        "checkpointing": {
            "interval_ms": 60000,
            "min_pause_ms": 30000,
            "timeout_ms": 600000,
            "max_concurrent": 1,
            "mode": "EXACTLY_ONCE",
            "storage": "S3 or filesystem (matches Warlock lake storage backend)",
        },
    },

    "metrics_aggregation": {
        "description": (
            "Pre-aggregates telemetry for dashboard queries. "
            "Produces hourly rollups of event counts, posture distributions, "
            "and latency percentiles."
        ),
        "source_topic": "warlock.telemetry.enriched",
        "sink": "Iceberg table warlock_telemetry.metrics_rollup (via Flink Iceberg sink)",
        "processing": [
            "1. Tumbling window (1 hour, event time)",
            "2. Group by (control_id, source_type, region, framework)",
            "3. Compute: count, posture distribution, p50/p95/p99 latency",
            "4. Write directly to Iceberg table (skip Kafka for aggregates)",
        ],
        "parallelism": 2,
    },

    "anomaly_detection": {
        "description": (
            "Detects anomalous telemetry patterns: sudden volume drops (collector "
            "failure), volume spikes (attack), metric distribution shifts."
        ),
        "source_topic": "warlock.telemetry.enriched",
        "sink_topic": "warlock.pipeline.alerts",
        "processing": [
            "1. Sliding window (1 hour, slide 5 minutes)",
            "2. Per source_system: track rolling mean and stddev of event count",
            "3. Alert if count deviates > 3 sigma from 7-day rolling baseline",
            "4. Per control_id: alert if posture flaps (>3 transitions in 1 hour)",
            "5. Global: alert if any source_type has zero events for 2x poll interval",
        ],
        "parallelism": 2,
    },
}

# Example Flink SQL rule for posture evaluation
FLINK_SQL_EXAMPLES = {
    "jboss_connection_pool_exhaustion": """
        -- Detect JBoss connection pool approaching exhaustion
        -- Maps to NIST SC-5 (Denial of Service Protection)
        INSERT INTO posture_changes
        SELECT
            event_id,
            'sc-5' AS control_id,
            source_system,
            region,
            CASE
                WHEN AVG(CAST(JSON_VALUE(raw_payload, '$.ActiveCount') AS DOUBLE))
                     / NULLIF(AVG(CAST(JSON_VALUE(raw_payload, '$.MaxPoolSize') AS DOUBLE)), 0)
                     > 0.9
                THEN 'non_compliant'
                WHEN AVG(CAST(JSON_VALUE(raw_payload, '$.ActiveCount') AS DOUBLE))
                     / NULLIF(AVG(CAST(JSON_VALUE(raw_payload, '$.MaxPoolSize') AS DOUBLE)), 0)
                     > 0.7
                THEN 'partial'
                ELSE 'compliant'
            END AS posture_state,
            window_start AS evaluated_at
        FROM TABLE(
            TUMBLE(TABLE enriched_telemetry, DESCRIPTOR(event_time), INTERVAL '5' MINUTES)
        )
        WHERE source_type = 'jboss_eap'
          AND evidence_type = 'runtime_metric'
          AND JSON_VALUE(raw_payload, '$.mbean') LIKE '%datasources%'
        GROUP BY event_id, source_system, region, window_start, window_end
    """,

    "oracle_privilege_escalation": """
        -- Detect privilege escalation via Oracle CDC
        -- Maps to NIST AC-6 (Least Privilege)
        INSERT INTO posture_changes
        SELECT
            event_id,
            'ac-6' AS control_id,
            source_system,
            region,
            'non_compliant' AS posture_state,
            event_time AS evaluated_at
        FROM enriched_telemetry
        WHERE source_type = 'oracle_cdc'
          AND evidence_type = 'change_data'
          AND JSON_VALUE(raw_payload, '$.table') = 'ROLE_ASSIGNMENTS'
          AND JSON_VALUE(raw_payload, '$.op') = 'c'  -- INSERT (Debezium convention)
          AND JSON_VALUE(raw_payload, '$.after.role_name') IN ('DBA', 'SYSDBA', 'SYSOPER')
    """,

    "f5_ssl_certificate_expiry": """
        -- Detect SSL certificates approaching expiry
        -- Maps to NIST SC-8 (Transmission Confidentiality)
        INSERT INTO posture_changes
        SELECT
            event_id,
            'sc-8' AS control_id,
            source_system,
            region,
            CASE
                WHEN CAST(JSON_VALUE(raw_payload, '$.expirationDate') AS BIGINT)
                     - UNIX_TIMESTAMP() < 7 * 86400
                THEN 'non_compliant'
                WHEN CAST(JSON_VALUE(raw_payload, '$.expirationDate') AS BIGINT)
                     - UNIX_TIMESTAMP() < 30 * 86400
                THEN 'partial'
                ELSE 'compliant'
            END AS posture_state,
            event_time AS evaluated_at
        FROM enriched_telemetry
        WHERE source_type = 'f5_ltm'
          AND evidence_type = 'configuration'
          AND JSON_VALUE(raw_payload, '$.endpoint') = '/mgmt/tm/ltm/profile/client-ssl'
    """,
}


# ============================================================================
# 6. QUERY LAYER -- SERVING REAL-TIME DASHBOARDS
# ============================================================================
#
# TWO-TIER QUERY ARCHITECTURE:
#
# Tier 1 (sub-second): ClickHouse for real-time dashboard panels
#   - Pre-aggregated metrics from Flink -> Kafka -> ClickHouse materialized views
#   - Posture summary (% compliant per framework/region)
#   - Alert timeline (last N posture changes)
#   - Source health (collector heartbeat status)
#
# Tier 2 (seconds-to-minutes): Trino over Iceberg for ad-hoc analytics
#   - Full telemetry history queries
#   - Cross-framework correlation
#   - Audit trail deep dives
#   - Evidence export for external auditors
#
# WHY TWO TIERS:
#   ClickHouse alone could handle both, but Iceberg gives you:
#   - Time travel for point-in-time audit queries
#   - Schema evolution without downtime
#   - Open format (no vendor lock-in, works with DuckDB locally)
#   Trino alone could serve dashboards, but ClickHouse gives you:
#   - Sub-100ms p95 on pre-aggregated queries
#   - Built-in materialized views that update from Kafka
#   - Lower resource footprint for a fixed set of dashboard queries
#
# FOR WARLOCK LOCAL/DEMO MODE:
#   DuckDB replaces both tiers. Warlock already uses DuckDB for local lake
#   queries. This aligns with the AI-off/air-gapped requirement.

QUERY_LAYER_CONFIG = {
    "clickhouse": {
        "role": "Real-time dashboard serving (Tier 1)",
        "deployment": "ClickHouse Cloud or self-hosted (single node sufficient to start)",
        "ingestion": "Kafka engine tables consuming from warlock.telemetry.* topics",
        "materialized_views": [
            {
                "name": "posture_summary_mv",
                "description": "Per-framework, per-region posture percentage, updated in real-time",
                "refresh": "On Kafka message arrival (ClickHouse Kafka engine)",
                "query_pattern": "SELECT framework, region, posture_state, count(*) ...",
            },
            {
                "name": "alert_timeline_mv",
                "description": "Last 1000 posture state changes across all controls",
                "refresh": "On Kafka message arrival",
                "query_pattern": "SELECT control_id, old_state, new_state, timestamp ... ORDER BY timestamp DESC LIMIT 1000",
            },
            {
                "name": "source_health_mv",
                "description": "Last heartbeat per source_system, staleness detection",
                "refresh": "On Kafka message arrival + periodic (ReplacingMergeTree)",
                "query_pattern": "SELECT source_system, max(timestamp), now() - max(timestamp) as staleness ...",
            },
            {
                "name": "hourly_metrics_mv",
                "description": "Pre-computed hourly rollups for trend charts",
                "refresh": "AggregatingMergeTree from Kafka engine",
                "query_pattern": "SELECT toStartOfHour(timestamp), source_type, count(), avgState(latency) ...",
            },
        ],
    },
    "trino": {
        "role": "Ad-hoc analytics over Iceberg (Tier 2)",
        "deployment": "Trino cluster (coordinator + 2-4 workers) or single-node for small deployments",
        "catalogs": [
            {
                "name": "warlock_telemetry",
                "connector": "iceberg",
                "description": "Full telemetry lake -- raw, enriched, posture, metrics tables",
            },
            {
                "name": "warlock_oltp",
                "connector": "postgresql (or jdbc)",
                "description": "Live OLTP database for federated queries joining lake + operational data",
            },
        ],
        "query_patterns": [
            "Point-in-time compliance posture: SELECT * FROM enriched_events FOR TIMESTAMP AS OF ...",
            "Cross-framework correlation: JOIN enriched_events e1 ON e1.control_id = crosswalk.source_control ...",
            "Evidence export: SELECT * FROM raw_events WHERE control_id = 'ac-2' AND region = 'us' AND date BETWEEN ...",
            "Drift analysis: SELECT * FROM posture_snapshots WHERE old_state != new_state ORDER BY timestamp",
        ],
    },
    "duckdb_local": {
        "role": "Local/demo/air-gapped query engine (replaces both tiers)",
        "deployment": "Embedded in Warlock Python process (existing pattern)",
        "description": (
            "DuckDB reads Parquet files from the lake/ directory directly. "
            "Warlock's existing lake query infrastructure (query.py, readers.py) "
            "already supports this. For telemetry, extend with views that match "
            "the ClickHouse materialized view semantics but computed on-demand."
        ),
    },
}


# ============================================================================
# 7. IMPLEMENTATION SEQUENCE
# ============================================================================
#
# Phased rollout. Each phase is independently valuable. Do not attempt
# to build all 13 collectors simultaneously.

IMPLEMENTATION_PHASES = {
    "phase_1": {
        "name": "Foundation (Weeks 1-3)",
        "description": "Streaming infrastructure + first 2 collectors",
        "deliverables": [
            "Deploy Redpanda cluster (3 nodes, or single-node dev mode)",
            "Create Kafka topic topology (all topics defined above)",
            "Extend Warlock TelemetryEvent schema as PyArrow + Iceberg schema in schema.py",
            "Build TelemetryCollector base class extending Warlock BaseConnector pattern",
            "Implement JBoss JMX collector (highest visibility, multi-region)",
            "Implement Salt event bus collector (configuration posture is foundational)",
            "Write raw telemetry zone writer extending zones.py",
            "Verify end-to-end: JBoss MBean -> Kafka -> Parquet in lake/telemetry/raw/",
            "DuckDB queries over raw Parquet files work locally",
        ],
        "risk": "Jolokia deployment on JBoss instances requires app team coordination",
    },
    "phase_2": {
        "name": "CDC + Processing (Weeks 4-6)",
        "description": "Database change capture + Flink enrichment job",
        "deliverables": [
            "Deploy Kafka Connect with Debezium Oracle + MySQL connectors",
            "Configure Oracle LogMiner for monitored tables",
            "Configure MySQL binlog replication for CA instance",
            "Deploy Flink cluster (standalone or YARN/K8s, 2 TaskManagers)",
            "Implement telemetry_enrichment Flink job (control_id mapping)",
            "Implement posture_evaluation Flink job (first 5 assertion rules)",
            "Wire enriched events to Iceberg enriched_events table",
            "Validate CDC events flow: Oracle DML -> Debezium -> Kafka -> Flink -> Iceberg",
        ],
        "risk": "Oracle LogMiner supplemental logging may require DBA coordination",
    },
    "phase_3": {
        "name": "Network + Security (Weeks 7-9)",
        "description": "Infrastructure telemetry collectors",
        "deliverables": [
            "Implement F5 iControl REST collector",
            "Implement Azure LB metrics collector",
            "Implement syslog collector (DMZ architecture with MirrorMaker)",
            "Implement Windows event log collector (Winlogbeat -> Kafka)",
            "Implement Docker stats/events collector",
            "Deploy ClickHouse with Kafka engine tables",
            "Create first 4 materialized views (posture_summary, alert_timeline, source_health, hourly_metrics)",
            "Connect Warlock dashboard frontend to ClickHouse",
        ],
        "risk": "DMZ Kafka architecture requires network team approval for MirrorMaker",
    },
    "phase_4": {
        "name": "Application + Integration (Weeks 10-12)",
        "description": "Remaining collectors + full query layer",
        "deliverables": [
            "Implement RabbitMQ collector (management API + firehose)",
            "Implement Camel/ServiceMix ESB collector",
            "Implement Jackrabbit observation collector",
            "Implement James email metrics collector",
            "Implement BIRT report execution collector",
            "Deploy Trino with Iceberg catalog",
            "Configure Trino OLTP catalog for federated queries",
            "Implement anomaly detection Flink job",
            "Build Flink SQL rule library (20+ compliance rules)",
            "Storage tiering automation (Iceberg expire_snapshots + lifecycle rules)",
        ],
        "risk": "Camel/ServiceMix instrumentation may require ESB team coordination",
    },
    "phase_5": {
        "name": "Hardening + Scale (Weeks 13-16)",
        "description": "Production readiness, data quality, cost optimization",
        "deliverables": [
            "Data quality checks at each pipeline stage (Great Expectations or dbt tests)",
            "Row count anomaly detection (zero events = collector failure alert)",
            "End-to-end latency monitoring (event timestamp -> lake write timestamp)",
            "Cost monitoring: per-TB processed, per-query cost estimation",
            "Compaction scheduling for Iceberg tables (rewrite_data_files)",
            "Backfill tooling: replay from Kafka topic for missed time ranges",
            "Disaster recovery: Kafka MirrorMaker for cross-region replication",
            "Load testing: simulate peak telemetry volume (10x normal)",
            "Documentation: collector runbooks, schema changelog, troubleshooting",
            "AI-ON integration: route ambiguous posture evaluations to AI reasoning",
        ],
    },
}


# ============================================================================
# 8. COST OPTIMIZATION NOTES
# ============================================================================

COST_OPTIMIZATION = {
    "compute": {
        "collectors": (
            "Collectors are lightweight Python processes. Run on existing infrastructure "
            "where possible (Salt collector on Salt master, JMX collector as a JBoss "
            "co-located container). Do not over-provision dedicated VMs."
        ),
        "flink": (
            "Start with 2 TaskManagers (4 slots each). Flink autoscaler (reactive mode) "
            "adds capacity during peak. Use spot/preemptible instances for TaskManagers. "
            "Coordinator on a reserved instance."
        ),
        "clickhouse": (
            "Single node handles millions of rows/sec for the query patterns above. "
            "ClickHouse Cloud starts at ~$0.10/hr. Self-hosted on a single 16-core, "
            "64GB RAM node is sufficient for <1TB/day telemetry."
        ),
        "trino": (
            "2-4 worker nodes. Use spot instances. Trino is stateless -- workers can "
            "be replaced instantly. Scale down to 1 worker during off-hours."
        ),
    },
    "storage": {
        "parquet_compression": (
            "ZSTD for enriched/posture zones (better ratio than Snappy, worth the CPU). "
            "Snappy for raw zone (lower latency for streaming writes)."
        ),
        "partitioning_efficiency": (
            "Iceberg hidden partitioning avoids the 'too many small files' problem. "
            "Target 128MB-256MB Parquet files. Use Iceberg rewrite_data_files for compaction."
        ),
        "tiering_savings": (
            "Moving 6-month+ data to S3 Glacier Instant Retrieval saves ~68% vs Standard. "
            "For 1TB/month telemetry, this saves ~$15K/year on storage alone."
        ),
    },
    "network": {
        "cross_region": (
            "Minimize cross-region Kafka traffic. Each region should have its own "
            "Kafka broker (or Redpanda node). MirrorMaker replicates only the topics "
            "needed centrally (enriched, posture_changes, not raw regional telemetry)."
        ),
    },
}


# ============================================================================
# 9. DATA QUALITY FRAMEWORK
# ============================================================================

DATA_QUALITY_CHECKS = {
    "completeness": [
        "Every source_type has at least 1 event per poll_interval * 2 (staleness check)",
        "All 5 Oracle databases producing CDC events (no silent connector failure)",
        "All 3 JBoss regions producing JMX telemetry",
        "Windows event log collectors online for all OpTool workstations",
    ],
    "consistency": [
        "SHA-256 of raw_payload matches sha256 field (integrity check)",
        "event_id is globally unique (UUID collision check on sample)",
        "timestamp is within 5 minutes of ingested_at (clock skew check)",
        "posture_state values are in the 5-value enum (no garbage states)",
    ],
    "accuracy": [
        "Control_id mappings validated against framework YAML definitions",
        "Region field matches known region codes (us, uk, au, ca)",
        "Source_type matches registered collector types",
    ],
    "timeliness": [
        "P95 end-to-end latency (event -> lake) < 5 minutes for streaming sources",
        "P95 end-to-end latency (event -> lake) < 2x poll_interval for polled sources",
        "ClickHouse materialized views lag < 30 seconds behind Kafka",
    ],
    "implementation": (
        "Flink anomaly_detection job handles real-time checks. "
        "Batch checks run hourly via Warlock pipeline scheduler (scheduler.py). "
        "Results written to warlock.telemetry.data_quality Kafka topic and "
        "surfaced in ClickHouse source_health_mv."
    ),
}
