"""Alert routing for compliance posture changes.

When controls degrade past thresholds, sends notifications
to configured channels (Slack webhook, PagerDuty, email, generic webhook).

Also provides WebhookSubscriber — an EventBus subscriber that forwards
pipeline events (finding.normalized, control.assessed) to configured
outbound webhook URLs with HMAC-SHA256 request signing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import smtplib
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore
    _HAS_HTTPX = False

from warlock.assessors.posture import ControlPosture

log = logging.getLogger(__name__)

TIMEOUT = 15.0
MAX_RETRIES = 1

# ---------------------------------------------------------------------------
# Email rate limiter: max 100 emails per rolling hour window
# ---------------------------------------------------------------------------

_email_rate_lock = threading.Lock()
_email_send_timestamps: list[float] = []
_EMAIL_RATE_LIMIT = 100
_EMAIL_RATE_WINDOW_SECONDS = 3600.0


def _check_email_rate_limit() -> bool:
    """Return True if sending is allowed under the rate limit.

    Maintains an in-memory list of send timestamps and prunes entries
    older than the 1-hour window. Thread-safe.
    """
    now = time.monotonic()
    with _email_rate_lock:
        # Prune old entries
        cutoff = now - _EMAIL_RATE_WINDOW_SECONDS
        while _email_send_timestamps and _email_send_timestamps[0] < cutoff:
            _email_send_timestamps.pop(0)
        if len(_email_send_timestamps) >= _EMAIL_RATE_LIMIT:
            return False
        _email_send_timestamps.append(now)
        return True


# ---------------------------------------------------------------------------
# WebhookSubscriber (#34)
# ---------------------------------------------------------------------------

_WEBHOOK_EVENT_TYPES = {"finding.normalized", "control.assessed"}
_WEBHOOK_MAX_RETRIES = 3


class WebhookSubscriber:
    """EventBus subscriber that POSTs pipeline events to configured URLs.

    Subscribes to ``finding.normalized`` and ``control.assessed`` events and
    forwards them via HTTP POST with an HMAC-SHA256 signature so recipients can
    verify authenticity.

    Configuration (read from environment at construction time):
        WLK_WEBHOOK_URLS   — comma-separated list of target URLs
        WLK_WEBHOOK_SECRET — shared secret for HMAC-SHA256 signing (optional)

    The signature is placed in the ``X-Warlock-Signature`` request header as
    ``sha256=<hex-digest>`` of the raw JSON body.  Retries up to 3 times with
    exponential backoff (1s, 2s, 4s).
    """

    def __init__(
        self,
        urls: list[str] | None = None,
        secret: str = "",
    ) -> None:
        if urls is None:
            raw = os.environ.get("WLK_WEBHOOK_URLS", "")
            urls = [u.strip() for u in raw.split(",") if u.strip()]
        if not secret:
            secret = os.environ.get("WLK_WEBHOOK_SECRET", "")
        self.urls: list[str] = urls
        self._secret: str = secret

    # ------------------------------------------------------------------
    # EventBus handler interface
    # ------------------------------------------------------------------

    def __call__(self, event: Any) -> None:
        """Handle a PipelineEvent — called by the EventBus."""
        if not self.urls:
            return
        if event.event_type not in _WEBHOOK_EVENT_TYPES:
            return
        self._deliver(event)

    # Friendly name used by _safe_call in bus.py for log messages
    __name__ = "WebhookSubscriber"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_payload(self, event: Any) -> dict[str, Any]:
        """Serialise a PipelineEvent into a plain dict."""
        return {
            "id": event.id,
            "event_type": event.event_type,
            "payload_id": event.payload_id,
            "timestamp": event.timestamp.isoformat(),
            "metadata": event.metadata,
        }

    def _sign(self, body: bytes) -> str:
        """Return ``sha256=<hex>`` HMAC signature for *body*."""
        if not self._secret:
            return ""
        digest = hmac.new(self._secret.encode(), body, hashlib.sha256).hexdigest()
        return f"sha256={digest}"

    def _deliver(self, event: Any) -> None:
        """POST the event to every configured URL with retry + backoff."""
        payload_dict = self._build_payload(event)
        body = json.dumps(payload_dict, default=str).encode()
        signature = self._sign(body)

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if signature:
            headers["X-Warlock-Signature"] = signature

        for url in self.urls:
            self._post_with_retry(url, body, headers, event.event_type)

    def _post_with_retry(
        self,
        url: str,
        body: bytes,
        headers: dict[str, str],
        event_type: str,
    ) -> None:
        """POST *body* to *url*, retrying up to _WEBHOOK_MAX_RETRIES times."""
        if not _HAS_HTTPX:
            log.error("httpx not installed — cannot deliver webhook event")
            return

        for attempt in range(_WEBHOOK_MAX_RETRIES):
            try:
                resp = httpx.post(url, content=body, headers=headers, timeout=TIMEOUT)
                resp.raise_for_status()
                log.debug(
                    "Webhook delivered: event=%s url=%s status=%d",
                    event_type,
                    url,
                    resp.status_code,
                )
                return
            except Exception as exc:
                wait = 2**attempt  # 1s, 2s, 4s
                if attempt < _WEBHOOK_MAX_RETRIES - 1:
                    log.warning(
                        "Webhook POST failed (attempt %d/%d): url=%s error=%s — retrying in %ds",
                        attempt + 1,
                        _WEBHOOK_MAX_RETRIES,
                        url,
                        exc,
                        wait,
                    )
                    time.sleep(wait)
                else:
                    log.error(
                        "Webhook POST failed after %d attempts: url=%s error=%s",
                        _WEBHOOK_MAX_RETRIES,
                        url,
                        exc,
                    )


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class AlertConfig:
    """Configuration for a single alert channel."""

    channel: str  # "slack", "pagerduty", "webhook", "email"
    url: str = ""  # webhook URL
    api_key: str = ""  # for PagerDuty routing key
    threshold_score: float = 70.0  # posture score below which to alert
    threshold_status: list[str] = field(default_factory=lambda: ["non_compliant"])
    frameworks: list[str] = field(default_factory=list)  # empty = all
    severities: list[str] = field(default_factory=list)  # empty = all
    enabled: bool = True


@dataclass
class AlertResult:
    """Result of an alert send attempt."""

    channel: str
    framework: str
    control_id: str
    status: str
    posture_score: float
    sent_at: datetime
    success: bool
    error: str = ""


# ---------------------------------------------------------------------------
# Slack Block Kit message builder
# ---------------------------------------------------------------------------


def _build_slack_blocks(posture: ControlPosture) -> dict[str, Any]:
    """Build a Slack Block Kit message for a posture alert."""
    # Status emoji
    status_emoji = {
        "non_compliant": ":red_circle:",
        "partial": ":large_orange_circle:",
        "compliant": ":large_green_circle:",
        "not_assessed": ":white_circle:",
    }.get(posture.status, ":question:")

    freshness_text = (
        f"{posture.evidence_freshness_hours:.1f}h ago"
        if posture.evidence_freshness_hours is not None
        else "unknown"
    )

    return {
        "text": (
            f"{status_emoji} Control {posture.control_id} ({posture.framework}) "
            f"posture degraded to {posture.posture_score:.0f}%"
        ),
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"Compliance Alert: {posture.framework} / {posture.control_id}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{status_emoji} {posture.status}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Posture Score:*\n{posture.posture_score:.1f} / 100",
                    },
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"*Findings:*\n"
                            f":white_check_mark: {posture.compliant_count}  "
                            f":x: {posture.non_compliant_count}  "
                            f":warning: {posture.partial_count}"
                        ),
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Last Evidence:*\n{freshness_text}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"*Evidence Sources:* {', '.join(posture.evidence_sources) or 'none'}\n"
                        f"*Total Findings:* {posture.total_findings}"
                    ),
                },
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": (
                            f"Warlock GRC | {posture.assessed_at.strftime('%Y-%m-%d %H:%M UTC')}"
                        ),
                    },
                ],
            },
        ],
    }


# ---------------------------------------------------------------------------
# PagerDuty Events API v2 payload
# ---------------------------------------------------------------------------


def _build_pagerduty_payload(config: AlertConfig, posture: ControlPosture) -> dict[str, Any]:
    """Build a PagerDuty Events API v2 trigger payload."""
    severity_map = {
        "non_compliant": "critical",
        "partial": "warning",
        "compliant": "info",
        "not_assessed": "info",
    }
    return {
        "routing_key": config.api_key,
        "event_action": "trigger",
        "dedup_key": f"warlock-{posture.framework}-{posture.control_id}",
        "payload": {
            "summary": (
                f"Compliance posture degraded: {posture.framework}/{posture.control_id} "
                f"— {posture.status} (score: {posture.posture_score:.0f}%)"
            ),
            "source": "warlock-grc",
            "severity": severity_map.get(posture.status, "warning"),
            "component": posture.control_id,
            "group": posture.framework,
            "class": "compliance",
            "custom_details": {
                "posture_score": posture.posture_score,
                "total_findings": posture.total_findings,
                "compliant_count": posture.compliant_count,
                "non_compliant_count": posture.non_compliant_count,
                "partial_count": posture.partial_count,
                "evidence_sources": posture.evidence_sources,
                "evidence_freshness_hours": posture.evidence_freshness_hours,
            },
        },
    }


# ---------------------------------------------------------------------------
# Generic webhook payload
# ---------------------------------------------------------------------------


def _build_webhook_payload(posture: ControlPosture) -> dict[str, Any]:
    """Build a generic JSON webhook payload."""
    return {
        "event": "posture_degradation",
        "framework": posture.framework,
        "control_id": posture.control_id,
        "status": posture.status,
        "posture_score": posture.posture_score,
        "total_findings": posture.total_findings,
        "compliant_count": posture.compliant_count,
        "non_compliant_count": posture.non_compliant_count,
        "partial_count": posture.partial_count,
        "not_assessed_count": posture.not_assessed_count,
        "evidence_sources": posture.evidence_sources,
        "evidence_freshness_hours": posture.evidence_freshness_hours,
        "assessed_at": posture.assessed_at.isoformat(),
    }


# ---------------------------------------------------------------------------
# AlertRouter
# ---------------------------------------------------------------------------


class AlertRouter:
    """Evaluates posture against thresholds and routes alerts to channels."""

    def __init__(self, configs: list[AlertConfig]) -> None:
        self.configs = [c for c in configs if c.enabled]
        self._last_error: str = ""
        # W-9: Alert deduplication cache
        self._sent_cache: dict[str, datetime] = {}
        self.cooldown_minutes: int = self._load_cooldown_minutes()

    def evaluate_and_alert(
        self,
        postures: list[ControlPosture],
    ) -> list[AlertResult]:
        """Check each posture against thresholds and send alerts.

        Args:
            postures: List of ControlPosture to evaluate.

        Returns:
            List of AlertResult for every alert attempted.
        """
        results: list[AlertResult] = []
        now = datetime.now(timezone.utc)

        for posture in postures:
            for config in self.configs:
                if not self._should_alert(config, posture):
                    continue

                # W-9: Check dedup cooldown
                dedup_key = f"{posture.framework}|{posture.control_id}|{posture.status}"
                last_sent = self._sent_cache.get(dedup_key)
                if last_sent is not None:
                    elapsed = (now - last_sent).total_seconds() / 60
                    if elapsed < self.cooldown_minutes:
                        continue

                result = self._send_alert(config, posture)
                results.append(result)

                if result.success:
                    self._sent_cache[dedup_key] = now

        return results

    def _should_alert(self, config: AlertConfig, posture: ControlPosture) -> bool:
        """Determine if a posture triggers this alert config."""
        # Framework filter
        if config.frameworks and posture.framework not in config.frameworks:
            return False

        # Check if status matches threshold
        status_match = posture.status in config.threshold_status

        # Check if score is below threshold
        score_match = posture.posture_score < config.threshold_score

        # Alert if either condition is met
        return status_match or score_match

    def _send_alert(self, config: AlertConfig, posture: ControlPosture) -> AlertResult:
        """Dispatch to the appropriate channel sender."""
        senders = {
            "slack": self.send_slack,
            "pagerduty": self.send_pagerduty,
            "webhook": self.send_webhook,
            "email": self.send_email,
        }

        sender = senders.get(config.channel)
        if not sender:
            return AlertResult(
                channel=config.channel,
                framework=posture.framework,
                control_id=posture.control_id,
                status=posture.status,
                posture_score=posture.posture_score,
                sent_at=datetime.now(timezone.utc),
                success=False,
                error=f"Unknown channel: {config.channel}",
            )

        success = False
        error = ""
        try:
            success = sender(config, posture)
        except Exception as e:
            error = str(e)
            log.exception(
                "Alert send failed: channel=%s framework=%s control=%s",
                config.channel,
                posture.framework,
                posture.control_id,
            )

        return AlertResult(
            channel=config.channel,
            framework=posture.framework,
            control_id=posture.control_id,
            status=posture.status,
            posture_score=posture.posture_score,
            sent_at=datetime.now(timezone.utc),
            success=success,
            error=error,
        )

    def send_slack(self, config: AlertConfig, posture: ControlPosture) -> bool:
        """POST to Slack webhook with Block Kit formatted message.

        Args:
            config: Alert configuration with Slack webhook URL.
            posture: Control posture triggering the alert.

        Returns:
            True if sent successfully.
        """
        if not config.url:
            log.warning("Slack alert config has no URL")
            return False

        payload = _build_slack_blocks(posture)
        return self._post_with_retry(config.url, payload)

    def send_pagerduty(self, config: AlertConfig, posture: ControlPosture) -> bool:
        """POST to PagerDuty Events API v2.

        Args:
            config: Alert configuration with PagerDuty routing key.
            posture: Control posture triggering the alert.

        Returns:
            True if sent successfully.
        """
        if not config.api_key:
            log.warning("PagerDuty alert config has no api_key (routing key)")
            return False

        url = "https://events.pagerduty.com/v2/enqueue"
        payload = _build_pagerduty_payload(config, posture)
        return self._post_with_retry(url, payload)

    def send_webhook(self, config: AlertConfig, posture: ControlPosture) -> bool:
        """POST generic JSON payload to a webhook URL.

        Args:
            config: Alert configuration with webhook URL.
            posture: Control posture triggering the alert.

        Returns:
            True if sent successfully.
        """
        if not config.url:
            log.warning("Webhook alert config has no URL")
            return False

        payload = _build_webhook_payload(posture)
        return self._post_with_retry(config.url, payload)

    def send_email(self, config: AlertConfig, posture: ControlPosture) -> bool:
        """Send an email alert for a posture degradation via SMTP.

        Reads SMTP configuration from ``get_settings()``. Supports both
        STARTTLS (port 587) and implicit SSL (port 465). Falls back to
        a log warning if SMTP is not configured.

        Args:
            config: Alert configuration. ``config.url`` is used as the
                recipient email address.
            posture: Control posture triggering the alert.

        Returns:
            True if sent successfully, False otherwise.
        """
        from warlock.config import get_settings

        settings = get_settings()
        if not settings.smtp_host:
            log.warning(
                "Email alert skipped — smtp_host not configured: "
                "framework=%s control=%s status=%s score=%.1f",
                posture.framework,
                posture.control_id,
                posture.status,
                posture.posture_score,
            )
            self._last_error = "SMTP not configured (smtp_host is empty)"
            return False

        recipient = config.url
        if not recipient:
            log.warning("Email alert config has no recipient (url field)")
            self._last_error = "No recipient email address"
            return False

        subject = (
            f"[Warlock GRC] Compliance Alert: {posture.framework} / "
            f"{posture.control_id} — {posture.status}"
        )
        body_html = _build_posture_email_html(posture)

        return self._smtp_send(
            settings=settings,
            recipient=recipient,
            subject=subject,
            body_html=body_html,
        )

    def send_escalation_email(
        self,
        recipient: str,
        subject: str,
        body_html: str,
    ) -> bool:
        """Send an escalation notification email via SMTP.

        Called by the escalation engine. Uses the same SMTP transport
        as ``send_email`` but accepts pre-built subject and body.

        Args:
            recipient: Destination email address.
            subject: Email subject line.
            body_html: HTML body content.

        Returns:
            True if sent successfully, False otherwise.
        """
        from warlock.config import get_settings

        settings = get_settings()
        if not settings.smtp_host:
            log.warning("Escalation email skipped — smtp_host not configured")
            self._last_error = "SMTP not configured (smtp_host is empty)"
            return False

        return self._smtp_send(
            settings=settings,
            recipient=recipient,
            subject=subject,
            body_html=body_html,
        )

    def _smtp_send(
        self,
        settings: Any,
        recipient: str,
        subject: str,
        body_html: str,
    ) -> bool:
        """Low-level SMTP send with rate limiting and error handling.

        Supports STARTTLS (port 587) and implicit SSL (port 465).
        Authenticates when ``smtp_user`` and ``smtp_password`` are set.

        Args:
            settings: Application settings object with smtp_* fields.
            recipient: Destination email address.
            subject: Email subject line.
            body_html: HTML body content.

        Returns:
            True on success, False on failure.
        """
        if not _check_email_rate_limit():
            log.warning(
                "Email rate limit exceeded (%d/hour) — dropping email to %s",
                _EMAIL_RATE_LIMIT,
                recipient,
            )
            self._last_error = "Rate limit exceeded"
            return False

        msg = MIMEMultipart("alternative")
        msg["From"] = settings.smtp_from
        msg["To"] = recipient
        msg["Subject"] = subject
        msg["X-Mailer"] = "Warlock GRC"

        # Plain text fallback
        import html as html_mod

        plain_text = html_mod.unescape(
            body_html.replace("<br>", "\n")
            .replace("<br/>", "\n")
            .replace("</p>", "\n")
            .replace("</tr>", "\n")
            .replace("</td>", " | ")
        )
        # Strip remaining tags
        import re

        plain_text = re.sub(r"<[^>]+>", "", plain_text)

        msg.attach(MIMEText(plain_text, "plain", "utf-8"))
        msg.attach(MIMEText(body_html, "html", "utf-8"))

        try:
            if settings.smtp_port == 465:
                # Implicit SSL
                with smtplib.SMTP_SSL(
                    settings.smtp_host,
                    settings.smtp_port,
                    timeout=TIMEOUT,
                ) as server:
                    if settings.smtp_user and settings.smtp_password:
                        server.login(settings.smtp_user, settings.smtp_password)
                    server.send_message(msg)
            else:
                # STARTTLS or plain
                with smtplib.SMTP(
                    settings.smtp_host,
                    settings.smtp_port,
                    timeout=TIMEOUT,
                ) as server:
                    server.ehlo()
                    if settings.smtp_tls:
                        server.starttls()
                        server.ehlo()
                    if settings.smtp_user and settings.smtp_password:
                        server.login(settings.smtp_user, settings.smtp_password)
                    server.send_message(msg)

            log.info(
                "Email sent successfully: to=%s subject=%s",
                recipient,
                subject[:80],
            )
            return True

        except smtplib.SMTPAuthenticationError as exc:
            self._last_error = f"SMTP authentication failed: {exc}"
            log.error("SMTP auth failed for %s: %s", settings.smtp_host, exc)
            return False
        except smtplib.SMTPException as exc:
            self._last_error = f"SMTP error: {exc}"
            log.error("SMTP error sending to %s: %s", recipient, exc)
            return False
        except OSError as exc:
            self._last_error = f"SMTP connection error: {exc}"
            log.error(
                "Failed to connect to SMTP %s:%d: %s",
                settings.smtp_host,
                settings.smtp_port,
                exc,
            )
            return False

    @staticmethod
    def _post_with_retry(
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> bool:
        """POST JSON with one retry on failure.

        Args:
            url: Target URL.
            payload: JSON payload.
            headers: Optional extra headers.

        Returns:
            True if any attempt succeeds.
        """
        if not _HAS_HTTPX:
            log.error("httpx is not installed — cannot send alert")
            return False

        request_headers = {"Content-Type": "application/json"}
        if headers:
            request_headers.update(headers)

        last_error: Exception | None = None
        for attempt in range(1 + MAX_RETRIES):
            try:
                resp = httpx.post(
                    url,
                    json=payload,
                    headers=request_headers,
                    timeout=TIMEOUT,
                )
                resp.raise_for_status()
                return True
            except Exception as e:
                last_error = e
                if attempt < MAX_RETRIES:
                    log.warning(
                        "Alert POST to %s failed (attempt %d/%d): %s",
                        url,
                        attempt + 1,
                        1 + MAX_RETRIES,
                        e,
                    )

        log.error("Alert POST to %s failed after retries: %s", url, last_error)
        return False

    @staticmethod
    def _load_cooldown_minutes() -> int:
        """Load cooldown from config, falling back to 60 minutes.

        Reads ``escalation_check_interval_minutes`` from the application
        settings. If config loading fails (e.g. during early startup),
        defaults to 60 minutes.
        """
        try:
            from warlock.config import get_settings

            settings = get_settings()
            return settings.escalation_check_interval_minutes or 60
        except Exception:
            return 60


# ---------------------------------------------------------------------------
# Email HTML template for posture alerts
# ---------------------------------------------------------------------------


def _build_posture_email_html(posture: ControlPosture) -> str:
    """Build an HTML email body for a posture degradation alert.

    The template includes severity-coloured status, posture score,
    finding counts, evidence freshness, and a footer with the
    assessment timestamp.
    """
    status_color = {
        "non_compliant": "#c0392b",
        "partial": "#e67e22",
        "compliant": "#27ae60",
        "not_assessed": "#95a5a6",
    }.get(posture.status, "#7f8c8d")

    freshness_text = (
        f"{posture.evidence_freshness_hours:.1f} hours ago"
        if posture.evidence_freshness_hours is not None
        else "unknown"
    )

    assessed_str = (
        posture.assessed_at.strftime("%Y-%m-%d %H:%M UTC") if posture.assessed_at else "N/A"
    )

    return f"""<html>
<body style="font-family: sans-serif; color: #333; max-width: 600px;">
<h2 style="color: {status_color};">
  Compliance Alert: {posture.framework} / {posture.control_id}
</h2>
<p>The posture for control <strong>{posture.control_id}</strong> in
<strong>{posture.framework}</strong> has degraded and requires attention.</p>

<table style="border-collapse: collapse; width: 100%;">
  <tr>
    <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Status</td>
    <td style="padding: 8px; border-bottom: 1px solid #ddd; color: {status_color};">
      {posture.status}
    </td>
  </tr>
  <tr>
    <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Posture Score</td>
    <td style="padding: 8px; border-bottom: 1px solid #ddd;">
      {posture.posture_score:.1f} / 100
    </td>
  </tr>
  <tr>
    <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Findings</td>
    <td style="padding: 8px; border-bottom: 1px solid #ddd;">
      Compliant: {posture.compliant_count} |
      Non-compliant: {posture.non_compliant_count} |
      Partial: {posture.partial_count} |
      Total: {posture.total_findings}
    </td>
  </tr>
  <tr>
    <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Evidence Sources</td>
    <td style="padding: 8px; border-bottom: 1px solid #ddd;">
      {", ".join(posture.evidence_sources) or "none"}
    </td>
  </tr>
  <tr>
    <td style="padding: 8px; font-weight: bold; border-bottom: 1px solid #ddd;">Last Evidence</td>
    <td style="padding: 8px; border-bottom: 1px solid #ddd;">{freshness_text}</td>
  </tr>
</table>

<hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
<p style="font-size: 12px; color: #888;">
  Warlock GRC | Assessed at {assessed_str}
</p>
</body>
</html>"""
