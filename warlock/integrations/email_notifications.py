"""Email notification service for Warlock GRC platform.

Supports SMTP and AWS SES (optional). Subscribes to EventBus for critical events.
"""

from __future__ import annotations

import logging
import smtplib
from dataclasses import dataclass
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any

from warlock.config import get_settings

log = logging.getLogger(__name__)

# Optional AWS SES support
try:
    import boto3

    _HAS_BOTO3 = True
except ImportError:
    _HAS_BOTO3 = False


# ---------------------------------------------------------------------------
# Templates (simple f-string based)
# ---------------------------------------------------------------------------

_TEMPLATES: dict[str, dict[str, str]] = {
    "alert_digest": {
        "subject": "Warlock Alert Digest — {date}",
        "body": (
            "Warlock GRC Alert Digest\n"
            "========================\n\n"
            "Date: {date}\n"
            "New findings: {finding_count}\n"
            "Critical controls: {critical_count}\n"
            "Non-compliant controls: {non_compliant_count}\n\n"
            "Summary:\n{summary}\n\n"
            "— Warlock GRC Platform"
        ),
    },
    "evidence_request": {
        "subject": "Evidence Request: {control_id} ({framework})",
        "body": (
            "Evidence Request\n"
            "================\n\n"
            "Framework: {framework}\n"
            "Control: {control_id}\n"
            "Description: {description}\n"
            "Due date: {due_date}\n"
            "Requested by: {requestor}\n\n"
            "Please upload the required evidence to the Warlock portal.\n\n"
            "— Warlock GRC Platform"
        ),
    },
    "poam_reminder": {
        "subject": "POA&M Reminder: {poam_id} — {weakness}",
        "body": (
            "POA&M Reminder\n"
            "==============\n\n"
            "POA&M ID: {poam_id}\n"
            "Framework: {framework}\n"
            "Control: {control_id}\n"
            "Weakness: {weakness}\n"
            "Status: {status}\n"
            "Due date: {due_date}\n\n"
            "This item requires your attention.\n\n"
            "— Warlock GRC Platform"
        ),
    },
    "compliance_report": {
        "subject": "Compliance Report — {framework} — {date}",
        "body": (
            "Compliance Report\n"
            "=================\n\n"
            "Framework: {framework}\n"
            "Date: {date}\n"
            "Posture score: {score}%\n\n"
            "Compliant: {compliant}\n"
            "Non-compliant: {non_compliant}\n"
            "Partial: {partial}\n"
            "Not assessed: {not_assessed}\n\n"
            "— Warlock GRC Platform"
        ),
    },
}


@dataclass
class EmailMessage:
    to: list[str]
    subject: str
    body: str
    html: str | None = None


class EmailNotifier:
    """Email notification service supporting SMTP and AWS SES."""

    def __init__(
        self,
        smtp_host: str | None = None,
        smtp_port: int | None = None,
        smtp_user: str | None = None,
        smtp_password: str | None = None,
        email_from: str | None = None,
        use_ses: bool = False,
        ses_region: str = "us-east-1",
    ) -> None:
        settings = get_settings()
        self.smtp_host = smtp_host or settings.smtp_host
        self.smtp_port = smtp_port or settings.smtp_port
        self.smtp_user = smtp_user or settings.smtp_user
        self.smtp_password = smtp_password or settings.smtp_password
        self.email_from = email_from or settings.smtp_from
        self.use_ses = use_ses
        self.ses_region = ses_region

    # -- Template rendering ---------------------------------------------------

    @staticmethod
    def render_template(template_name: str, **kwargs: Any) -> tuple[str, str]:
        """Render a named template with the given variables.

        Returns:
            Tuple of (subject, body).

        Raises:
            KeyError: If the template name is unknown.
        """
        if template_name not in _TEMPLATES:
            available = ", ".join(sorted(_TEMPLATES))
            raise KeyError(f"Unknown template: {template_name!r}. Available: {available}")

        tmpl = _TEMPLATES[template_name]
        subject = tmpl["subject"].format_map(kwargs)
        body = tmpl["body"].format_map(kwargs)
        return subject, body

    # -- Sending --------------------------------------------------------------

    def send(self, message: EmailMessage) -> bool:
        """Send an email message.

        Returns True on success, False on failure (logged, never raised).
        """
        if self.use_ses:
            return self._send_ses(message)
        return self._send_smtp(message)

    def send_template(self, template_name: str, to: list[str], **kwargs: Any) -> bool:
        """Render a template and send it."""
        subject, body = self.render_template(template_name, **kwargs)
        return self.send(EmailMessage(to=to, subject=subject, body=body))

    # -- SMTP -----------------------------------------------------------------

    def _send_smtp(self, message: EmailMessage) -> bool:
        if not self.smtp_host:
            log.warning("SMTP host not configured — email not sent")
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = self.email_from
            msg["To"] = ", ".join(message.to)
            msg["Subject"] = message.subject
            msg.attach(MIMEText(message.body, "plain"))
            if message.html:
                msg.attach(MIMEText(message.html, "html"))

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                if self.smtp_user and self.smtp_password:
                    server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.email_from, message.to, msg.as_string())

            log.info("Email sent to %s: %s", message.to, message.subject)
            return True
        except Exception:
            log.exception("Failed to send email to %s", message.to)
            return False

    # -- AWS SES --------------------------------------------------------------

    def _send_ses(self, message: EmailMessage) -> bool:
        if not _HAS_BOTO3:
            log.error("boto3 not installed — cannot send via SES")
            return False

        try:
            client = boto3.client("ses", region_name=self.ses_region)
            body: dict[str, Any] = {"Text": {"Data": message.body, "Charset": "UTF-8"}}
            if message.html:
                body["Html"] = {"Data": message.html, "Charset": "UTF-8"}

            client.send_email(
                Source=self.email_from,
                Destination={"ToAddresses": message.to},
                Message={
                    "Subject": {"Data": message.subject, "Charset": "UTF-8"},
                    "Body": body,
                },
            )
            log.info("SES email sent to %s: %s", message.to, message.subject)
            return True
        except Exception:
            log.exception("Failed to send SES email to %s", message.to)
            return False

    # -- EventBus subscriber interface ----------------------------------------

    def __call__(self, event: Any) -> None:
        """EventBus handler — sends alert digest for critical events."""
        settings = get_settings()
        if not settings.email_enabled:
            return

        event_type = getattr(event, "event_type", "")
        metadata = getattr(event, "metadata", {})

        # Only send for assessed controls that are non-compliant
        if event_type == "control.assessed" and metadata.get("status") == "non_compliant":
            recipients = metadata.get("notify_emails", [])
            if not recipients:
                return

            self.send_template(
                "alert_digest",
                to=recipients,
                date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                finding_count=metadata.get("finding_count", 0),
                critical_count=metadata.get("critical_count", 0),
                non_compliant_count=1,
                summary=f"Control {metadata.get('control_id', '?')} assessed as non-compliant.",
            )
