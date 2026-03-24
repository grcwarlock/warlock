"""Microsoft Teams integration via incoming webhooks and Adaptive Cards.

Provides a ``TeamsNotifier`` that sends richly formatted Adaptive Cards
to Teams channels for findings, approval requests, and compliance posture
summaries.
"""

from __future__ import annotations

import logging
from typing import Any

try:
    import httpx

    _HAS_HTTPX = True
except ImportError:
    httpx = None  # type: ignore[assignment]
    _HAS_HTTPX = False

log = logging.getLogger(__name__)

_MAX_RETRIES = 3
_TIMEOUT = 15.0

# Severity -> color for Adaptive Card container styles
_SEVERITY_COLORS: dict[str, str] = {
    "critical": "attention",  # red
    "high": "attention",
    "medium": "warning",  # yellow
    "low": "good",  # green
    "info": "accent",  # blue
}


class TeamsNotifierError(Exception):
    """Raised when a Teams notification fails."""


class TeamsNotifier:
    """Microsoft Teams integration for sending Adaptive Cards via webhooks.

    Each method that sends a card requires an explicit ``webhook_url``
    parameter so different channels can receive different notification types.
    """

    def __init__(self) -> None:
        if not _HAS_HTTPX:
            raise TeamsNotifierError("httpx is required for Teams integration")

    # ------------------------------------------------------------------
    # Low-level send
    # ------------------------------------------------------------------

    def send_adaptive_card(self, webhook_url: str, card_data: dict[str, Any]) -> bool:
        """Send an Adaptive Card payload to a Teams incoming webhook.

        Args:
            webhook_url: The Teams incoming webhook URL.
            card_data: An Adaptive Card payload dict.  If it does not contain
                the ``type`` and ``$schema`` keys, they are added automatically.

        Returns:
            True if the card was delivered successfully.

        Raises:
            TeamsNotifierError: After all retries are exhausted.
        """
        if not webhook_url:
            raise TeamsNotifierError("webhook_url is required")

        # Ensure the payload has the Adaptive Card wrapper
        if "type" not in card_data or card_data.get("type") != "message":
            card_data = {
                "type": "message",
                "attachments": [
                    {
                        "contentType": "application/vnd.microsoft.card.adaptive",
                        "contentUrl": None,
                        "content": self._ensure_card_envelope(card_data),
                    }
                ],
            }

        last_exc: Exception | None = None
        for attempt in range(_MAX_RETRIES):
            try:
                resp = httpx.post(
                    webhook_url,
                    json=card_data,
                    headers={"Content-Type": "application/json"},
                    timeout=_TIMEOUT,
                )
                resp.raise_for_status()
                log.debug("Teams adaptive card delivered to webhook")
                return True
            except Exception as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES - 1:
                    import time

                    wait = 2**attempt
                    log.warning(
                        "Teams POST failed (attempt %d/%d): %s -- retrying in %ds",
                        attempt + 1,
                        _MAX_RETRIES,
                        exc,
                        wait,
                    )
                    time.sleep(wait)

        raise TeamsNotifierError(
            f"Teams notification failed after {_MAX_RETRIES} attempts: {last_exc}"
        )

    @staticmethod
    def _ensure_card_envelope(card: dict[str, Any]) -> dict[str, Any]:
        """Ensure the card dict has Adaptive Card schema and type."""
        if card.get("type") == "AdaptiveCard":
            return card
        return {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": card.get("body", []),
            "actions": card.get("actions", []),
        }

    # ------------------------------------------------------------------
    # Card builders
    # ------------------------------------------------------------------

    def build_finding_card(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Build an Adaptive Card for a compliance finding notification.

        Args:
            finding: Dict with ``title``, ``severity``, ``source``,
                ``description``, ``resource_id``, ``finding_id``.

        Returns:
            Adaptive Card payload ready for ``send_adaptive_card()``.
        """
        title = finding.get("title", "Untitled Finding")
        severity = (finding.get("severity") or "medium").lower()
        source = finding.get("source", "unknown")
        description = finding.get("description", "")
        resource_id = finding.get("resource_id", "N/A")
        finding_id = finding.get("finding_id") or finding.get("id", "N/A")

        color_style = _SEVERITY_COLORS.get(severity, "default")

        return {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "Container",
                    "style": color_style,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": f"Finding: {title}",
                            "weight": "Bolder",
                            "size": "Medium",
                            "wrap": True,
                        }
                    ],
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Severity", "value": severity.capitalize()},
                        {"title": "Source", "value": source},
                        {"title": "Resource", "value": resource_id},
                        {"title": "Finding ID", "value": str(finding_id)},
                    ],
                },
                {
                    "type": "TextBlock",
                    "text": description[:500] if description else "No description.",
                    "wrap": True,
                    "isSubtle": True,
                },
            ],
            "actions": [
                {
                    "type": "Action.OpenUrl",
                    "title": "View in Warlock",
                    "url": f"https://warlock.local/findings/{finding_id}",
                }
            ],
        }

    def build_approval_card(self, approval_request: dict[str, Any]) -> dict[str, Any]:
        """Build an Adaptive Card with approve/reject actions.

        Args:
            approval_request: Dict with ``title``, ``request_id``,
                ``requester``, ``description``, ``risk_level``,
                ``callback_url``.

        Returns:
            Adaptive Card payload with Action.Submit buttons.
        """
        title = approval_request.get("title", "Approval Required")
        request_id = approval_request.get("request_id", "N/A")
        requester = approval_request.get("requester", "N/A")
        description = approval_request.get("description", "")
        risk_level = approval_request.get("risk_level", "moderate")
        callback_url = approval_request.get("callback_url", "")

        return {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "TextBlock",
                    "text": f"Approval Required: {title}",
                    "weight": "Bolder",
                    "size": "Medium",
                    "wrap": True,
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Request ID", "value": str(request_id)},
                        {"title": "Requester", "value": requester},
                        {"title": "Risk Level", "value": risk_level.capitalize()},
                    ],
                },
                {
                    "type": "TextBlock",
                    "text": description[:500] if description else "No description.",
                    "wrap": True,
                    "isSubtle": True,
                },
                {
                    "type": "Input.Text",
                    "id": "comment",
                    "placeholder": "Optional comment...",
                    "isMultiline": True,
                },
            ],
            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Approve",
                    "style": "positive",
                    "data": {
                        "action": "approve",
                        "request_id": request_id,
                        "callback_url": callback_url,
                    },
                },
                {
                    "type": "Action.Submit",
                    "title": "Reject",
                    "style": "destructive",
                    "data": {
                        "action": "reject",
                        "request_id": request_id,
                        "callback_url": callback_url,
                    },
                },
            ],
        }

    def build_posture_card(self, posture_summary: dict[str, Any]) -> dict[str, Any]:
        """Build an Adaptive Card with compliance posture summary.

        Args:
            posture_summary: Dict with ``overall_score``, ``frameworks``
                (list of dicts with ``name``, ``score``, ``total_controls``,
                ``compliant_controls``), ``timestamp``, ``critical_findings``,
                ``high_findings``.

        Returns:
            Adaptive Card payload summarizing compliance posture.
        """
        overall = posture_summary.get("overall_score", 0)
        frameworks = posture_summary.get("frameworks", [])
        timestamp = posture_summary.get("timestamp", "N/A")
        critical = posture_summary.get("critical_findings", 0)
        high = posture_summary.get("high_findings", 0)

        # Color based on overall score
        if overall >= 80:
            score_color = "good"
        elif overall >= 60:
            score_color = "warning"
        else:
            score_color = "attention"

        framework_facts = []
        for fw in frameworks[:10]:  # limit to top 10
            name = fw.get("name", "Unknown")
            score = fw.get("score", 0)
            total = fw.get("total_controls", 0)
            compliant = fw.get("compliant_controls", 0)
            framework_facts.append(
                {"title": name, "value": f"{score}% ({compliant}/{total} controls)"}
            )

        return {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "Container",
                    "style": score_color,
                    "items": [
                        {
                            "type": "TextBlock",
                            "text": f"Compliance Posture: {overall}%",
                            "weight": "Bolder",
                            "size": "Large",
                        },
                        {
                            "type": "TextBlock",
                            "text": f"As of {timestamp}",
                            "isSubtle": True,
                            "size": "Small",
                        },
                    ],
                },
                {
                    "type": "FactSet",
                    "facts": [
                        {"title": "Critical Findings", "value": str(critical)},
                        {"title": "High Findings", "value": str(high)},
                    ],
                },
                {
                    "type": "TextBlock",
                    "text": "Framework Scores",
                    "weight": "Bolder",
                    "separator": True,
                },
                {
                    "type": "FactSet",
                    "facts": framework_facts,
                },
            ],
            "actions": [
                {
                    "type": "Action.OpenUrl",
                    "title": "View Full Report",
                    "url": "https://warlock.local/posture",
                }
            ],
        }

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    @staticmethod
    def is_configured() -> bool:
        """Return True.

        Teams uses per-call webhook URLs, so there is no global
        configuration to validate.  Always considered available.
        """
        return True
