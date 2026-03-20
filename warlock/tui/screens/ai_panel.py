"""Interactive AI reasoning panel.

Chat-style interface for conversing with the AI about GRC entities --
findings, issues, POA&Ms, and controls. Supports quick-action buttons
and displays entity context alongside the conversation.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Any

from textual import work
from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    Markdown,
    Select,
    Static,
)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Entity types the user can reason about
# ---------------------------------------------------------------------------

_ENTITY_TYPES = [
    ("Finding", "finding"),
    ("Issue", "issue"),
    ("POA&M", "poam"),
    ("Control", "control"),
]

# Quick action prompts
_QUICK_ACTIONS = [
    ("Why is this non-compliant?", "why_noncompliant"),
    ("How do I fix this?", "how_to_fix"),
    ("What's the business impact?", "business_impact"),
    ("Generate remediation plan", "remediation_plan"),
]

_QUICK_ACTION_PROMPTS: dict[str, str] = {
    "why_noncompliant": (
        "Analyze this entity and explain why it is non-compliant. "
        "Reference the specific control requirements that are not being met."
    ),
    "how_to_fix": (
        "Provide step-by-step remediation guidance for this entity. "
        "Include specific technical actions and configuration changes needed."
    ),
    "business_impact": (
        "Assess the business impact of this entity's current state. "
        "Consider financial, operational, reputational, and regulatory risks."
    ),
    "remediation_plan": (
        "Generate a detailed remediation plan for this entity. Include: "
        "1) Immediate actions (24-48h), 2) Short-term fixes (1-2 weeks), "
        "3) Long-term improvements (1-3 months), with responsible roles and "
        "estimated effort for each."
    ),
}


# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

AI_PANEL_CSS = """\
#ai-screen {
    layout: horizontal;
}

#conversation-column {
    width: 2fr;
    layout: vertical;
}

#context-column {
    width: 1fr;
    border-left: solid $accent;
    padding: 1;
}

#status-bar {
    height: 3;
    padding: 0 2;
    border-bottom: solid $accent;
    content-align: left middle;
}

#entity-selector {
    height: 5;
    padding: 0 2;
}

#entity-selector Select {
    width: 30;
    margin-right: 1;
}

#entity-selector Input {
    width: 40;
}

#chat-area {
    height: 1fr;
    padding: 1 2;
    overflow-y: auto;
}

.user-message {
    text-align: right;
    margin: 1 0 1 10;
    padding: 1 2;
    background: $primary-darken-2;
    border: round $primary;
}

.ai-message {
    margin: 1 10 1 0;
    padding: 1 2;
    background: $surface;
    border: round $accent;
}

.system-message {
    text-align: center;
    color: $text-muted;
    margin: 1 4;
}

#input-bar {
    height: 5;
    padding: 1 2;
    border-top: solid $accent;
}

#input-bar Input {
    width: 1fr;
    margin-right: 1;
}

#quick-actions {
    height: auto;
    padding: 0 2 1 2;
}

#quick-actions Button {
    margin-right: 1;
    min-width: 20;
}

#context-panel {
    height: 1fr;
}

#setup-guide {
    padding: 4;
    text-align: center;
}

#no-entity-label {
    text-align: center;
    padding: 4;
    color: $text-muted;
}
"""


# ---------------------------------------------------------------------------
# Screen
# ---------------------------------------------------------------------------


class AIPanelScreen(Screen):
    """Interactive AI reasoning interface."""

    CSS = AI_PANEL_CSS
    BINDINGS = [
        ("escape", "app.pop_screen", "Back"),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._session_id: str = str(uuid.uuid4())
        self._entity_type: str = ""
        self._entity_id: str = ""
        self._entity_data: dict[str, Any] = {}
        self._ai_available: bool = False
        self._messages: list[dict[str, str]] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with Container(id="ai-screen"):
            # Left column: conversation
            with Vertical(id="conversation-column"):
                # Status bar
                yield Static("", id="status-bar")

                # Entity selector
                with Horizontal(id="entity-selector"):
                    yield Select(
                        _ENTITY_TYPES,
                        prompt="Entity type",
                        id="entity-type-select",
                    )
                    yield Input(
                        placeholder="Entity ID (e.g., finding UUID)",
                        id="entity-id-input",
                    )
                    yield Button("Load", variant="primary", id="load-entity-btn")

                # Quick action buttons
                with Horizontal(id="quick-actions"):
                    for label, action_id in _QUICK_ACTIONS:
                        yield Button(label, id=f"qa-{action_id}", variant="default")

                # Chat area
                yield VerticalScroll(id="chat-area")

                # Input bar
                with Horizontal(id="input-bar"):
                    yield Input(
                        placeholder="Ask a question about this entity...",
                        id="chat-input",
                    )
                    yield Button("Send", variant="primary", id="send-btn")

            # Right column: entity context
            with Vertical(id="context-column"):
                yield Label("[bold]Entity Context[/bold]")
                yield VerticalScroll(
                    Markdown("*Select an entity to view its context.*", id="context-md"),
                    id="context-panel",
                )

        # Setup guide (shown when AI is not configured)
        yield Container(
            Label(
                "[bold]AI Reasoning Not Configured[/bold]\n\n"
                "Run [bold]warlock ai configure[/bold] to enable AI reasoning.\n\n"
                "Supported providers: OpenAI, Anthropic, Google Gemini, Ollama.\n\n"
                "Once configured, you can ask the AI about any finding, issue, "
                "POA&M, or control in your GRC data.",
                id="setup-guide-text",
            ),
            id="setup-guide",
        )
        yield Footer()

    def on_mount(self) -> None:
        self._check_ai_status()

    # ------------------------------------------------------------------
    # AI availability check
    # ------------------------------------------------------------------

    def _check_ai_status(self) -> None:
        """Check whether AI is configured and update the status bar."""
        status_bar = self.query_one("#status-bar", Static)

        try:
            from warlock.ai.service import get_ai_service

            svc = get_ai_service()
            if svc.provider is not None:
                self._ai_available = True
                provider_name = getattr(svc.provider, "name", "unknown")
                model_name = getattr(svc.provider, "model", "unknown")
                status_bar.update(
                    f"[green bold]AI Enabled[/]  |  "
                    f"Provider: {provider_name}  |  "
                    f"Model: {model_name}"
                )
                self.query_one("#setup-guide").display = False
                self.query_one("#ai-screen").display = True
            else:
                self._show_setup_guide(status_bar)
        except Exception:
            self._show_setup_guide(status_bar)

    def _show_setup_guide(self, status_bar: Static) -> None:
        status_bar.update("[red bold]AI Disabled[/]  |  Run 'warlock ai configure' to enable")
        self._ai_available = False
        self.query_one("#setup-guide").display = True
        self.query_one("#ai-screen").display = False

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id or ""

        if btn_id == "send-btn":
            self._send_message()
        elif btn_id == "load-entity-btn":
            self._load_entity()
        elif btn_id.startswith("qa-"):
            action_key = btn_id[3:]  # strip "qa-" prefix
            prompt = _QUICK_ACTION_PROMPTS.get(action_key, "")
            if prompt:
                self._send_user_message(prompt)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "chat-input":
            self._send_message()
        elif event.input.id == "entity-id-input":
            self._load_entity()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "entity-type-select" and event.value is not Select.BLANK:
            self._entity_type = str(event.value)

    # ------------------------------------------------------------------
    # Entity loading
    # ------------------------------------------------------------------

    def _load_entity(self) -> None:
        """Load the selected entity from the DB and display its context."""
        entity_type_select = self.query_one("#entity-type-select", Select)
        entity_id_input = self.query_one("#entity-id-input", Input)

        if entity_type_select.value is Select.BLANK:
            self.notify("Select an entity type first.", severity="warning")
            return

        self._entity_type = str(entity_type_select.value)
        self._entity_id = entity_id_input.value.strip()

        if not self._entity_id:
            self.notify("Enter an entity ID.", severity="warning")
            return

        self._load_entity_worker(self._entity_type, self._entity_id)

    @work(thread=True, exclusive=True, group="entity-load")
    def _load_entity_worker(self, entity_type: str, entity_id: str) -> None:
        """Fetch entity data from the DB in a background thread."""
        try:
            from warlock.db.engine import get_session

            session_gen = get_session()
            session = next(session_gen)
            try:
                entity_data = self._fetch_entity(session, entity_type, entity_id)
                if entity_data:
                    self._entity_data = entity_data
                    self.call_from_thread(self._display_context, entity_data)
                    self.call_from_thread(
                        self._add_system_message,
                        f"Loaded {entity_type} {entity_id[:8]}... Ready for questions.",
                    )
                    # Start a fresh conversation session for this entity
                    self._session_id = str(uuid.uuid4())
                    self._messages.clear()
                else:
                    self.call_from_thread(
                        self.notify,
                        f"{entity_type} '{entity_id}' not found.",
                        severity="warning",
                    )
            finally:
                try:
                    next(session_gen)
                except StopIteration:
                    pass
        except Exception as exc:
            log.exception("Failed to load entity")
            self.call_from_thread(self.notify, f"Load failed: {exc}", severity="error")

    def _fetch_entity(
        self, session: Any, entity_type: str, entity_id: str
    ) -> dict[str, Any] | None:
        """Query the DB for the given entity and return a serializable dict."""
        from warlock.db import models

        model_map: dict[str, type] = {
            "finding": models.Finding,
            "control": models.ControlResult,
        }

        # Check for optional models that may exist
        if hasattr(models, "Issue"):
            model_map["issue"] = models.Issue
        if hasattr(models, "POAM"):
            model_map["poam"] = models.POAM
        elif hasattr(models, "Poam"):
            model_map["poam"] = models.Poam

        model_cls = model_map.get(entity_type)
        if model_cls is None:
            return None

        entity = session.get(model_cls, entity_id)
        if entity is None:
            # Try partial ID match
            entity = session.query(model_cls).filter(model_cls.id.like(f"{entity_id}%")).first()

        if entity is None:
            return None

        # Convert to dict -- use column inspection
        data: dict[str, Any] = {}
        for col in entity.__table__.columns:
            val = getattr(entity, col.name, None)
            if isinstance(val, datetime):
                val = val.isoformat()
            data[col.name] = val

        return data

    # ------------------------------------------------------------------
    # Conversation
    # ------------------------------------------------------------------

    def _send_message(self) -> None:
        """Send the current input as a user message."""
        chat_input = self.query_one("#chat-input", Input)
        message = chat_input.value.strip()
        if not message:
            return
        chat_input.value = ""
        self._send_user_message(message)

    def _send_user_message(self, message: str) -> None:
        """Add user message to chat and trigger AI response."""
        if not self._ai_available:
            self.notify(
                "AI not configured. Run 'warlock ai configure' first.",
                severity="warning",
            )
            return

        if not self._entity_id:
            self.notify("Load an entity first.", severity="warning")
            return

        self._add_user_bubble(message)
        self._messages.append({"role": "user", "content": message})
        self._get_ai_response_worker(message)

    @work(thread=True, exclusive=True, group="ai-response")
    def _get_ai_response_worker(self, message: str) -> None:
        """Call the AI service in a background thread."""
        self.call_from_thread(self._add_typing_indicator)

        try:
            from warlock.ai.service import get_ai_service
            from warlock.ai.types import ConversationContext

            svc = get_ai_service()
            context = ConversationContext(
                entity_type=self._entity_type,
                entity_id=self._entity_id,
                entity_data=self._entity_data,
            )

            result = svc.converse(
                session_id=self._session_id,
                message=message,
                context=context,
            )

            self.call_from_thread(self._remove_typing_indicator)

            if result.ai_used and result.value:
                response_text = str(result.value)
                self._messages.append({"role": "assistant", "content": response_text})
                latency = result.latency_ms
                model = result.model
                self.call_from_thread(
                    self._add_ai_bubble,
                    response_text,
                    f"{model} | {latency}ms",
                )
            else:
                reason = result.fallback_reason or "AI unavailable"
                self.call_from_thread(
                    self._add_system_message,
                    f"AI could not respond: {reason}",
                )
        except Exception as exc:
            log.exception("AI conversation failed")
            self.call_from_thread(self._remove_typing_indicator)
            self.call_from_thread(
                self._add_system_message,
                f"Error: {exc}",
            )

    # ------------------------------------------------------------------
    # Chat UI helpers (run on main thread)
    # ------------------------------------------------------------------

    def _add_user_bubble(self, text: str) -> None:
        """Add a user message bubble to the chat area."""
        chat = self.query_one("#chat-area", VerticalScroll)
        bubble = Static(f"[bold]You:[/bold] {text}", classes="user-message")
        chat.mount(bubble)
        bubble.scroll_visible()

    def _add_ai_bubble(self, text: str, meta: str = "") -> None:
        """Add an AI response bubble with markdown rendering."""
        chat = self.query_one("#chat-area", VerticalScroll)
        container = Vertical(classes="ai-message")
        chat.mount(container)
        md = Markdown(text)
        container.mount(md)
        if meta:
            container.mount(Static(f"[dim]{meta}[/dim]"))
        container.scroll_visible()

    def _add_system_message(self, text: str) -> None:
        """Add a system/info message to the chat area."""
        chat = self.query_one("#chat-area", VerticalScroll)
        msg = Static(f"[dim italic]{text}[/]", classes="system-message")
        chat.mount(msg)
        msg.scroll_visible()

    def _add_typing_indicator(self) -> None:
        """Show a typing indicator while waiting for AI."""
        chat = self.query_one("#chat-area", VerticalScroll)
        indicator = Static(
            "[dim italic]AI is thinking...[/]",
            classes="system-message",
            id="typing-indicator",
        )
        chat.mount(indicator)
        indicator.scroll_visible()

    def _remove_typing_indicator(self) -> None:
        """Remove the typing indicator."""
        try:
            indicator = self.query_one("#typing-indicator")
            indicator.remove()
        except Exception:
            pass

    def _display_context(self, data: dict[str, Any]) -> None:
        """Render entity data in the context panel."""
        md_parts: list[str] = [f"## {self._entity_type.title()}: `{self._entity_id[:12]}...`\n"]

        for key, value in data.items():
            if value is None:
                continue
            display_key = key.replace("_", " ").title()
            if isinstance(value, dict):
                md_parts.append(f"**{display_key}:**\n```json\n{_format_json(value)}\n```\n")
            elif isinstance(value, list):
                md_parts.append(f"**{display_key}:** {len(value)} items\n")
            elif isinstance(value, str) and len(value) > 100:
                md_parts.append(f"**{display_key}:**\n> {value[:200]}...\n")
            else:
                md_parts.append(f"**{display_key}:** {value}\n")

        md_text = "\n".join(md_parts)
        self.query_one("#context-md", Markdown).update(md_text)


def _format_json(data: Any) -> str:
    """Format a dict/list as indented JSON for display."""
    import json

    try:
        return json.dumps(data, indent=2, default=str)[:500]
    except Exception:
        return str(data)[:500]
