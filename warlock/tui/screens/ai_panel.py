"""AI Reasoning Panel — simple chat interface.

Type a question, get an answer grounded in your compliance data.
No entity selection needed — the AI searches across everything.

Examples:
  "What are my biggest risks in AWS?"
  "How do I fix AC-2?"
  "Show me non-compliant controls in SOC 2"
  "What's the remediation for SC-28?"
  "Summarize my compliance posture"
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.widgets import Button, Input, Label, Markdown, Static

log = logging.getLogger(__name__)


class AIPanelScreen(VerticalScroll):
    """Simple chat interface — type a question, get an AI-powered answer."""

    DEFAULT_CSS = """
    AIPanelScreen {
        padding: 1 2;
    }
    #ai-status-bar {
        height: 1;
        margin-bottom: 1;
        color: $text-muted;
    }
    #chat-history {
        min-height: 10;
        max-height: 80vh;
        border: solid $surface-lighten-2;
        padding: 1;
        margin-bottom: 1;
    }
    .user-msg {
        color: $text;
        margin: 0 0 1 4;
    }
    .ai-msg {
        margin: 0 4 1 0;
    }
    .system-msg {
        color: $text-muted;
        text-align: center;
        margin: 1 0;
    }
    #quick-actions {
        height: 3;
        margin-bottom: 1;
    }
    #quick-actions Button {
        margin-right: 1;
    }
    #input-row {
        height: 3;
    }
    #chat-input {
        width: 1fr;
    }
    #send-btn {
        width: 10;
    }
    #setup-guide {
        padding: 2 4;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._ai_available = False
        self._session_id = None
        self._messages: list[dict] = []

    def compose(self) -> ComposeResult:
        yield Static("", id="ai-status-bar")

        # Chat interface (hidden until AI is confirmed available)
        with Vertical(id="chat-area"):
            yield VerticalScroll(
                Static("[dim]Ask anything about your compliance data.[/dim]", classes="system-msg"),
                id="chat-history",
            )
            with Vertical(id="quick-actions"):
                yield Label("[dim]Quick questions:[/dim]")
                with Vertical():
                    yield Button("What are my top risks?", id="q-risks", variant="default")
                    yield Button("Show non-compliant controls", id="q-noncomp", variant="default")
                    yield Button("Summarize compliance posture", id="q-posture", variant="default")
                    yield Button(
                        "What needs remediation first?", id="q-remediate", variant="default"
                    )
            with Vertical(id="input-row"):
                yield Input(placeholder="Ask a question...", id="chat-input")
                yield Button("Send", variant="primary", id="send-btn")

        # Setup guide (shown when AI is not configured)
        yield Vertical(
            Label(
                "[bold]AI Reasoning[/bold]\n\n"
                "AI is not configured. To enable:\n\n"
                "  1. Run the demo with AI:  [bold]./scripts/demo.sh[/bold]  (select a provider)\n"
                "  2. Or set env vars:\n"
                "     [dim]export WLK_AI_PROVIDER=anthropic[/dim]\n"
                "     [dim]export WLK_AI_API_KEY=your-key[/dim]\n"
                "     [dim]export WLK_AI_MODEL=claude-sonnet-4-20250514[/dim]\n"
                "     [dim]export WLK_AI_ENABLED=true[/dim]\n\n"
                "Supported: Anthropic, OpenAI, Ollama, Gemini",
            ),
            id="setup-guide",
        )

    def on_mount(self) -> None:
        self._check_ai_status()

    def _check_ai_status(self) -> None:
        status_bar = self.query_one("#ai-status-bar", Static)
        try:
            from warlock.ai.service import get_ai_service

            svc = get_ai_service()
            if svc.is_available():
                self._ai_available = True
                provider = getattr(svc, "_provider", "unknown")
                model = getattr(svc, "_model", "unknown")
                status_bar.update(
                    f"[green bold]AI Enabled[/]  |  Provider: {provider}  |  Model: {model}"
                )
                self.query_one("#setup-guide").display = False
                self.query_one("#chat-area").display = True
            else:
                self._show_setup()
        except Exception:
            self._show_setup()

    def _show_setup(self) -> None:
        status_bar = self.query_one("#ai-status-bar", Static)
        status_bar.update("[yellow]AI Not Configured[/]")
        self.query_one("#chat-area").display = False
        self.query_one("#setup-guide").display = True

    # ------------------------------------------------------------------
    # Input handling
    # ------------------------------------------------------------------

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "chat-input" and event.value.strip():
            self._send_message(event.value.strip())
            event.input.value = ""

    def on_button_pressed(self, event: Button.Pressed) -> None:
        quick_questions = {
            "q-risks": "What are my top 5 risks across all frameworks? Include dollar amounts if available.",
            "q-noncomp": "Show me all non-compliant controls grouped by framework with severity.",
            "q-posture": "Give me an executive summary of my compliance posture across all 14 frameworks.",
            "q-remediate": "What should I remediate first? Prioritize by risk impact and effort.",
        }
        question = quick_questions.get(event.button.id)
        if question:
            self._send_message(question)
        elif event.button.id == "send-btn":
            chat_input = self.query_one("#chat-input", Input)
            if chat_input.value.strip():
                self._send_message(chat_input.value.strip())
                chat_input.value = ""

    def _send_message(self, message: str) -> None:
        if not self._ai_available:
            return

        # Add user message to chat
        history = self.query_one("#chat-history", VerticalScroll)
        history.mount(Static(f"[bold]You:[/bold] {message}", classes="user-msg"))

        # Add thinking indicator
        thinking = Static("[dim italic]Thinking...[/dim italic]", id="thinking-indicator")
        history.mount(thinking)
        history.scroll_end()

        # Send to AI in background
        self._call_ai(message)

    @work(thread=True)
    def _call_ai(self, message: str) -> None:
        """Send message to AI with full compliance context."""
        try:
            context = self._build_context(message)

            from warlock.ai.service import get_ai_service
            from warlock.ai.types import ConversationContext

            svc = get_ai_service()

            if self._session_id is None:
                import uuid

                self._session_id = str(uuid.uuid4())

            conv_context = ConversationContext(
                entity_type="search",
                entity_id="all",
                entity_data=context,
                related_controls=[],
                related_findings=[],
                compliance_context={},
                messages=self._messages,
                session_id=self._session_id,
                created_at=datetime.now(timezone.utc),
                last_activity=datetime.now(timezone.utc),
            )

            result = svc.converse(
                session_id=self._session_id,
                message=message,
                context=conv_context,
            )

            if result.ai_used:
                response = result.value if isinstance(result.value, str) else str(result.value)
                self._messages.append({"role": "user", "content": message})
                self._messages.append({"role": "assistant", "content": response})
            else:
                response = f"AI unavailable: {result.fallback_reason or 'unknown reason'}"

            self.app.call_from_thread(self._display_response, response, result.ai_used)

        except Exception as exc:
            log.debug("AI call failed: %s", exc, exc_info=True)
            self.app.call_from_thread(
                self._display_response,
                f"Error: {exc.__class__.__name__}: {exc}",
                False,
            )

    def _display_response(self, response: str, ai_used: bool) -> None:
        """Display AI response in the chat history."""
        history = self.query_one("#chat-history", VerticalScroll)

        # Remove thinking indicator
        try:
            thinking = self.query_one("#thinking-indicator")
            thinking.remove()
        except Exception:
            pass

        # Add response
        if ai_used:
            history.mount(Markdown(f"**AI:** {response}", classes="ai-msg"))
        else:
            history.mount(Static(f"[yellow]{response}[/yellow]", classes="system-msg"))

        history.scroll_end()

    def _build_context(self, message: str) -> dict:
        """Build compliance context by searching the DB based on the user's question."""
        from warlock.db.engine import get_session, init_db
        from warlock.db.models import ControlResult, Finding, Issue, POAM, RiskAnalysis
        from sqlalchemy import func, desc

        init_db()
        context = {}

        try:
            with get_session() as session:
                # Framework coverage summary
                coverage_rows = (
                    session.query(
                        ControlResult.framework,
                        func.count().label("total"),
                        func.sum(func.cast(ControlResult.status == "compliant", type_=None)).label(
                            "compliant"
                        ),
                        func.sum(
                            func.cast(ControlResult.status == "non_compliant", type_=None)
                        ).label("non_compliant"),
                    )
                    .group_by(ControlResult.framework)
                    .all()
                )
                context["coverage"] = [
                    {
                        "framework": r.framework,
                        "total": r.total,
                        "compliant": int(r.compliant or 0),
                        "non_compliant": int(r.non_compliant or 0),
                        "rate": round(int(r.compliant or 0) / r.total * 100, 1) if r.total else 0,
                    }
                    for r in coverage_rows
                ]

                # Top findings by severity
                top_findings = (
                    session.query(Finding).order_by(desc(Finding.severity)).limit(20).all()
                )
                context["top_findings"] = [
                    {
                        "severity": f.severity,
                        "source": f.source,
                        "title": f.title[:100] if hasattr(f, "title") else f.observation_type,
                        "resource": f.resource_id,
                        "control_ids": f.control_id if hasattr(f, "control_id") else "",
                    }
                    for f in top_findings
                ]

                # Open issues summary
                open_issues = (
                    session.query(func.count(Issue.id))
                    .filter(Issue.status.in_(["open", "in_progress"]))
                    .scalar()
                )
                critical_issues = (
                    session.query(func.count(Issue.id))
                    .filter(Issue.status.in_(["open", "in_progress"]), Issue.priority == "critical")
                    .scalar()
                )
                context["issues"] = {"open": open_issues or 0, "critical": critical_issues or 0}

                # Overdue POA&Ms
                overdue_poams = (
                    session.query(func.count(POAM.id))
                    .filter(
                        POAM.status.in_(["open", "in_progress"]),
                        POAM.scheduled_completion < datetime.now(timezone.utc),
                    )
                    .scalar()
                )
                context["overdue_poams"] = overdue_poams or 0

                # Latest risk analysis
                latest_risk = (
                    session.query(RiskAnalysis).order_by(desc(RiskAnalysis.created_at)).first()
                )
                if latest_risk and latest_risk.details:
                    portfolio = latest_risk.details.get("portfolio_result", {})
                    context["risk"] = {
                        "framework": latest_risk.framework,
                        "total_mean_ale": portfolio.get("total_mean_ale"),
                        "total_var_95": portfolio.get("total_var_95"),
                    }

                # Non-compliant control sample (for remediation questions)
                non_compliant = (
                    session.query(ControlResult)
                    .filter(ControlResult.status == "non_compliant")
                    .limit(30)
                    .all()
                )
                context["non_compliant_controls"] = [
                    {
                        "framework": r.framework,
                        "control_id": r.control_id,
                        "severity": r.severity,
                        "remediation_summary": r.remediation_summary[:200]
                        if r.remediation_summary
                        else None,
                    }
                    for r in non_compliant
                ]

        except Exception as exc:
            log.debug("Context build failed: %s", exc)
            context["error"] = str(exc)

        # Truncate for prompt size
        context_str = json.dumps(context, default=str)
        if len(context_str) > 8000:
            context["top_findings"] = context["top_findings"][:10]
            context["non_compliant_controls"] = context["non_compliant_controls"][:15]

        return context
