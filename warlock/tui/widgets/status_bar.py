"""Status and metric display widgets for the Warlock TUI."""

from __future__ import annotations

from textual.widgets import Static


class MetricCard(Static):
    """Colored metric card: label + big number + subtitle.

    Used for: Total ALE, VaR-95, Open Issues, etc.
    """

    DEFAULT_CSS = """
    MetricCard {
        height: 4;
        padding: 0 1;
        border: solid $accent;
    }
    """

    def __init__(
        self,
        label: str,
        value: str,
        subtitle: str = "",
        color: str = "white",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.card_label = label
        self.card_value = value
        self.card_subtitle = subtitle
        self.card_color = color

    def render(self) -> str:
        lines = [
            f"[dim]{self.card_label}[/dim]",
            f"[bold {self.card_color}]{self.card_value}[/bold {self.card_color}]",
        ]
        if self.card_subtitle:
            lines.append(f"[dim]{self.card_subtitle}[/dim]")
        return "\n".join(lines)


class StatusIndicator(Static):
    """Green/yellow/red dot with label.

    Used for: connector status, AI status, pipeline status.
    """

    DEFAULT_CSS = """
    StatusIndicator {
        height: 1;
        padding: 0 1;
    }
    """

    # Map status names to colors and symbols
    STATUS_MAP = {
        "ok": ("green", "●"),
        "good": ("green", "●"),
        "up": ("green", "●"),
        "active": ("green", "●"),
        "connected": ("green", "●"),
        "warning": ("yellow", "●"),
        "degraded": ("yellow", "●"),
        "partial": ("yellow", "●"),
        "error": ("red", "●"),
        "down": ("red", "●"),
        "disconnected": ("red", "●"),
        "critical": ("red", "●"),
        "unknown": ("dim", "○"),
    }

    def __init__(
        self,
        label: str,
        status: str = "unknown",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.indicator_label = label
        self.indicator_status = status.lower()

    def render(self) -> str:
        color, symbol = self.STATUS_MAP.get(self.indicator_status, ("dim", "○"))
        return f"[{color}]{symbol}[/{color}] {self.indicator_label}"

    def update_status(self, status: str) -> None:
        """Change the status and refresh the widget."""
        self.indicator_status = status.lower()
        self.refresh()
