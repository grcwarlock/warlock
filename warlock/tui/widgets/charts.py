"""Plotext chart wrappers for Textual widgets."""

from __future__ import annotations

import plotext as plt
from textual.widgets import Static


class BarChart(Static):
    """Render a plotext bar chart inside a Textual widget."""

    def __init__(
        self,
        labels: list[str],
        values: list[float],
        title: str = "",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.chart_labels = labels
        self.chart_values = values
        self.chart_title = title

    def render(self) -> str:
        plt.clear_figure()
        plt.bar(self.chart_labels, self.chart_values)
        if self.chart_title:
            plt.title(self.chart_title)
        plt.theme("dark")
        width = max(self.size.width, 20)
        height = max(self.size.height - 1, 5)
        plt.plotsize(width, height)
        return plt.build()


class LineChart(Static):
    """Render a plotext line chart inside a Textual widget.

    Useful for posture trends, loss exceedance curves, etc.
    """

    def __init__(
        self,
        x: list[float],
        y: list[float],
        title: str = "",
        x_label: str = "",
        y_label: str = "",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.chart_x = x
        self.chart_y = y
        self.chart_title = title
        self.chart_x_label = x_label
        self.chart_y_label = y_label

    def render(self) -> str:
        plt.clear_figure()
        plt.plot(self.chart_x, self.chart_y)
        if self.chart_title:
            plt.title(self.chart_title)
        if self.chart_x_label:
            plt.xlabel(self.chart_x_label)
        if self.chart_y_label:
            plt.ylabel(self.chart_y_label)
        plt.theme("dark")
        width = max(self.size.width, 20)
        height = max(self.size.height - 1, 5)
        plt.plotsize(width, height)
        return plt.build()


class ProgressMetric(Static):
    """Big number with label and color-coded progress bar.

    Displays like: "87.3% Compliant" with a colored progress bar underneath.
    """

    DEFAULT_CSS = """
    ProgressMetric {
        height: 3;
        padding: 0 1;
    }
    """

    def __init__(
        self,
        value: float,
        label: str = "",
        bar_width: int = 30,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.metric_value = max(0.0, min(value, 100.0))
        self.metric_label = label
        self.bar_width = bar_width

    def render(self) -> str:
        pct = self.metric_value
        if pct >= 80:
            color = "green"
        elif pct >= 60:
            color = "yellow"
        else:
            color = "red"

        filled = int(self.bar_width * pct / 100)
        empty = self.bar_width - filled
        bar = f"[{color}]{'#' * filled}[/{color}][dim]{'.' * empty}[/dim]"
        return f"[bold {color}]{pct:5.1f}%[/bold {color}] {self.metric_label}\n{bar}"
