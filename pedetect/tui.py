# pedetect/tui.py
"""
Interactive Terminal User Interface (TUI) for the PE Obfuscation Detector.
Uses Textual framework for a multi-panel forensic dashboard.
"""
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, Label
from textual.reactive import reactive
from rich.text import Text
from rich.panel import Panel
from rich.table import Table as RichTable


class EntropyPanel(Static):
    """Displays section-level entropy as a spectral bar chart."""

    def __init__(self, section_entropy: list, **kwargs):
        super().__init__(**kwargs)
        self.section_entropy = section_entropy

    def compose(self) -> ComposeResult:
        yield Static(self._render_entropy())

    def _render_entropy(self) -> str:
        lines = []
        lines.append("[bold cyan]Section Entropy Analysis[/bold cyan]")
        lines.append("[dim]Scale: ░ 0-3  ▒ 3-5  ▓ 5-7  █ 7-8[/dim]")
        lines.append("")
        for sec in self.section_entropy:
            ent = sec['entropy']
            name = sec['name']
            if ent < 3:
                color = "green"
                char = "░"
            elif ent < 5:
                color = "blue"
                char = "▒"
            elif ent < 7:
                color = "yellow"
                char = "▓"
            else:
                color = "red"
                char = "█"
            bar_len = int(ent / 8 * 30)
            bar = char * bar_len
            lines.append(f"  {name:<15} [{color}]{bar:<30}[/{color}] {ent:.2f}")
        return "\n".join(lines)

    def render(self):
        return Text.from_markup(self._render_entropy())


class VerdictPanel(Static):
    """Displays the verdict with color-coded confidence."""

    def __init__(self, verdict: str, confidence: float, **kwargs):
        super().__init__(**kwargs)
        self.verdict = verdict
        self.confidence = confidence

    def render(self):
        color_map = {'CLEAN': 'green', 'SUSPICIOUS': 'yellow', 'PACKED': 'red', 'ERROR': 'dim'}
        color = color_map.get(self.verdict, 'white')
        text = Text()
        text.append("\n")
        text.append(f"  {self.verdict}\n", style=f"bold {color}")
        text.append(f"  Confidence: {self.confidence:.1%}\n", style=f"{color}")
        text.append("\n")
        return text


class EvidencePanel(Static):
    """Displays the evidence chain."""

    def __init__(self, evidence_chain: list, **kwargs):
        super().__init__(**kwargs)
        self.evidence_chain = evidence_chain

    def render(self):
        text = Text()
        text.append("Evidence Chain\n", style="bold cyan")
        text.append("─" * 50 + "\n", style="dim")
        for i, evidence in enumerate(self.evidence_chain[:15], 1):
            text.append(f"  ▸ ", style="red")
            text.append(f"{evidence}\n", style="white")
        if len(self.evidence_chain) > 15:
            text.append(f"\n  ... and {len(self.evidence_chain) - 15} more findings\n", style="dim")
        return text


class ScoringPanel(Static):
    """Displays the weighted scoring breakdown."""

    def __init__(self, heuristics: dict, total_weight: float, confidence: float, **kwargs):
        super().__init__(**kwargs)
        self.heuristics = heuristics
        self.total_weight = total_weight
        self.confidence = confidence

    def render(self):
        text = Text()
        text.append("Weighted Scoring Breakdown\n", style="bold cyan")
        text.append("─" * 50 + "\n", style="dim")
        text.append(f"  {'Heuristic':<20} {'Score':>6} {'Weight':>7} {'Contrib':>8}\n", style="bold dim")
        text.append("  " + "─" * 45 + "\n", style="dim")
        for name, info in self.heuristics.items():
            score = info['score']
            weight = info.get('weight', 0.5)
            contribution = score * weight
            display = name.replace('_', ' ').title()
            if contribution > 0.5:
                color = "red"
            elif contribution > 0.2:
                color = "yellow"
            else:
                color = "green"
            text.append(f"  {display:<20} ", style="white")
            text.append(f"{score:>5.2f} ", style="white")
            text.append(f"{weight:>6.1f} ", style="dim")
            text.append(f"{contribution:>7.3f}\n", style=color)
        text.append("  " + "─" * 45 + "\n", style="dim")
        text.append(f"  {'TOTAL':<20} ", style="bold")
        text.append(f"{'':>5} ", style="white")
        text.append(f"{self.total_weight:>6.1f} ", style="bold dim")
        text.append(f"{self.confidence:>7.4f}\n", style="bold")
        return text


class OverlayPanel(Static):
    """Displays overlay detection information."""

    def __init__(self, overlay: dict, **kwargs):
        super().__init__(**kwargs)
        self.overlay = overlay

    def render(self):
        text = Text()
        size = self.overlay.get('size', 0)
        entropy = self.overlay.get('entropy', 0.0)
        if size > 0:
            text.append("Overlay Detection\n", style="bold cyan")
            text.append("─" * 30 + "\n", style="dim")
            text.append(f"  Size: {size:,} bytes\n", style="yellow")
            text.append(f"  Entropy: {entropy:.2f}\n", style="yellow" if entropy > 6 else "green")
        else:
            text.append("Overlay: None detected\n", style="dim")
        return text


class FileInfoPanel(Static):
    """Displays file metadata."""

    def __init__(self, file_info: dict, **kwargs):
        super().__init__(**kwargs)
        self.file_info = file_info

    def render(self):
        text = Text()
        text.append("File Information\n", style="bold cyan")
        text.append("─" * 50 + "\n", style="dim")
        text.append(f"  Path:   {self.file_info['path']}\n", style="white")
        text.append(f"  MD5:    {self.file_info['md5']}\n", style="dim")
        text.append(f"  SHA256: {self.file_info['sha256']}\n", style="dim")
        text.append(f"  Size:   {self.file_info['size']:,} bytes\n", style="white")
        return text


class PEDetectTUI(App):
    """PE Obfuscation Detector - Interactive TUI Dashboard."""

    CSS = """
    Screen {
        layout: grid;
        grid-size: 2 3;
        grid-columns: 3fr 2fr;
        grid-rows: auto 1fr auto;
        grid-gutter: 1;
        background: $surface;
    }
    #header-panel {
        column-span: 2;
        height: 5;
        border: solid $accent;
        padding: 0 1;
    }
    #scoring-panel {
        border: solid $primary;
        padding: 1;
        height: 100%;
    }
    #right-top {
        layout: vertical;
        border: solid $primary;
        padding: 1;
    }
    #evidence-panel {
        border: solid $primary;
        padding: 1;
        column-span: 2;
        height: auto;
        max-height: 20;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "toggle_dark", "Toggle Dark Mode"),
    ]

    def __init__(self, result: dict, **kwargs):
        super().__init__(**kwargs)
        self.result = result

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="header-panel"):
            yield FileInfoPanel(self.result['file'])
        with Container(id="scoring-panel"):
            yield ScoringPanel(
                self.result['heuristics'],
                self.result.get('total_weight', 0),
                self.result['confidence']
            )
        with Vertical(id="right-top"):
            yield VerdictPanel(self.result['verdict'], self.result['confidence'])
            yield EntropyPanel(self.result.get('section_entropy', []))
            yield OverlayPanel(self.result.get('overlay', {}))
        with Container(id="evidence-panel"):
            yield EvidencePanel(self.result['evidence_chain'])
        yield Footer()

    def action_toggle_dark(self) -> None:
        self.dark = not self.dark


def launch_tui(result: dict):
    """Launch the TUI dashboard with analysis results."""
    app = PEDetectTUI(result)
    app.title = "PE Obfuscation Detector v0.3.0"
    app.sub_title = f"Verdict: {result['verdict']} ({result['confidence']:.1%})"
    app.run()
