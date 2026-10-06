"""Render the first EvidenceForge Studio design review as standalone SVGs."""

from __future__ import annotations

from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BG = "#0b111c"
NAV = "#0e1826"
SURFACE = "#121f31"
SURFACE_2 = "#17283e"
LINE = "#2b4059"
TEXT = "#e9edf5"
MUTED = "#94a9be"
BLUE = "#7294f3"
MINT = "#72d9c4"


class Canvas:
    """Tiny SVG drawing helper for review mockups."""

    def __init__(self, title: str, active: str) -> None:
        self.parts: list[str] = [
            '<svg xmlns="http://www.w3.org/2000/svg" width="1440" height="900" '
            'viewBox="0 0 1440 900" role="img">',
            f"<title>{escape(title)}</title>",
            '<defs><linearGradient id="primary" x2="0" y2="1">'
            '<stop stop-color="#789bff"/><stop offset="1" stop-color="#5278e9"/>'
            "</linearGradient></defs>",
        ]
        self.rect(0, 0, 1440, 900, BG)
        self.rect(0, 0, 222, 900, NAV)
        self.rect(221, 0, 1, 900, "#223248")
        self.rect(222, 0, 1218, 59, "#0c1421")
        self.rect(222, 58, 1218, 1, "#223248")
        self.rect(18, 23, 34, 34, "#3d62b0", 9)
        self.label(35, 46, "≋", 25, "#c3d5ff", anchor="middle")
        self.label(63, 41, "EvidenceForge", 17, TEXT, weight=700)
        self.label(64, 58, "S T U D I O", 9, MINT, weight=700)
        self.rect(16, 86, 190, 34, "#17273a", 7)
        self.circle(29, 103, 4, MINT)
        self.label(40, 108, "Documents / EvidenceForge", 11, "#adbed0")
        for index, name in enumerate(("Scenarios", "Industry packs", "Org packs", "Job center")):
            y = 153 + index * 49 + (12 if index == 3 else 0)
            if name == active:
                self.rect(12, y - 23, 198, 40, "#233958", 8)
                self.rect(12, y - 23, 3, 40, "#80a7ff", 2)
            self.label(30, y + 3, ("◇", "▱", "▢", "◌")[index], 18, "#91b4ea")
            self.label(60, y + 2, name, 14, TEXT if name == active else "#a3b2c5", weight=600)
        self.label(31, 850, "⚙", 19, "#9db3cb")
        self.label(60, 850, "Settings", 14, TEXT if active == "Settings" else "#a3b2c5", weight=600)
        self.label(254, 38, title, 13, TEXT, weight=650)
        self.label(1300, 38, "●  Local service", 11, MINT)

    def rect(
        self,
        x: int,
        y: int,
        width: int,
        height: int,
        fill: str,
        radius: int = 0,
        stroke: str | None = None,
    ) -> None:
        edge = f' stroke="{stroke}"' if stroke else ""
        self.parts.append(
            f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
            f'rx="{radius}" fill="{fill}"{edge}/>'
        )

    def label(
        self,
        x: int,
        y: int,
        value: str,
        size: int = 14,
        fill: str = TEXT,
        weight: int = 400,
        anchor: str = "start",
    ) -> None:
        self.parts.append(
            f'<text x="{x}" y="{y}" fill="{fill}" font-size="{size}" '
            f'font-weight="{weight}" text-anchor="{anchor}" '
            'font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif">'
            f"{escape(value)}</text>"
        )

    def circle(self, x: int, y: int, radius: int, fill: str) -> None:
        self.parts.append(f'<circle cx="{x}" cy="{y}" r="{radius}" fill="{fill}"/>')

    def button(self, x: int, y: int, width: int, title: str, primary: bool = False) -> None:
        self.rect(x, y, width, 36, "url(#primary)" if primary else "#213650", 8, "#45648e")
        self.label(x + width // 2, y + 23, title, 12, TEXT, 650, "middle")

    def card(self, x: int, y: int, width: int, height: int, title: str) -> None:
        self.rect(x, y, width, height, SURFACE, 11, LINE)
        self.label(x + 19, y + 31, title, 17, TEXT, 680)

    def save(self, name: str) -> None:
        ROOT.mkdir(parents=True, exist_ok=True)
        (ROOT / name).write_text("\n".join([*self.parts, "</svg>"]), encoding="utf-8")


def library() -> None:
    view = Canvas("Scenarios", "Scenarios")
    view.label(258, 105, "YOUR WORKSPACE", 10, MINT, 750)
    view.label(258, 149, "Scenarios", 34, TEXT, 750)
    view.label(258, 176, "Find a scenario and pick up where you left off.", 14, MUTED)
    view.button(1230, 113, 169, "+  New scenario", True)
    view.rect(258, 207, 774, 43, "#142237", 9, "#37516f")
    view.label(275, 234, "⌕", 22, "#849cb7")
    view.label(306, 234, "Search names, descriptions, users, hosts, YAML…", 13, "#7189a2")
    view.button(1044, 211, 99, "☷  Filters")
    view.button(1153, 211, 122, "Saved views")
    view.label(1298, 237, "6 scenarios", 12, MUTED)
    view.card(258, 276, 205, 560, "Projects")
    for index, (name, count) in enumerate(
        (("All scenarios", "6"), ("Healthcare", "3"), ("Branch office", "2"), ("Research", "1"))
    ):
        y = 319 + index * 46
        if index == 1:
            view.rect(270, y - 22, 181, 37, "#253d5d", 7)
        view.label(282, y + 2, "▢", 15, "#91aee0")
        view.label(307, y + 2, name, 12, TEXT if index == 1 else MUTED, 600)
        view.label(430, y + 2, count, 11, "#8399b0", anchor="end")
    view.label(282, 536, "+  New folder", 12, "#8eb4ff", 650)
    examples = [
        (
            "Healthcare breach",
            "Credential access across clinical and IT hosts",
            "12 users   ·   18 systems   ·   Validated",
            484,
            276,
        ),
        (
            "Branch office intrusion",
            "Remote access and lateral movement exercise",
            "8 users   ·   11 systems   ·   2 runs",
            949,
            276,
        ),
        (
            "APT healthcare campaign",
            "Multi-stage investigation with patient data",
            "18 users   ·   24 systems   ·   Draft",
            484,
            458,
        ),
        (
            "Insider exfiltration",
            "Finance team activity and false leads",
            "6 users   ·   9 systems   ·   1 run",
            949,
            458,
        ),
    ]
    for title, detail, status, x, y in examples:
        view.card(x, y, 443, 163, title)
        view.rect(x + 20, y + 50, 34, 34, "#243d60", 8)
        view.label(x + 37, y + 73, "◇", 19, "#a7c4ff", anchor="middle")
        view.label(x + 21, y + 109, detail, 12, MUTED)
        view.label(x + 21, y + 137, status, 11, "#7f9ab4")
        view.label(x + 414, y + 29, "↗", 19, "#839dbc")
    view.save("01-library.svg")


def workspace() -> None:
    view = Canvas("Scenario workspace", "Scenarios")
    view.label(258, 95, "SCENARIOS  /  HEALTHCARE BREACH", 11, MINT, 750)
    view.label(258, 143, "Healthcare breach", 32, TEXT, 750)
    view.label(
        258,
        172,
        "Credential access across clinical and IT hosts with an 8-hour investigation window.",
        14,
        MUTED,
    )
    for index, chip in enumerate(
        ("Scenario 2.0", "12 users", "18 systems", "46 events", "Updated today")
    ):
        x = (258, 372, 463, 562, 666)[index]
        width = (104, 80, 91, 92, 113)[index]
        view.rect(x, 190, width, 28, "#172940", 6, "#2d4866")
        view.label(x + width // 2, 208, chip, 11, "#b5cce3", 500, "middle")
    view.button(1102, 132, 111, "✓  Validate")
    view.button(1224, 132, 176, "+  Conversation", True)
    view.rect(242, 245, 1198, 1, LINE)
    for label, x, selected in (
        ("Overview", 259, True),
        ("Conversations  3", 379, False),
        ("Validation", 559, False),
        ("Runs  2", 696, False),
    ):
        view.label(x, 234, label, 13, TEXT if selected else MUTED, 630)
        if selected:
            view.rect(x, 243, 70, 3, BLUE, 2)
    view.card(258, 277, 550, 211, "Continue work")
    view.label(278, 325, "MOST RECENT CONVERSATION", 10, "#82a0bd", 700)
    view.rect(278, 344, 510, 89, "#1b304b", 8, "#3b5777")
    view.label(297, 376, "Investigate credential timeline", 15, TEXT, 650)
    view.label(297, 399, "Last worked on today at 10:42 AM", 11, MUTED)
    view.label(758, 391, "↗", 19, "#98baff")
    view.card(827, 277, 573, 211, "Validation")
    view.rect(847, 330, 533, 63, "#193c3d", 8, "#3a7064")
    view.label(866, 358, "●  Valid with 3 warnings", 15, "#9be9d0", 670)
    view.label(866, 380, "Resource forecast: 218 MiB peak · 45 MiB output", 11, "#b1c9cb")
    view.button(847, 424, 136, "View findings")
    view.card(258, 507, 550, 253, "Source and environment")
    view.label(278, 558, "scenario.yaml", 13, "#b6c9dc", 620)
    view.label(278, 585, "Industry pack: Healthcare 1.2.0", 12, MUTED)
    view.label(278, 610, "Org pack: Bayview Hospital 1.0.0", 12, MUTED)
    view.button(278, 691, 124, "Open YAML")
    view.card(827, 507, 573, 253, "Recent runs")
    view.label(848, 559, "Today, 10:16 AM", 13, TEXT, 610)
    view.label(1253, 559, "Evaluated  ·  92", 11, MINT)
    view.rect(847, 579, 533, 1, LINE)
    view.label(848, 607, "Yesterday, 3:41 PM", 13, TEXT, 610)
    view.label(1253, 607, "Completed", 11, MUTED)
    view.button(847, 689, 112, "View runs")
    view.save("02-workspace.svg")


def conversation() -> None:
    view = Canvas("Conversation", "Scenarios")
    view.label(258, 94, "SCENARIOS  /  HEALTHCARE BREACH", 11, MINT, 750)
    view.label(258, 137, "Healthcare breach", 29, TEXT, 750)
    view.label(258, 162, "Conversation history stays with the scenario.", 13, MUTED)
    view.rect(222, 190, 1218, 1, LINE)
    view.rect(222, 190, 239, 710, "#101b2b")
    view.rect(460, 190, 1, 710, LINE)
    view.label(242, 220, "CONVERSATIONS", 10, MUTED, 760)
    view.button(410, 201, 32, "+")
    for index, (title, when) in enumerate(
        (
            ("Investigate credential timeline", "Active now"),
            ("Revise host roles", "Yesterday"),
            ("Initial scenario design", "Sep 27"),
        )
    ):
        y = 246 + index * 67
        if index == 0:
            view.rect(232, y - 21, 219, 56, "#203650", 8, "#3a5878")
        view.label(247, y + 2, title, 12, TEXT if index == 0 else MUTED, 630)
        view.label(247, y + 21, when, 10, MINT if index == 0 else "#768fa9")
    view.label(491, 222, "Investigate credential timeline", 15, TEXT, 680)
    view.label(492, 241, "Healthcare breach", 11, MUTED)
    view.rect(1040, 203, 177, 34, "#1b2d43", 6, "#3a5571")
    view.label(1128, 225, "GPT-6 Sol  ⌄", 12, TEXT, 570, "middle")
    view.rect(1227, 203, 178, 34, "#1b2d43", 6, "#3a5571")
    view.label(1316, 225, "Medium  ⌄", 12, TEXT, 570, "middle")
    view.rect(461, 256, 979, 1, LINE)
    view.rect(913, 300, 478, 71, "#244066", 13, "#4b6ca3")
    view.label(932, 324, "YOU", 10, "#a7c6ff", 750)
    view.label(932, 350, "Check whether the service account timeline is plausible.", 13, TEXT)
    view.rect(492, 402, 624, 110, SURFACE_2, 13, "#35516f")
    view.label(512, 426, "CODEX", 10, MINT, 750)
    view.label(512, 452, "The authentication sequence is plausible, but the", 13, TEXT)
    view.label(512, 474, "first Kerberos event predates the host startup. I can", 13, TEXT)
    view.label(512, 496, "revise that timestamp and revalidate the scenario.", 13, TEXT)
    view.rect(492, 534, 220, 32, "#18283b", 7, "#304a66")
    view.label(507, 555, "⌄  4 activities · view details", 11, "#9ab2c8")
    view.rect(491, 703, 916, 132, "#18283b", 12, "#466181")
    view.label(512, 735, "Ask about this scenario…", 13, "#8297ac")
    view.rect(507, 781, 151, 29, "#203650", 6, "#375679")
    view.label(583, 800, "Automatic skill  ⌄", 11, "#aac0da", anchor="middle")
    view.label(678, 800, "Enter to send  ·  Shift+Enter for a new line", 10, MUTED)
    view.button(1357, 781, 33, "↑", True)
    view.save("03-conversation.svg")


def jobs() -> None:
    view = Canvas("Job center", "Job center")
    view.label(258, 105, "ALL OPERATIONS", 10, MINT, 750)
    view.label(258, 149, "Job center", 34, TEXT, 750)
    view.label(258, 176, "Track every generation and evaluation in your workspace.", 14, MUTED)
    view.button(1215, 128, 184, "▶  Resume paused jobs")
    for index, (count, label) in enumerate((("2", "Running"), ("1", "Queued"), ("8", "Completed"))):
        x = 258 + index * 129
        view.rect(x, 208, 116, 69, "#142238", 9, LINE)
        view.label(x + 18, 239, count, 23, TEXT, 700)
        view.label(x + 18, 260, label, 11, MUTED)
    for x, title, percent, hour in (
        (258, "Healthcare breach", 63, "5 of 8 simulated hours"),
        (835, "Branch office intrusion", 25, "2 of 8 simulated hours"),
    ):
        view.card(x, 307, 555, 256, title)
        view.label(x + 20, 360, "GENERATION  ·  RUNNING", 11, "#98c8ff", 680)
        view.label(x + 20, 394, hour, 13, TEXT, 600)
        view.label(x + 530, 394, f"{percent}%", 12, "#bdd2f1", 650, "end")
        view.rect(x + 20, 408, 514, 12, "#2a3e57", 7)
        view.rect(x + 20, 408, 514 * percent // 100, 12, BLUE, 7)
        view.label(x + 20, 448, "Rendering coordinated evidence · checkpoint enabled", 11, MUTED)
        view.rect(x + 20, 473, 514, 1, LINE)
        view.button(x + 20, 492, 132, "Open bundle")
        view.button(x + 161, 492, 91, "Suspend")
    view.card(258, 585, 1132, 150, "Queued · Insider exfiltration")
    view.label(278, 637, "Waiting for an available worker", 13, MUTED)
    view.label(278, 696, "Each job keeps its own progress, log, and bundle path.", 11, "#7895b0")
    view.save("04-job-center.svg")


def settings() -> None:
    view = Canvas("Settings", "Settings")
    view.label(258, 105, "PREFERENCES", 10, MINT, 750)
    view.label(258, 149, "Settings", 34, TEXT, 750)
    view.label(258, 176, "Compact controls, grouped by task.", 14, MUTED)
    view.rect(258, 209, 191, 583, SURFACE, 10, LINE)
    for index, name in enumerate(("Workspace", "Jobs", "Authoring & tools")):
        y = 249 + index * 48
        if name == "Jobs":
            view.rect(270, y - 25, 167, 39, "#233958", 7, "#365474")
        view.label(284, y, name, 13, TEXT if name == "Jobs" else MUTED, 630)
    view.rect(469, 209, 930, 583, SURFACE, 10, LINE)
    view.label(496, 252, "When I quit", 20, TEXT, 700)
    view.label(496, 275, "These choices apply the next time you close the window.", 12, MUTED)
    view.rect(495, 297, 879, 1, LINE)
    rows = (
        ("Generation and evaluation jobs", "Continue in background  ⌄"),
        ("Start queued generations", "☑"),
        ("Evaluations", "Continue  ⌄"),
        ("Authoring turns", "Stop active turns  ⌄"),
    )
    for index, (name, control) in enumerate(rows):
        y = 332 + index * 73
        view.label(496, y + 12, name, 13, TEXT, 600)
        view.circle(
            768 if index == 0 else 671 if index == 1 else 570 if index == 2 else 609,
            y + 7,
            8,
            "#263c59",
        )
        view.label(
            768 if index == 0 else 671 if index == 1 else 570 if index == 2 else 609,
            y + 11,
            "?",
            11,
            "#aac7e8",
            700,
            "middle",
        )
        if control == "☑":
            view.rect(1323, y - 7, 19, 19, BLUE, 4, "#a4baff")
            view.label(1333, y + 8, "✓", 13, "#ffffff", 700, "middle")
        else:
            view.rect(1117, y - 12, 228, 35, "#1a2d44", 7, "#3a5675")
            view.label(1132, y + 10, control, 12, TEXT)
        view.rect(496, y + 36, 878, 1, "#25384c")
    view.label(496, 655, "Only jobs started by this app are affected.", 12, MUTED)
    view.button(1241, 730, 132, "Save settings", True)
    view.save("05-settings.svg")


def main() -> None:
    """Write the five reviewable screen designs."""
    library()
    workspace()
    conversation()
    jobs()
    settings()


if __name__ == "__main__":
    main()
