"""The Accelerating Threat Horizontal.

One attack step produces several log events, each log event maps to several
MITRE ATT&CK techniques, and those techniques fan out into a large graph of
possible next steps.

The slide template (title, logo, red footer) is drawn as the background and the
animation fills the area where the slide's bullet points used to be.

Render (1080p, 60 fps):
    manim -qh scenes/threat_horizontal.py ThreatHorizontal
"""

from __future__ import annotations

import random
from pathlib import Path

import numpy as np

from manim import *

ASSETS = Path(__file__).parent / "assets"

# Slide palette (sampled from the template).
TITLE_RED = ManimColor("#BC0604")
FOOTER_RED = ManimColor("#990000")
GOLD = ManimColor("#CAB576")
INK = ManimColor("#2B2B2B")
SLATE = ManimColor("#4A5560")
MUTED = ManimColor("#9AA3AB")
PAPER = ManimColor("#F7F5F0")

FONT = "Carlito"  # metric-compatible with Calibri, the slide's font
MONO = "DejaVu Sans Mono"

# Vertical bounds of the free area between the slide title and the footer.
CONTENT_TOP = 2.35
CONTENT_BOTTOM = -3.45


def label(text, size=20, color=INK, weight=NORMAL, font=FONT):
    return Text(text, font=font, font_size=size, color=color, weight=weight)


# ---------------------------------------------------------------- icons


def terminal_icon(width=1.4, color=TITLE_RED):
    h = width * 0.72
    body = RoundedRectangle(
        width=width, height=h, corner_radius=0.08 * width,
        stroke_color=color, stroke_width=4, fill_color=WHITE, fill_opacity=1,
    )
    bar = Rectangle(
        width=width, height=0.18 * h,
        stroke_width=0, fill_color=color, fill_opacity=1,
    ).align_to(body, UP)
    dots = VGroup(*[Dot(radius=0.025 * width, color=WHITE) for _ in range(3)])
    dots.arrange(RIGHT, buff=0.04 * width).move_to(bar).align_to(bar, LEFT).shift(0.06 * width * RIGHT)
    prompt = Text(">_", font=MONO, font_size=42 * width, color=color, weight=BOLD)
    prompt.move_to(body).shift(0.08 * h * DOWN + 0.15 * width * LEFT)
    return VGroup(body, bar, dots, prompt)


def log_icon(height=0.6, color=SLATE):
    w = height * 0.78
    fold = 0.28 * w
    page = Polygon(
        [-w / 2, height / 2, 0], [w / 2 - fold, height / 2, 0],
        [w / 2, height / 2 - fold, 0], [w / 2, -height / 2, 0],
        [-w / 2, -height / 2, 0],
        stroke_color=color, stroke_width=3, fill_color=WHITE, fill_opacity=1,
    )
    corner = VMobject(stroke_color=color, stroke_width=3).set_points_as_corners([
        [w / 2 - fold, height / 2, 0], [w / 2 - fold, height / 2 - fold, 0],
        [w / 2, height / 2 - fold, 0],
    ])
    lines = VGroup(*[
        Line(
            [-w * 0.3, y, 0], [w * (0.3 if i % 2 == 0 else 0.12), y, 0],
            stroke_color=color, stroke_width=2.5,
        )
        for i, y in enumerate(np.linspace(height * 0.08, -height * 0.32, 4))
    ])
    return VGroup(page, corner, lines)


def target_icon(radius=0.17, color=TITLE_RED):
    rings = VGroup(
        Circle(radius=radius, stroke_color=color, stroke_width=2.5),
        Circle(radius=radius * 0.55, stroke_color=color, stroke_width=2.5),
        Dot(radius=radius * 0.18, color=color),
    )
    ticks = VGroup(*[
        Line(d * radius * 0.75, d * radius * 1.3, stroke_color=color, stroke_width=2.5)
        for d in (UP, DOWN, LEFT, RIGHT)
    ])
    return VGroup(rings, ticks)


def network_icon(size=0.42, color=GOLD):
    pts = [np.array(p) * size for p in ([-0.5, 0, 0], [0.1, 0.4, 0], [0.1, -0.4, 0], [0.55, 0.05, 0])]
    edges = VGroup(*[
        Line(pts[a], pts[b], stroke_color=color, stroke_width=2.5)
        for a, b in ((0, 1), (0, 2), (1, 3), (2, 3), (1, 2))
    ])
    nodes = VGroup(*[Dot(p, radius=size * 0.11, color=color) for p in pts])
    return VGroup(edges, nodes)


def step_badge(number, text, color=TITLE_RED):
    circle = Circle(radius=0.19, stroke_width=0, fill_color=color, fill_opacity=1)
    num = label(str(number), size=22, color=WHITE, weight=BOLD).move_to(circle)
    caption = label(text, size=24, color=color, weight=BOLD)
    return VGroup(VGroup(circle, num), caption).arrange(RIGHT, buff=0.15)


def smooth_link(start, end, color=MUTED, width=2.0, opacity=1.0):
    dx = (end[0] - start[0]) * 0.5
    return CubicBezier(
        start, start + RIGHT * dx, end - RIGHT * dx, end,
        stroke_color=color, stroke_width=width, stroke_opacity=opacity,
    )


# ---------------------------------------------------------------- content

ATTACK_TITLE = ["Phishing document runs", "encoded PowerShell"]
ATTACK_CMD = "powershell.exe -enc JABjAGwA..."

# (source, event, detail, techniques it maps to)
LOGS = [
    ("Sysmon EID 1", "Process Create", "winword.exe > powershell.exe", ["T1204.002", "T1059.001", "T1027"]),
    ("PowerShell EID 4104", "Script Block", "FromBase64String(...) | IEX", ["T1059.001", "T1140", "T1027"]),
    ("Sysmon EID 3", "Network Connection", "powershell.exe > 185.x.x.x:443", ["T1071.001", "T1105"]),
    ("Sysmon EID 11", "File Create", "%TEMP%\\update.exe", ["T1105", "T1036"]),
]

TECHNIQUES = {
    "T1204.002": "Malicious File",
    "T1059.001": "PowerShell",
    "T1027": "Obfuscated Files/Info",
    "T1140": "Deobfuscate/Decode",
    "T1105": "Ingress Tool Transfer",
    "T1071.001": "Web Protocols",
    "T1036": "Masquerading",
}

NEXT_STEPS = [
    ("T1547", "Boot/Logon Autostart"),
    ("T1053", "Scheduled Task/Job"),
    ("T1055", "Process Injection"),
    ("T1562", "Impair Defenses"),
    ("T1003", "OS Credential Dumping"),
    ("T1082", "System Info Discovery"),
    ("T1087", "Account Discovery"),
    ("T1018", "Remote System Discovery"),
    ("T1021", "Remote Services"),
    ("T1570", "Lateral Tool Transfer"),
    ("T1041", "Exfiltration over C2"),
    ("T1486", "Data Encrypted for Impact"),
]


class ThreatHorizontal(Scene):
    def construct(self):
        random.seed(7)

        background = ImageMobject(ASSETS / "slide_background.png")
        background.set_z_index(-10).scale_to_fit_height(config.frame_height)
        self.add(background)
        self.wait(0.5)

        # ---------------------------------------------- 1. one attack step
        attack_x, logs_x, tech_x = -5.25, -0.4, 4.8
        badge_y = CONTENT_TOP - 0.2

        badge1 = step_badge(1, "One attack step").move_to([attack_x, badge_y, 0])
        term = terminal_icon(1.5).move_to([attack_x, 0.35, 0])
        attack_text = VGroup(*[label(line, size=21, weight=BOLD) for line in ATTACK_TITLE])
        attack_text.arrange(DOWN, buff=0.08).next_to(term, DOWN, buff=0.3)
        attack_cmd = label(ATTACK_CMD, size=12, color=SLATE, font=MONO).next_to(attack_text, DOWN, buff=0.15)

        self.play(FadeIn(badge1, shift=0.2 * DOWN), run_time=0.6)
        self.play(DrawBorderThenFill(term[0]), FadeIn(term[1:]), run_time=0.9)
        self.play(Write(term[3]), run_time=0.5)
        self.play(FadeIn(attack_text, shift=0.15 * UP), run_time=0.6)
        self.play(AddTextLetterByLetter(attack_cmd), run_time=0.9)
        self.wait(0.6)

        # ---------------------------------------------- 2. logs collected
        badge2 = step_badge(2, "Logs collected", color=SLATE).move_to([logs_x, badge_y, 0])

        log_cards = VGroup()
        for i, (src, event, detail, _) in enumerate(LOGS):
            y = 1.25 - i * 1.15
            box = RoundedRectangle(
                width=4.35, height=0.95, corner_radius=0.1,
                stroke_color=SLATE, stroke_width=2, fill_color=PAPER, fill_opacity=1,
            ).move_to([logs_x, y, 0])
            icon = log_icon(0.6).move_to(box.get_left() + RIGHT * 0.4)
            head = label(f"{src} · {event}", size=16, weight=BOLD)
            sub = label(detail, size=12, color=SLATE, font=MONO)
            text = VGroup(head, sub).arrange(DOWN, aligned_edge=LEFT, buff=0.1)
            text.next_to(icon, RIGHT, buff=0.22)
            log_cards.add(VGroup(box, icon, text))

        fan_start = np.array([VGroup(term, attack_text, attack_cmd).get_right()[0] + 0.12, term.get_y(), 0])
        log_arrows = VGroup(*[
            Arrow(
                fan_start, card.get_left(), buff=0.08,
                stroke_width=3, color=SLATE, max_tip_length_to_length_ratio=0.08,
            )
            for card in log_cards
        ])

        self.play(FadeIn(badge2, shift=0.2 * DOWN), run_time=0.6)
        self.play(
            LaggedStart(
                *[
                    AnimationGroup(GrowArrow(arrow), FadeIn(card, shift=0.4 * RIGHT))
                    for arrow, card in zip(log_arrows, log_cards)
                ],
                lag_ratio=0.35,
            ),
            run_time=2.4,
        )
        self.wait(0.6)

        # ---------------------------------------------- 3. mapped to techniques
        badge3 = step_badge(3, "Mapped to techniques").move_to([tech_x, badge_y, 0])

        tech_pills = {}
        for i, (tid, name) in enumerate(TECHNIQUES.items()):
            y = 1.6 - i * 0.69
            box = RoundedRectangle(
                width=3.7, height=0.55, corner_radius=0.27,
                stroke_color=TITLE_RED, stroke_width=2, fill_color=WHITE, fill_opacity=1,
            ).move_to([tech_x, y, 0])
            icon = target_icon(0.15).move_to(box.get_left() + RIGHT * 0.33)
            tid_text = label(tid, size=17, color=TITLE_RED, weight=BOLD)
            name_text = label(name, size=15)
            text = VGroup(tid_text, name_text).arrange(RIGHT, buff=0.12)
            text.next_to(icon, RIGHT, buff=0.18)
            tech_pills[tid] = VGroup(box, icon, text)

        self.play(FadeIn(badge3, shift=0.2 * DOWN), run_time=0.6)

        shown = set()
        mapping_links = VGroup()
        for card, (_, _, _, techniques) in zip(log_cards, LOGS):
            links = VGroup(*[
                smooth_link(
                    card[0].get_right(), tech_pills[t][0].get_left(),
                    color=TITLE_RED, width=2.5,
                )
                for t in techniques
            ])
            new = [tech_pills[t] for t in techniques if t not in shown]
            shown.update(techniques)
            self.play(
                card[0].animate.set_stroke(TITLE_RED, width=3.5),
                run_time=0.3,
            )
            self.play(
                LaggedStart(*[Create(l) for l in links], lag_ratio=0.2),
                LaggedStart(*[GrowFromEdge(p, LEFT) for p in new], lag_ratio=0.2),
                run_time=1.1,
            )
            self.play(
                card[0].animate.set_stroke(SLATE, width=2),
                links.animate.set_stroke(MUTED, width=1.8),
                run_time=0.3,
            )
            mapping_links.add(links)
        self.wait(1.2)

        # ---------------------------------------------- 4. next steps explode
        tech_group = VGroup(*tech_pills.values())
        roots_x = -5.35
        self.play(
            FadeOut(VGroup(badge1, badge2, term, attack_text, attack_cmd, log_arrows, log_cards, mapping_links)),
            FadeOut(badge3),
            tech_group.animate.scale(0.82).move_to([roots_x, -0.5, 0]),
            run_time=1.4,
        )

        badge3b = step_badge(3, "Techniques").move_to([roots_x, badge_y, 0])
        badge4 = step_badge(4, "Possible next steps", color=INK)
        badge4.add_to_back(network_icon(0.42).next_to(badge4, LEFT, buff=0.15))
        badge4.move_to([1.6, badge_y, 0])

        summary = self.summary_line(0)
        self.play(
            FadeIn(badge3b, shift=0.2 * DOWN), FadeIn(badge4, shift=0.2 * DOWN),
            FadeIn(summary, shift=0.2 * UP), run_time=0.8,
        )

        roots = [pill[0].get_right() for pill in tech_group]
        graph_top, graph_bottom = CONTENT_TOP - 0.6, CONTENT_BOTTOM + 0.65

        # Layer 1: named next-step techniques.
        l1_x = -3.4
        l1_pts = [
            np.array([l1_x, y, 0])
            for y in np.linspace(graph_top - 0.1, graph_bottom + 0.1, len(NEXT_STEPS))
        ]
        l1_nodes = VGroup()
        l1_labels = VGroup()
        l1_edges = VGroup()
        for p, (tid, name) in zip(l1_pts, NEXT_STEPS):
            l1_nodes.add(Dot(p, radius=0.07, color=GOLD).set_stroke(INK, 1))
            l1_labels.add(
                VGroup(
                    label(tid, size=13, color=INK, weight=BOLD),
                    label(name, size=12, color=SLATE),
                ).arrange(RIGHT, buff=0.08).next_to(p, RIGHT, buff=0.12)
            )
            for root in random.sample(roots, random.randint(2, 3)):
                l1_edges.add(smooth_link(root, p, color=GOLD, width=1.6, opacity=0.8))

        self.play(
            LaggedStart(*[Create(e) for e in l1_edges], lag_ratio=0.03),
            LaggedStart(*[GrowFromCenter(n) for n in l1_nodes], lag_ratio=0.08),
            LaggedStart(*[FadeIn(l, shift=0.1 * RIGHT) for l in l1_labels], lag_ratio=0.08),
            run_time=2.6,
        )
        self.play(Transform(summary, self.summary_line(len(NEXT_STEPS))), run_time=0.4)

        # Deeper layers: unnamed steps that keep multiplying.
        anchors = [n.get_center() + RIGHT * (lbl.width + 0.25) for n, lbl in zip(l1_nodes, l1_labels)]
        total = len(NEXT_STEPS)
        layers = [(0.75, 30, 0.055, 0.85), (3.05, 70, 0.04, 0.6), (5.2, 150, 0.03, 0.4)]
        prev = anchors
        for depth, (x, count, radius, opacity) in enumerate(layers):
            pts = [
                np.array([x + random.uniform(-0.35, 0.35) * (1 + depth * 0.6), y, 0])
                for y in np.linspace(graph_top, graph_bottom, count)
            ]
            if depth == len(layers) - 1:
                pts = [
                    np.array([random.uniform(4.4, 6.65), random.uniform(graph_bottom, graph_top), 0])
                    for _ in range(count)
                ]
            nodes = VGroup(*[
                Dot(p, radius=radius, color=GOLD if depth == 0 else interpolate_color(GOLD, MUTED, 0.5 * depth))
                for p in pts
            ])
            edges = VGroup()
            for p in pts:
                parents = sorted(prev, key=lambda q: abs(q[1] - p[1]) + random.uniform(0, 1.5))
                for q in parents[: random.randint(1, 2)]:
                    edges.add(smooth_link(q, p, color=MUTED, width=1.4 - 0.3 * depth, opacity=opacity))
            self.play(
                LaggedStart(*[Create(e) for e in edges], lag_ratio=0.6 / len(edges)),
                LaggedStart(*[GrowFromCenter(n) for n in nodes], lag_ratio=0.6 / len(nodes)),
                run_time=1.8 + 0.4 * depth,
            )
            total += count
            self.play(Transform(summary, self.summary_line(total)), run_time=0.4)
            prev = pts

        self.play(Indicate(summary[-1], color=TITLE_RED, scale_factor=1.15), run_time=1.0)
        self.wait(3)

    def summary_line(self, next_steps):
        parts = [
            ("1", "attack step"),
            (str(len(LOGS)), "log events"),
            (str(len(TECHNIQUES)), "techniques"),
            (f"{next_steps}+" if next_steps else "?", "possible next steps"),
        ]
        items = []
        for i, (num, text) in enumerate(parts):
            color = TITLE_RED if i == len(parts) - 1 else INK
            items.append(
                VGroup(
                    label(num, size=24, color=color, weight=BOLD),
                    label(text, size=20, color=SLATE),
                ).arrange(RIGHT, buff=0.1, aligned_edge=DOWN)
            )
            if i < len(parts) - 1:
                items.append(label("→", size=22, color=MUTED))
        return VGroup(*items).arrange(RIGHT, buff=0.25).move_to([0, CONTENT_BOTTOM + 0.18, 0])
