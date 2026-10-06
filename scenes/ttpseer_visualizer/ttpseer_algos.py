"""Step-by-step visualizers for TTPSeer's run-time algorithms.

Algorithm 1 (Relevant Attack Path Selector, "Pruning") and Algorithm 2
(Attack Path Threat Horizon Expander, "Expanding") are played on a small
worked example so the audience can follow every line of the pseudo-code.

Each algorithm has two variants:

* ``*Panel``: only the worked example, sized to replace the bullet text box
  on the right half of the slide (the algorithm image stays on the left).
* ``*Walkthrough``: the algorithm image from the deck on the left with the
  current line highlighted, plus the worked example on the right; sized to
  cover both the image and the bullet box.

Render everything with ``python scenes/ttpseer_visualizer/render.py``.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np

from manim import *

ASSETS = Path(__file__).parent / "assets"

# Concordia deck palette
FONT = "Carlito"  # metric-compatible with Calibri, the deck font
RED = "#BC0604"
INK = "#222222"
MUTED = "#555555"
GRAY = "#8C8C8C"
LIGHT = "#D9D9D9"
PALE = "#F4F4F4"
YELLOW = "#EDB94C"
TEAL = "#24B4B2"
CORAL = "#E3473A"
MINT = "#DDF1F0"

# Geometry, in scene units (frame height is always 8). Slide shapes in EMU.
FRAME_H = 8.0
PANEL_W = FRAME_H * 4923962 / 4047500  # bullet text box on the slide
IMG_W = FRAME_H * 6261854 / 4047500  # algorithm picture box on the slide
WALK_W = FRAME_H * (6891868 + 4923962 - 118534) / 4047500  # picture + bullets


def txt(s: str, size: float = 20, color: str = INK, bold: bool = False) -> Text:
    return Text(s, font=FONT, font_size=size, color=color, weight=BOLD if bold else NORMAL)


class Node(VGroup):
    """A MITRE ATT&CK technique box: ID on top, short name below."""

    def __init__(self, tid: str, name: str, observed: bool = False, forecast: bool = False,
                 w: float = 1.42, h: float = 0.74):
        super().__init__()
        self.key = tid
        self.base_stroke = RED if observed else (TEAL if forecast else GRAY)
        self.box = RoundedRectangle(
            corner_radius=0.1, width=w, height=h, stroke_color=self.base_stroke,
            stroke_width=2.5, fill_color=RED if observed else WHITE, fill_opacity=1,
        )
        self.tid = txt(tid, 22, WHITE if observed else INK, bold=True)
        self.name = txt(name, 14, WHITE if observed else MUTED)
        if self.name.width > w - 0.14:
            self.name.scale_to_fit_width(w - 0.14)
        VGroup(self.tid, self.name).arrange(DOWN, buff=0.05).move_to(self.box)
        self.add(self.box, self.tid, self.name)


def make_edge(a: Node, b: Node, color: str = GRAY) -> Arrow:
    arrow = Arrow(
        a.get_right(), b.get_left(), buff=0.04, stroke_width=3, color=color,
        tip_length=0.16, max_tip_length_to_length_ratio=0.3,
        max_stroke_width_to_length_ratio=12,
    )
    arrow.base_color = color
    return arrow


def chip(label: str, w: float = 0.86, color: str = INK, stroke: str = GRAY, fill: str = WHITE) -> VGroup:
    box = RoundedRectangle(corner_radius=0.08, width=w, height=0.42, stroke_color=stroke,
                           stroke_width=2, fill_color=fill, fill_opacity=1)
    t = txt(label, 16, color, bold=True)
    if t.width > w - 0.1:
        t.scale_to_fit_width(w - 0.1)
    return VGroup(box, t.move_to(box))


class AlgoScene(Scene):
    """Shared layout: status line with line number, graph area, model area."""

    MODE = "panel"  # or "walk"
    ALG_IMG = ""
    IMG_H = 1  # source image height in px
    LINE_ROWS: dict[int, float] = {}  # algorithm line -> centre row in px
    ROW_PX = 50

    def setup(self):
        self.camera.background_color = WHITE
        self.cur_status = None
        self.hl = None
        if self.MODE == "walk":
            fw = config.frame_width
            img = ImageMobject(str(ASSETS / self.ALG_IMG))
            img.stretch_to_fit_height(FRAME_H).stretch_to_fit_width(IMG_W)
            img.move_to([-fw / 2 + IMG_W / 2, 0, 0])
            self.img = img
            self.add(img)
            self.pc = np.array([fw / 2 - PANEL_W / 2, 0, 0])
        else:
            self.pc = ORIGIN.copy()

    # -- coordinates -------------------------------------------------------
    def P(self, x: float, y: float) -> np.ndarray:
        return self.pc + np.array([x, y, 0.0])

    # -- status line + algorithm highlight ----------------------------------
    def _status_mob(self, n: int, msg: str) -> VGroup:
        num = txt(f"Line {n}", 20, WHITE, bold=True)
        pill = RoundedRectangle(corner_radius=0.12, width=num.width + 0.3, height=0.42,
                                fill_color=RED, fill_opacity=1, stroke_width=0)
        num.move_to(pill)
        body = txt(msg, 20, INK)
        g = VGroup(VGroup(pill, num), body).arrange(RIGHT, buff=0.18)
        if g.width > PANEL_W - 0.4:
            g.scale_to_fit_width(PANEL_W - 0.4)
        g.move_to(self.P(0, 3.12)).align_to(self.P(-PANEL_W / 2 + 0.2, 0), LEFT)
        return g

    def _hl_mob(self, n: int) -> Rectangle:
        left = -config.frame_width / 2
        y = FRAME_H / 2 - self.LINE_ROWS[n] / self.IMG_H * FRAME_H
        h = self.ROW_PX / self.IMG_H * FRAME_H * 0.98
        band = Rectangle(width=IMG_W * 0.96, height=h, fill_color=YELLOW, fill_opacity=0.32,
                         stroke_width=0).move_to([left + IMG_W * 0.49, y, 0])
        return band

    def status(self, n: int, msg: str) -> list[Animation]:
        new = self._status_mob(n, msg)
        anims: list[Animation] = []
        if self.cur_status is None:
            anims.append(FadeIn(new, shift=UP * 0.15))
        else:
            anims += [FadeOut(self.cur_status, shift=UP * 0.15), FadeIn(new, shift=UP * 0.15)]
        self.cur_status = new
        if self.MODE == "walk":
            hl = self._hl_mob(n)
            if self.hl is None:
                anims.append(FadeIn(hl))
                self.hl = hl
            else:
                anims.append(self.hl.animate.move_to(hl))
        return anims

    def header(self, left: str, right: str = "") -> VGroup:
        a = VGroup(txt("Worked example", 18, RED, bold=True), txt(left, 18, MUTED)).arrange(RIGHT, buff=0.15)
        a.move_to(self.P(0, 3.66)).align_to(self.P(-PANEL_W / 2 + 0.2, 0), LEFT)
        return a

    # -- graph helpers -------------------------------------------------------
    def build_nodes(self, spec: dict[str, tuple[str, float, float]], observed: str, forecast=()) -> dict[str, Node]:
        nodes = {}
        for tid, (name, x, y) in spec.items():
            nodes[tid] = Node(tid, name, observed=tid == observed, forecast=tid in forecast).move_to(self.P(x, y))
        return nodes

    def path_anims(self, path, on: bool, color=YELLOW) -> list[Animation]:
        anims = []
        for tid in path:
            n = self.nodes[tid]
            anims.append(n.box.animate.set_stroke(color if on else n.base_stroke, 6 if on else 2.5))
        for a, b in zip(path, path[1:]):
            e = self.edges[(a, b)]
            anims.append(e.animate.set_color(color if on else e.base_color).set_stroke(width=6 if on else 3))
        return anims

    # -- model area ----------------------------------------------------------
    def model_box(self) -> VGroup:
        box = RoundedRectangle(corner_radius=0.14, width=1.1, height=1.05, stroke_color=RED,
                               stroke_width=3, fill_color=WHITE, fill_opacity=1)
        m = txt("M", 36, RED, bold=True)
        sub = txt("model", 14, MUTED)
        VGroup(m, sub).arrange(DOWN, buff=0.02).move_to(box)
        return VGroup(box, m, sub).move_to(self.P(-0.7, -2.85))

    BAR_X0, BAR_X1, BAR_BASE, BAR_SCALE = 0.45, 4.7, -3.48, 2.3

    def bars(self, items: list[tuple[str, float]], beta: float | None = None) -> VGroup:
        x0, x1, base = self.BAR_X0, self.BAR_X1, self.BAR_BASE
        slot = (x1 - x0) / len(items)
        self.bar_rects, self.bar_vals = {}, {}
        axis = Line(self.P(x0 - 0.1, base), self.P(x1, base), color=GRAY, stroke_width=2)
        items_g, extras = VGroup(), VGroup()
        for i, (tid, p) in enumerate(items):
            cx = x0 + slot * (i + 0.5)
            r = Rectangle(width=slot * 0.58, height=max(p * self.BAR_SCALE, 0.02), fill_color=LIGHT,
                          fill_opacity=1, stroke_width=0)
            r.move_to(self.P(cx, base), aligned_edge=DOWN)
            v = txt(f"{p:.2f}", 16, INK).next_to(r, UP, buff=0.05)
            lab = txt(tid, 15, MUTED).next_to(self.P(cx, base), DOWN, buff=0.08)
            self.bar_rects[tid], self.bar_vals[tid] = r, v
            items_g.add(VGroup(r, v, lab))
        if beta is not None:
            y = base + beta * self.BAR_SCALE
            line = DashedLine(self.P(x0 - 0.1, y), self.P(x1, y), color=CORAL, stroke_width=3, dash_length=0.12)
            bl = txt(f"β = {beta}", 16, CORAL, bold=True).next_to(line, UP, buff=0.04).align_to(line, RIGHT)
            extras.add(line, bl)
        g = VGroup(axis, items_g, extras)
        g.axis, g.items, g.extras = axis, items_g, extras
        return g

    def grow_bars(self, g: VGroup) -> list[Animation]:
        anims = [Create(g.axis)]
        for r, v, lab in g.items:
            anims.append(AnimationGroup(GrowFromEdge(r, DOWN), FadeIn(v), FadeIn(lab)))
        anims += [FadeIn(m) for m in g.extras]
        return anims


# ---------------------------------------------------------------------------
# Algorithm 1: Relevant Attack Path Selector (pruning)
# ---------------------------------------------------------------------------

PRUNE_NODES = {
    "T1566": ("Phishing", -3.45, 2.4),
    "T1091": ("Removable Media", -3.45, 1.55),
    "T1078": ("Valid Accounts", -3.45, 0.7),
    "T1204": ("User Execution", -1.45, 1.975),
    "T1021": ("Remote Services", -1.45, 0.7),
    "T1133": ("Ext. Remote Services", -1.45, -0.3),
    "T1190": ("Exploit Public App", -1.45, -1.2),
    "T1059": ("Command & Scripting", 0.55, 0.55),
}
PRUNE_PATHS = {
    "p1": ["T1566", "T1204", "T1059"],
    "p2": ["T1091", "T1204", "T1059"],
    "p3": ["T1078", "T1021", "T1059"],
    "p4": ["T1133", "T1059"],
    "p5": ["T1190", "T1059"],
}
# Model output M(context), sorted by decreasing probability as in the paper.
PRUNE_PROBS = {
    "p1": [("T1059", 0.62), ("T1047", 0.18), ("T1053", 0.11), ("T1106", 0.09)],
    "p2": [("T1047", 0.41), ("T1053", 0.33), ("T1106", 0.18), ("T1059", 0.08)],
    "p3": [("T1059", 0.41), ("T1047", 0.29), ("T1053", 0.18), ("T1106", 0.12)],
    "p4": [("T1047", 0.35), ("T1059", 0.27), ("T1106", 0.22), ("T1053", 0.16)],
    "p5": [("T1106", 0.38), ("T1047", 0.25), ("T1059", 0.19), ("T1053", 0.18)],
}
ALPHA = 0.5
E0 = "T1059"


class Pruning(AlgoScene):
    ALG_IMG = "alg1.png"
    IMG_H = 722
    ROW_PX = 51
    LINE_ROWS = {1: 252, 2: 303, 3: 354, 4: 406, 5: 457, 6: 508, 7: 560, 8: 629, 9: 681}

    def s_row(self, pname: str, score: float) -> VGroup:
        bg = RoundedRectangle(corner_radius=0.08, width=2.7, height=0.46, fill_color=PALE,
                              fill_opacity=1, stroke_color=LIGHT, stroke_width=1.5)
        name = txt(pname, 18, INK, bold=True).move_to(bg).align_to(bg, LEFT).shift(RIGHT * 0.15)
        bar = Rectangle(width=max(score * 2.2, 0.03), height=0.2, fill_color=GRAY, fill_opacity=1,
                        stroke_width=0)
        bar.move_to(bg).align_to(bg, LEFT).shift(RIGHT * 0.6)
        val = txt(f"{score:.2f}", 18, INK).move_to(bg).align_to(bg, RIGHT).shift(LEFT * 0.12)
        row = VGroup(bg, name, bar, val)
        row.bg, row.bar = bg, bar
        return row

    def construct(self):
        P = self.P
        self.nodes = self.build_nodes(PRUNE_NODES, observed=E0)
        pairs = {(a, b) for p in PRUNE_PATHS.values() for a, b in zip(p, p[1:])}
        self.edges = {(a, b): make_edge(self.nodes[a], self.nodes[b]) for a, b in sorted(pairs)}

        head = self.header(f"observed e₀ = {E0}   ·   α = {ALPHA}")
        graph = VGroup(*self.edges.values(), *self.nodes.values())
        self.play(FadeIn(head), FadeIn(graph, lag_ratio=0.05), run_time=1.6)
        self.wait(0.4)

        # Line 1: S <- empty list
        s_title = txt("S  (path, score)", 18, INK, bold=True).move_to(P(3.45, 2.45))
        s_slots = VGroup(*[
            RoundedRectangle(corner_radius=0.08, width=2.7, height=0.46, stroke_color=LIGHT,
                             stroke_width=1.5).set_stroke(opacity=0.8).move_to(P(3.45, 1.95 - 0.55 * i))
            for i in range(len(PRUNE_PATHS))
        ])
        for s in s_slots:
            s.set_stroke(LIGHT, 1.5)
        self.play(*self.status(1, "S ← empty list of (path, score)"), FadeIn(s_title), Create(s_slots), run_time=1.0)
        self.wait(0.6)

        model = self.model_box()
        self.play(FadeIn(model), run_time=0.5)

        rows = {}
        for idx, (pname, path) in enumerate(PRUNE_PATHS.items()):
            slow = idx == 0
            rt = 1.0 if slow else 0.45
            ctx, target = path[:-1], path[-1]
            tag = chip(pname, w=0.5, color=INK, stroke=YELLOW, fill=YELLOW)
            tag.scale(0.9).next_to(self.nodes[path[0]], LEFT, buff=0.06)

            # Line 2: for each path p in G
            self.play(*self.status(2, f"for each path p in G  →  {pname} ({idx + 1} of {len(PRUNE_PATHS)})"),
                      *self.path_anims(path, True), FadeIn(tag), run_time=rt)
            if slow:
                self.wait(0.6)

            # Line 3 + 4: split into context and target e0
            ctx_lab = txt("context", 16, MUTED).move_to(P(-4.0, -1.98)).align_to(P(-4.7, 0), LEFT)
            ctx_chips = VGroup(*[chip(t) for t in ctx]).arrange(RIGHT, buff=0.08)
            ctx_chips.next_to(ctx_lab, DOWN, buff=0.1).align_to(ctx_lab, LEFT)
            tgt_lab = txt("e₀ (target)", 16, MUTED).next_to(ctx_chips, DOWN, buff=0.18).align_to(ctx_lab, LEFT)
            tgt_chip = chip(target, color=WHITE, stroke=RED, fill=RED).next_to(tgt_lab, DOWN, buff=0.1).align_to(ctx_lab, LEFT)
            ctx_anims = [FadeIn(ctx_lab)] + [
                TransformFromCopy(self.nodes[t].tid, c) for t, c in zip(ctx, ctx_chips)
            ]
            tgt_anims = [FadeIn(tgt_lab), TransformFromCopy(self.nodes[target].tid, tgt_chip)]
            self.play(*self.status(3, "context ← every technique before the last one"), *ctx_anims, run_time=rt)
            self.wait(0.5 if slow else 0.1)
            self.play(*self.status(4, "e₀ ← the last technique (the one we observed)"), *tgt_anims, run_time=rt)
            self.wait(0.5 if slow else 0.1)

            # Line 5: prob_vector <- M(context)
            bars = self.bars(PRUNE_PROBS[pname])
            moving = ctx_chips.copy()
            self.play(*self.status(5, "ask the model M: what comes after the context?"),
                      moving.animate.scale(0.4).move_to(model).set_opacity(0),
                      Indicate(model[0], color=RED, scale_factor=1.08), run_time=rt)
            self.remove(moving)
            self.play(*self.grow_bars(bars), run_time=rt * 1.1)
            if slow:
                self.wait(0.5)

            # Line 6: s_e0 <- prob_vector[e0]
            score = dict(PRUNE_PROBS[pname])[E0]
            e0_rect, e0_val = self.bar_rects[E0], self.bar_vals[E0]
            self.play(*self.status(6, f"score s = prob_vector[e₀] = {score:.2f}"),
                      e0_rect.animate.set_fill(RED), e0_val.animate.set_color(RED).scale(1.25),
                      Indicate(tgt_chip, scale_factor=1.1), run_time=rt)
            if slow:
                self.wait(0.6)

            # Line 7: append (p, s_e0) to S
            row = self.s_row(pname, score).move_to(s_slots[idx])
            self.play(*self.status(7, f"append ({pname}, {score:.2f}) to S"),
                      TransformFromCopy(VGroup(tag, e0_val), row), run_time=rt * 1.2)
            rows[pname] = row
            self.wait(0.5 if slow else 0.2)

            self.play(*self.path_anims(path, False), FadeOut(tag), FadeOut(bars),
                      FadeOut(VGroup(ctx_lab, ctx_chips, tgt_lab, tgt_chip)), run_time=rt * 0.8)

        # Line 8: k <- ceil(|S| * alpha)
        n = len(PRUNE_PATHS)
        k = int(np.ceil(n * ALPHA))
        k_eq = txt(f"k = ⌈|S| · α⌉ = ⌈{n} × {ALPHA}⌉ = ⌈{n * ALPHA}⌉ = {k}", 28, INK, bold=True)
        k_eq.move_to(P(-0.1, -2.75))
        self.play(*self.status(8, "how many paths to keep?"), FadeOut(model), Write(k_eq), run_time=1.4)
        self.wait(1.2)

        # Line 9: keep only the top-k paths
        order = sorted(PRUNE_PATHS, key=lambda p: -dict(PRUNE_PROBS[p])[E0])
        kept, dropped = order[:k], order[k:]
        self.play(*self.status(9, f"return G′ ← keep only the top-{k} paths"),
                  *[rows[p].animate.move_to(s_slots[i]) for i, p in enumerate(order)], run_time=1.2)
        cut_y = (s_slots[k - 1].get_bottom()[1] + s_slots[k].get_top()[1]) / 2
        cut = DashedLine(P(1.95, cut_y), P(4.95, cut_y),
                         color=RED, stroke_width=3, dash_length=0.1)
        cut_lab = txt(f"top-{k}", 16, RED, bold=True).next_to(cut, LEFT, buff=0.08)
        self.play(Create(cut), FadeIn(cut_lab),
                  *[rows[p].bg.animate.set_fill(MINT).set_stroke(TEAL, 2.5) for p in kept],
                  *[rows[p].bar.animate.set_fill(TEAL) for p in kept],
                  *[rows[p].animate.set_opacity(0.35) for p in dropped], run_time=1.0)

        kept_edges = {(a, b) for p in kept for a, b in zip(PRUNE_PATHS[p], PRUNE_PATHS[p][1:])}
        kept_nodes = {t for p in kept for t in PRUNE_PATHS[p]}
        gone = [e for key, e in self.edges.items() if key not in kept_edges]
        gone += [nd for key, nd in self.nodes.items() if key not in kept_nodes]
        crosses = VGroup(*[Cross(self.nodes[t], stroke_color=RED, stroke_width=4, scale_factor=0.6)
                           for t in self.nodes if t not in kept_nodes])
        self.play(Create(crosses), *[m.animate.set_opacity(0.25) for m in gone], run_time=1.0)
        self.wait(0.4)
        self.play(FadeOut(crosses), *[FadeOut(m) for m in gone], run_time=1.0)

        result = txt(f"G′ keeps {k} of {n} paths, the ones that best explain e₀", 22, TEAL, bold=True)
        result.move_to(P(0, -2.0))
        self.play(FadeIn(result, shift=UP * 0.1), k_eq.animate.scale(0.8).move_to(P(-0.1, -2.9)).set_color(MUTED), run_time=1.0)
        self.wait(3)


class PruningPanel(Pruning):
    MODE = "panel"


class PruningWalkthrough(Pruning):
    MODE = "walk"


# ---------------------------------------------------------------------------
# Algorithm 2: Attack Path Threat Horizon Expander (expanding)
# ---------------------------------------------------------------------------

EXPAND_NODES = {
    "T1566": ("Phishing", -4.0, 1.9),
    "T1078": ("Valid Accounts", -4.0, 0.55),
    "T1204": ("User Execution", -2.2, 1.9),
    "T1021": ("Remote Services", -2.2, 0.55),
    "T1133": ("Ext. Remote Services", -2.2, -0.8),
    "T1059": ("Command & Scripting", -0.4, 0.55),
    "T1105": ("Ingress Tool Transfer", 1.4, 1.9),
    "T1547": ("Boot/Logon Autostart", 1.4, 0.55),
    "T1003": ("Credential Dumping", 1.4, -0.8),
    "T1055": ("Process Injection", 3.2, 1.25),
    "T1550": ("Alt. Auth Material", 3.2, -0.2),
    "T1570": ("Lateral Tool Transfer", 3.2, -1.2),
}
FORECAST = {"T1105", "T1547", "T1003", "T1055", "T1550", "T1570"}
G_PRIME = [["T1566", "T1204", "T1059"], ["T1078", "T1021", "T1059"], ["T1133", "T1059"]]
EXPAND_PROBS = {
    ("T1566", "T1204", "T1059"): [("T1105", 0.46), ("T1547", 0.34), ("T1082", 0.12), ("T1057", 0.08)],
    ("T1078", "T1021", "T1059"): [("T1003", 0.52), ("T1105", 0.21), ("T1082", 0.15), ("T1018", 0.12)],
    ("T1133", "T1059"): [("T1105", 0.38), ("T1003", 0.31), ("T1082", 0.18), ("T1016", 0.13)],
    ("T1566", "T1204", "T1059", "T1105"): [("T1055", 0.44), ("T1003", 0.22), ("T1082", 0.20), ("T1112", 0.14)],
    ("T1566", "T1204", "T1059", "T1547"): [("T1055", 0.36), ("T1112", 0.27), ("T1082", 0.21), ("T1003", 0.16)],
    ("T1078", "T1021", "T1059", "T1003"): [("T1550", 0.48), ("T1570", 0.33), ("T1082", 0.11), ("T1018", 0.08)],
    ("T1133", "T1059", "T1105"): [("T1055", 0.39), ("T1547", 0.25), ("T1082", 0.20), ("T1018", 0.16)],
    ("T1133", "T1059", "T1003"): [("T1550", 0.35), ("T1570", 0.26), ("T1018", 0.21), ("T1082", 0.18)],
}
BETA = 0.3
R = 2


class Expanding(AlgoScene):
    ALG_IMG = "alg2.png"
    IMG_H = 671
    ROW_PX = 45
    LINE_ROWS = {1: 261, 2: 305.5, 3: 350.5, 4: 395.5, 5: 441, 6: 486, 7: 591, 8: 635.5}

    def counter(self, i: int | None, n_paths: int) -> VGroup:
        s = f"i = {i} of r = {R}   ·   paths: {n_paths}" if i else f"paths: {n_paths}"
        t = txt(s, 18, INK, bold=True)
        return t.move_to(self.P(0, 3.66)).align_to(self.P(PANEL_W / 2 - 0.2, 0), RIGHT)

    def construct(self):
        P = self.P
        self.nodes = self.build_nodes(EXPAND_NODES, observed=E0, forecast=FORECAST)
        self.edges = {}
        for p in G_PRIME:
            for a, b in zip(p, p[1:]):
                self.edges[(a, b)] = make_edge(self.nodes[a], self.nodes[b])
        past_nodes = {t for p in G_PRIME for t in p}

        head = self.header(f"β = {BETA}   ·   r = {R}")
        cnt = self.counter(None, len(G_PRIME))
        graph = VGroup(*self.edges.values(), *[self.nodes[t] for t in past_nodes])
        g_label = txt("pruned past subgraph G′", 16, MUTED).next_to(self.nodes["T1566"], UP, buff=0.08).align_to(self.nodes["T1566"], LEFT)
        f_label = txt("forecast →", 16, TEAL, bold=True).next_to(self.nodes["T1105"], UP, buff=0.08).align_to(self.nodes["T1105"], LEFT)
        self.play(FadeIn(head), FadeIn(cnt), FadeIn(graph, lag_ratio=0.05), FadeIn(g_label), run_time=1.6)
        self.wait(0.5)

        model = self.model_box()
        self.play(FadeIn(model), run_time=0.5)

        paths = [list(p) for p in G_PRIME]
        first = True
        for i in range(1, R + 1):
            new_cnt = self.counter(i, len(paths))
            self.play(*self.status(1, f"for i = {i} to r: grow every path by one step"),
                      FadeTransform(cnt, new_cnt), run_time=0.8)
            cnt = new_cnt
            self.wait(0.4 if i == 1 else 0.2)
            new_paths = []
            for j, p in enumerate(paths):
                slow = first
                rt = 1.0 if slow else (0.55 if i == 1 else 0.4)

                # Line 2: for each path p in G'
                self.play(*self.status(2, f"for each path p in G′  →  path {j + 1} of {len(paths)}"),
                          *self.path_anims(p, True), run_time=rt)
                if slow:
                    self.wait(0.5)

                # Line 3: prob_vector <- M(p)
                lab = txt("p", 16, MUTED).move_to(P(-4.6, -2.25)).align_to(P(-4.7, 0), LEFT)
                w = 0.86 if len(p) <= 3 else 0.74
                pchips = VGroup(*[
                    chip(t, w=w, color=WHITE if t == E0 else INK, stroke=RED if t == E0 else GRAY,
                         fill=RED if t == E0 else WHITE) for t in p
                ]).arrange(RIGHT, buff=0.06)
                pchips.next_to(lab, DOWN, buff=0.1).align_to(lab, LEFT)
                self.play(FadeIn(lab), *[TransformFromCopy(self.nodes[t].tid, c) for t, c in zip(p, pchips)],
                          run_time=rt * 0.9)
                moving = pchips.copy()
                self.play(*self.status(3, "prob_vector ← M(p): what comes next?"),
                          moving.animate.scale(0.4).move_to(model).set_opacity(0),
                          Indicate(model[0], color=RED, scale_factor=1.08), run_time=rt)
                self.remove(moving)
                probs = EXPAND_PROBS[tuple(p)]
                bars = self.bars(probs, beta=BETA)
                self.play(*self.status(4, "for each technique in prob_vector: compare it to β"),
                          *self.grow_bars(bars), run_time=rt * 1.1)
                if slow:
                    self.wait(0.6)

                # Lines 4-5: keep techniques with prob >= beta
                passing = [t for t, v in probs if v >= BETA]
                self.play(*self.status(5, f"keep every technique with probability ≥ β = {BETA}"),
                          *[self.bar_rects[t].animate.set_fill(TEAL if v >= BETA else LIGHT).set_opacity(1 if v >= BETA else 0.5)
                            for t, v in probs],
                          *[self.bar_vals[t].animate.set_color(TEAL) for t in passing], run_time=rt)
                if slow:
                    self.wait(0.6)

                # Line 6: branch p with each passing technique
                grow = []
                for t in passing:
                    node = self.nodes[t]
                    if node not in self.mobjects:
                        grow.append(TransformFromCopy(self.bar_rects[t], node))
                for t in passing:
                    key = (p[-1], t)
                    if key not in self.edges:
                        e = make_edge(self.nodes[p[-1]], self.nodes[t], color=TEAL)
                        self.edges[key] = e
                        grow.append(GrowArrow(e))
                    else:
                        grow.append(Indicate(self.edges[key], color=TEAL, scale_factor=1.0))
                if first:
                    grow.append(FadeIn(f_label))
                branch_txt = " and ".join(passing)
                n_after = len(new_paths) + len(passing) + len(paths) - j - 1
                new_cnt = self.counter(i, n_after)
                self.play(*self.status(6, f"branch p with {branch_txt}"), *grow,
                          FadeTransform(cnt, new_cnt), run_time=rt * 1.3)
                cnt = new_cnt
                self.wait(0.6 if slow else 0.2)
                new_paths += [p + [t] for t in passing]

                self.play(*self.path_anims(p, False), FadeOut(bars), FadeOut(VGroup(lab, pchips)),
                          run_time=rt * 0.7)
                first = False
            paths = new_paths

        # Lines 7-8: G_t <- G', return
        bound = len(G_PRIME) * int(np.floor(1 / BETA)) ** R
        self.play(*self.status(7, "G_t ← G′  (now holding all the branches)"), FadeOut(model), run_time=0.8)
        for p in paths:
            self.play(*self.path_anims(p, True, color=TEAL), run_time=0.3)
            self.play(*self.path_anims(p, False), run_time=0.2)
        summary = VGroup(
            txt(f"{len(paths)} forecast attack paths", 26, TEAL, bold=True),
            txt(f"bounded by α·|P|·⌊1/β⌋ʳ = {len(G_PRIME)} · {int(np.floor(1 / BETA))}² = {bound}", 20, MUTED),
        ).arrange(DOWN, buff=0.15).move_to(P(0, -2.8))
        self.play(*self.status(8, "return G_t, the forecasted attack path graph"), FadeIn(summary, shift=UP * 0.1),
                  run_time=1.0)
        self.wait(3)


class ExpandingPanel(Expanding):
    MODE = "panel"


class ExpandingWalkthrough(Expanding):
    MODE = "walk"
