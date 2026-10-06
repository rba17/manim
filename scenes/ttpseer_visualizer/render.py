"""Render the TTPSeer algorithm visualizers at their slide sizes.

Usage:
    python scenes/ttpseer_visualizer/render.py [--out DIR] [--fps 30] [--scale 1.0] [names...]

Names: pruning_panel, pruning_walkthrough, expanding_panel, expanding_walkthrough
(default: all four). Each MP4 lands in DIR (default: scenes/ttpseer_visualizer/out).
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

from manim import WHITE, tempconfig  # noqa: E402

import ttpseer_algos as A  # noqa: E402

# name -> (scene class, frame width in units, pixel height at scale 1)
JOBS = {
    "pruning_panel": (A.PruningPanel, A.PANEL_W, 1600),
    "pruning_walkthrough": (A.PruningWalkthrough, A.WALK_W, 1000),
    "expanding_panel": (A.ExpandingPanel, A.PANEL_W, 1600),
    "expanding_walkthrough": (A.ExpandingWalkthrough, A.WALK_W, 1000),
}


def even(x: float) -> int:
    return int(round(x / 2)) * 2


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("names", nargs="*", default=list(JOBS))
    ap.add_argument("--out", type=Path, default=HERE / "out")
    ap.add_argument("--fps", type=int, default=30)
    ap.add_argument("--scale", type=float, default=1.0, help="pixel scale, e.g. 0.4 for drafts")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    media = args.out / "_media"

    for name in args.names:
        cls, fw, ph = JOBS[name]
        ph = even(ph * args.scale)
        pw = even(ph * fw / A.FRAME_H)
        opts = {
            "pixel_width": pw,
            "pixel_height": ph,
            "frame_width": fw,
            "frame_height": A.FRAME_H,
            "frame_rate": args.fps,
            "background_color": WHITE,
            "media_dir": str(media),
            "output_file": name,
            "disable_caching": True,
            "verbosity": "WARNING",
            "progress_bar": "none",
        }
        with tempconfig(opts):
            scene = cls()
            scene.render()
            src = Path(scene.renderer.file_writer.movie_file_path)
        shutil.copy(src, args.out / f"{name}.mp4")
        print(f"{name}: {pw}x{ph} -> {args.out / (name + '.mp4')}")


if __name__ == "__main__":
    main()
