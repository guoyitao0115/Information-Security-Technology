"""Create a clear PNG screenshot from the latest scanner console output."""

from __future__ import annotations

import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "screenshots" / "run_scanner.png"


def find_font() -> str | None:
    candidates = [
        "/System/Library/Fonts/STHeiti Medium.ttc",
        "/System/Library/Fonts/Supplemental/Songti.ttc",
        "/System/Library/Fonts/Menlo.ttc",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    return None


def main() -> None:
    command = [
        str(ROOT / ".venv" / "bin" / "python"),
        str(ROOT / "src" / "scanner.py"),
        "data",
        "--json",
        "results/scan_results.json",
        "--csv",
        "results/scan_summary.csv",
        "--figures",
        "results/figures",
    ]
    completed = subprocess.run(command, cwd=ROOT, check=True, text=True, capture_output=True)
    lines = completed.stdout.splitlines()
    visible_lines = ["$ .venv/bin/python src/scanner.py data --json results/scan_results.json --csv results/scan_summary.csv --figures results/figures"]
    visible_lines.extend(lines[:42])

    font_path = find_font()
    font = ImageFont.truetype(font_path, 18) if font_path else ImageFont.load_default()
    small_font = ImageFont.truetype(font_path, 15) if font_path else ImageFont.load_default()
    width = 1440
    line_height = 27
    padding = 28
    height = padding * 2 + line_height * len(visible_lines) + 52
    image = Image.new("RGB", (width, height), "#102022")
    draw = ImageDraw.Draw(image)
    draw.rounded_rectangle((18, 18, width - 18, height - 18), radius=10, fill="#162a2d", outline="#315255", width=2)
    draw.text((padding, 28), "Terminal - GitHub Actions Workflow Security Scan", fill="#d8ece8", font=small_font)
    y = 68
    for idx, line in enumerate(visible_lines):
        color = "#f1f5f4"
        if idx == 0:
            color = "#8fd3c7"
        elif "level=高风险" in line:
            color = "#ffb4a0"
        elif "level=中风险" in line:
            color = "#ffe199"
        elif "未发现明显风险" in line:
            color = "#b9e6c9"
        draw.text((padding, y), line[:150], fill=color, font=font)
        y += line_height
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT)
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
