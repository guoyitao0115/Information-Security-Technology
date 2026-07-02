"""Command line entry point for the GitHub Actions workflow security scanner."""

from __future__ import annotations

import argparse
from pathlib import Path

from reporter import enrich_results, format_console_report, write_csv, write_json
from rules import scan_workflow_file
from visualize import generate_all_figures


WORKFLOW_EXTENSIONS = {".yml", ".yaml"}


def discover_workflows(target: Path) -> list[Path]:
    if target.is_file() and target.suffix in WORKFLOW_EXTENSIONS:
        return [target]
    if not target.exists():
        raise FileNotFoundError(f"target not found: {target}")
    return sorted(path for path in target.rglob("*") if path.suffix in WORKFLOW_EXTENSIONS)


def scan_path(target: Path) -> list[dict]:
    files = discover_workflows(target)
    return [scan_workflow_file(path) for path in files]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Scan GitHub Actions workflows for common security risks.")
    parser.add_argument("target", type=Path, help="Workflow file or directory containing .yml/.yaml files")
    parser.add_argument("--json", type=Path, default=Path("results/scan_results.json"), help="JSON output path")
    parser.add_argument("--csv", type=Path, default=Path("results/scan_summary.csv"), help="CSV output path")
    parser.add_argument("--figures", type=Path, default=Path("results/figures"), help="Figure output directory")
    parser.add_argument("--no-figures", action="store_true", help="Do not generate figures")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    results = enrich_results(scan_path(args.target))
    write_json(results, args.json)
    write_csv(results, args.csv)
    if not args.no_figures:
        generate_all_figures(results, args.figures)
    print(format_console_report(results))
    print(f"\nSaved JSON: {args.json}")
    print(f"Saved CSV: {args.csv}")
    if not args.no_figures:
        print(f"Saved figures: {args.figures}")


if __name__ == "__main__":
    main()
