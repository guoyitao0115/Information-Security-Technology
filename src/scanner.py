# GitHub Actions workflow 安全扫描器的命令行入口。

from __future__ import annotations

import argparse
from pathlib import Path

from reporter import enrich_results, format_console_report, write_csv, write_json
from rules import scan_workflow_file
from visualize import generate_all_figures


WORKFLOW_EXTENSIONS = {".yml", ".yaml"}


def discover_workflows(target: Path) -> list[Path]:
    # 从单个文件或目录树中找出 workflow 文件。
    if target.is_file() and target.suffix in WORKFLOW_EXTENSIONS:
        return [target]
    if not target.exists():
        raise FileNotFoundError(f"target not found: {target}")
    # 排序可以保证 JSON/CSV 输出顺序稳定，便于多次实验结果对比。
    return sorted(path for path in target.rglob("*") if path.suffix in WORKFLOW_EXTENSIONS)


def scan_path(target: Path) -> list[dict]:
    files = discover_workflows(target)
    # 每个 workflow 独立扫描，跨文件的评分汇总交给 reporter.py 处理。
    return [scan_workflow_file(path) for path in files]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="扫描 GitHub Actions workflow 中的常见安全风险。")
    parser.add_argument("target", type=Path, help="workflow 文件或包含 .yml/.yaml 文件的目录")
    parser.add_argument("--json", type=Path, default=Path("results/scan_results.json"), help="JSON 输出路径")
    parser.add_argument("--csv", type=Path, default=Path("results/scan_summary.csv"), help="CSV 输出路径")
    parser.add_argument("--figures", type=Path, default=Path("results/figures"), help="图表输出目录")
    parser.add_argument("--no-figures", action="store_true", help="不生成图表")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    # 主流程顺序：扫描原始 YAML -> 补充评分和等级 -> 写出机器可读结果。
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
