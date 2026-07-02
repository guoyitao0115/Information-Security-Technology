"""Console and file output helpers."""

from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from risk_model import score_findings, score_to_level


def enrich_result(result: dict[str, Any]) -> dict[str, Any]:
    rule_ids = [finding["rule_id"] for finding in result["findings"]]
    score = score_findings(rule_ids)
    enriched = dict(result)
    enriched["risk_score"] = score
    enriched["risk_level"] = score_to_level(score)
    enriched["finding_count"] = len(rule_ids)
    return enriched


def enrich_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [enrich_result(result) for result in results]


def write_json(results: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


def write_csv(results: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["file", "events", "finding_count", "risk_score", "risk_level", "rule_ids", "titles"]
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "file": result["file"],
                    "events": "; ".join(result.get("events", [])),
                    "finding_count": result["finding_count"],
                    "risk_score": result["risk_score"],
                    "risk_level": result["risk_level"],
                    "rule_ids": "; ".join(finding["rule_id"] for finding in result["findings"]),
                    "titles": "; ".join(finding["title"] for finding in result["findings"]),
                }
            )


def rule_distribution(results: list[dict[str, Any]]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for result in results:
        for finding in result["findings"]:
            counter[finding["rule_id"]] += 1
    return counter


def format_console_report(results: list[dict[str, Any]]) -> str:
    lines = []
    lines.append("GitHub Actions Workflow Security Scan")
    lines.append("=" * 44)
    for result in results:
        lines.append(f"{result['file']}")
        lines.append(
            f"  level={result['risk_level']} score={result['risk_score']} findings={result['finding_count']}"
        )
        if not result["findings"]:
            lines.append("  - 未发现明显风险")
        for finding in result["findings"]:
            lines.append(
                f"  - {finding['rule_id']} {finding['title']} [{finding['severity']}, +{finding['weight']}]"
            )
            lines.append(f"    evidence: {finding['evidence']}")
            lines.append(f"    fix: {finding['recommendation']}")
    distribution = rule_distribution(results)
    lines.append("")
    lines.append("Rule distribution:")
    for rule_id, count in sorted(distribution.items()):
        lines.append(f"  {rule_id}: {count}")
    return "\n".join(lines)
