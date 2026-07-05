# 为最终报告生成可复现的实验图表。

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt

from reporter import rule_distribution
from risk_model import RULES


def configure_matplotlib() -> None:
    # 优先使用常见中文字体，保证图表标题和坐标轴标签能正常显示。
    plt.rcParams["font.sans-serif"] = ["Arial Unicode MS", "PingFang SC", "Songti SC", "DejaVu Sans"]
    plt.rcParams["axes.unicode_minus"] = False


def save_rule_distribution(results: list[dict[str, Any]], path: Path) -> None:
    # 展示样例集中哪些安全规则最常被命中。
    configure_matplotlib()
    path.parent.mkdir(parents=True, exist_ok=True)
    dist = rule_distribution(results)
    labels = sorted(dist.keys())
    values = [dist[label] for label in labels]

    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=160)
    # 固定配色，保证多次重新生成后的图表风格一致，便于比较。
    colors = ["#2f6f73", "#c45f3d", "#7b5ea7", "#d0a23a", "#556b8e", "#8c5b4f", "#4f8b59"]
    ax.bar(labels, values, color=colors[: len(labels)])
    ax.set_title("风险类型命中分布")
    ax.set_xlabel("规则编号")
    ax.set_ylabel("命中次数")
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    for i, value in enumerate(values):
        ax.text(i, value + 0.03, str(value), ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def save_score_comparison(results: list[dict[str, Any]], path: Path) -> None:
    # 对比不同 workflow 的风险评分，并标出低、中、高风险区间。
    configure_matplotlib()
    path.parent.mkdir(parents=True, exist_ok=True)
    labels = [Path(result["file"]).stem for result in results]
    scores = [result["risk_score"] for result in results]

    fig, ax = plt.subplots(figsize=(9, 4.8), dpi=160)
    # 这里的阈值需要和 risk_model.score_to_level 中的风险等级划分保持一致。
    colors = ["#3b7a78" if score < 4 else "#d0a23a" if score < 8 else "#c45f3d" for score in scores]
    ax.bar(labels, scores, color=colors)
    ax.axhspan(0, 3.99, color="#3b7a78", alpha=0.08, label="低风险")
    ax.axhspan(4, 7.99, color="#d0a23a", alpha=0.10, label="中风险")
    ax.axhspan(8, max(max(scores) + 2, 10), color="#c45f3d", alpha=0.08, label="高风险")
    ax.set_title("不同 Workflow 风险评分对比")
    ax.set_ylabel("风险评分")
    ax.tick_params(axis="x", labelrotation=20)
    ax.legend(loc="upper left", frameon=False)
    ax.grid(axis="y", linestyle="--", alpha=0.35)
    for i, score in enumerate(scores):
        ax.text(i, score + 0.15, str(score), ha="center", va="bottom", fontsize=9)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def save_rule_weight_table(path: Path) -> None:
    # 把评分模型本身画成表格，方便报告解释不同评分的来源。
    configure_matplotlib()
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [[meta.rule_id, meta.title, meta.severity, meta.weight] for meta in RULES.values()]
    fig, ax = plt.subplots(figsize=(10, 3.8), dpi=160)
    ax.axis("off")
    table = ax.table(
        cellText=rows,
        colLabels=["规则", "风险项", "严重性", "权重"],
        cellLoc="center",
        loc="center",
        colWidths=[0.10, 0.55, 0.16, 0.12],
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8.5)
    table.scale(1, 1.35)
    # 使用接近报告表格的样式，避免 matplotlib 默认表格过于简陋。
    for (row, col), cell in table.get_celld().items():
        if row == 0:
            cell.set_facecolor("#2f6f73")
            cell.set_text_props(color="white", weight="bold")
        elif row % 2 == 0:
            cell.set_facecolor("#f0f5f4")
        cell.set_edgecolor("#d5dddd")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def generate_all_figures(results: list[dict[str, Any]], output_dir: Path) -> None:
    # 生成 README、results 目录和课程报告中使用的全部图表。
    save_rule_distribution(results, output_dir / "risk_distribution.png")
    save_score_comparison(results, output_dir / "risk_scores.png")
    save_rule_weight_table(output_dir / "rule_weights.png")
