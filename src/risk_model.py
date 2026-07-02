"""Risk weights and scoring helpers for GitHub Actions workflow findings."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    title: str
    severity: str
    weight: int
    recommendation: str


RULES: dict[str, RuleMeta] = {
    "GHA001": RuleMeta(
        "GHA001",
        "使用 pull_request_target 触发器",
        "high",
        5,
        "仅在确有必要时使用 pull_request_target；不要在该事件下 checkout 或执行外部贡献者提交的未可信代码。",
    ),
    "GHA002": RuleMeta(
        "GHA002",
        "缺少显式 permissions 配置",
        "medium",
        3,
        "在 workflow 或 job 级别显式声明 GITHUB_TOKEN 最小权限，例如 permissions: contents: read。",
    ),
    "GHA003": RuleMeta(
        "GHA003",
        "存在写权限或过高权限",
        "high",
        4,
        "将 write 权限降到 read 或 none，仅对真正需要写入的 job 单独授权。",
    ),
    "GHA004": RuleMeta(
        "GHA004",
        "第三方 Action 未固定到完整 commit SHA",
        "medium",
        3,
        "将第三方 Action 从 tag 或分支固定到经过审计的完整 40 位 commit SHA。",
    ),
    "GHA005": RuleMeta(
        "GHA005",
        "步骤中包含危险 shell 命令模式",
        "high",
        4,
        "避免 curl|bash、wget|sh、eval 等动态执行方式；下载脚本时校验来源、哈希和执行权限。",
    ),
    "GHA006": RuleMeta(
        "GHA006",
        "Secret 或环境变量使用方式可疑",
        "medium",
        3,
        "避免将 secrets 拼接进命令行、日志或跨步骤环境变量；优先通过受控 action 输入传递敏感值。",
    ),
    "GHA007": RuleMeta(
        "GHA007",
        "checkout 与 pull_request_target 组合风险",
        "critical",
        6,
        "在 pull_request_target 中不要 checkout PR HEAD；如必须读取代码，应隔离权限并禁止访问 secrets。",
    ),
}


def score_to_level(score: int) -> str:
    if score >= 8:
        return "高风险"
    if score >= 4:
        return "中风险"
    if score >= 1:
        return "低风险"
    return "无明显风险"


def score_findings(rule_ids: list[str]) -> int:
    return sum(RULES[rule_id].weight for rule_id in rule_ids if rule_id in RULES)
