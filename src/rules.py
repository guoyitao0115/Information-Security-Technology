# 用于检测 GitHub Actions workflow 风险配置的静态规则。

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import yaml

from risk_model import RULES


SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
# 这些模式覆盖最常见的敏感值泄露方式：写日志、写 GITHUB_ENV/GITHUB_OUTPUT、
# 或把 secrets/token/password 直接拼进 shell 命令。
SUSPICIOUS_SECRET_RE = re.compile(
    r"(echo|printf|cat|env|printenv|set-output|GITHUB_ENV|GITHUB_OUTPUT).*(secrets\.|SECRET|TOKEN|PASSWORD|KEY)",
    re.IGNORECASE | re.DOTALL,
)
# 只做静态扫描，因此这里选取可解释、误报相对可控的危险命令模式。
DANGEROUS_COMMAND_PATTERNS = [
    re.compile(r"curl\s+[^|\n]+\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"wget\s+[^|\n]+\|\s*(bash|sh)", re.IGNORECASE),
    re.compile(r"\beval\s+", re.IGNORECASE),
    re.compile(r"chmod\s+\+x\s+.+\n\s*\./", re.IGNORECASE),
    re.compile(r"bash\s+-c\s+['\"]?\$\{?\{?\s*github\.event", re.IGNORECASE),
]


@dataclass
class Finding:
    # 标准化后的规则命中结果，可写入控制台、JSON、CSV 和报告表格。
    rule_id: str
    title: str
    severity: str
    weight: int
    location: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_workflow(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        return {}
    # PyYAML 按 YAML 1.1 会把未加引号的 on 解析为 True，这里还原 GitHub Actions 的触发器字段。
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def build_finding(rule_id: str, location: str, evidence: str) -> Finding:
    meta = RULES[rule_id]
    return Finding(
        rule_id=rule_id,
        title=meta.title,
        severity=meta.severity,
        weight=meta.weight,
        location=location,
        evidence=evidence,
        recommendation=meta.recommendation,
    )


def normalize_events(on_value: Any) -> set[str]:
    # 把 GitHub Actions 的 on 字段统一转换为事件名称集合。
    if isinstance(on_value, str):
        return {on_value}
    if isinstance(on_value, list):
        return {str(item) for item in on_value}
    if isinstance(on_value, dict):
        return {str(key) for key in on_value.keys()}
    return set()


def iter_jobs(workflow: dict[str, Any]):
    # 遍历合法的 job 字典，跳过格式异常的 job 节点。
    jobs = workflow.get("jobs", {})
    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if isinstance(job, dict):
                yield str(job_name), job


def iter_steps(workflow: dict[str, Any]):
    # 遍历 step 字典，并保留稳定的 job/step 位置信息。
    for job_name, job in iter_jobs(workflow):
        steps = job.get("steps", [])
        if isinstance(steps, list):
            for index, step in enumerate(steps, start=1):
                if isinstance(step, dict):
                    yield job_name, index, step


def permissions_are_missing(workflow: dict[str, Any]) -> bool:
    # 检查 workflow 或 job 层是否显式声明了 GitHub token 权限。
    if "permissions" in workflow:
        return False
    return all("permissions" not in job for _, job in iter_jobs(workflow))


def permission_items(value: Any):
    if isinstance(value, str):
        yield "all", value
    elif isinstance(value, dict):
        for scope, level in value.items():
            yield str(scope), str(level)


def detect_high_permissions(workflow: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    # 同时检查 workflow 顶层权限和 job 级覆盖权限，因为两者都可能授予写权限。
    scopes = [("workflow.permissions", workflow.get("permissions"))]
    for job_name, job in iter_jobs(workflow):
        scopes.append((f"jobs.{job_name}.permissions", job.get("permissions")))

    # 这些作用域可能修改仓库状态、发布产物或影响 pull request。
    risky_scopes = {"actions", "checks", "contents", "deployments", "issues", "packages", "pull-requests", "repository-projects"}
    for location, permissions in scopes:
        if permissions is None:
            continue
        for scope, level in permission_items(permissions):
            normalized = level.lower()
            if normalized == "write" and (scope in risky_scopes or scope == "all"):
                findings.append(build_finding("GHA003", location, f"{scope}: {level}"))
            elif normalized in {"write-all", "all"}:
                findings.append(build_finding("GHA003", location, str(permissions)))
                break
    return findings


def action_is_third_party(action: str) -> bool:
    # 将 GitHub 官方命名空间视为较低风险，把固定版本检查重点放在第三方 Action。
    owner = action.split("/", 1)[0].lower()
    return owner not in {"actions", "github"}


def action_ref(action: str) -> str | None:
    if "@" not in action:
        return None
    return action.rsplit("@", 1)[1]


def detect_unpinned_actions(workflow: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for job_name, index, step in iter_steps(workflow):
        uses = step.get("uses")
        if not isinstance(uses, str) or uses.startswith("./") or "docker://" in uses:
            continue
        ref = action_ref(uses)
        # tag 和分支都是可变引用；完整 40 位 SHA 才能保证引用的代码可复现。
        if action_is_third_party(uses) and (ref is None or not SHA_RE.match(ref)):
            findings.append(
                build_finding(
                    "GHA004",
                    f"jobs.{job_name}.steps[{index}].uses",
                    uses,
                )
            )
    return findings


def detect_dangerous_commands(workflow: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for job_name, index, step in iter_steps(workflow):
        run = step.get("run")
        if not isinstance(run, str):
            continue
        for pattern in DANGEROUS_COMMAND_PATTERNS:
            if pattern.search(run):
                # 控制证据长度，既保留风险片段，又避免控制台和 CSV 过长。
                evidence = " ".join(run.strip().split())[:180]
                findings.append(build_finding("GHA005", f"jobs.{job_name}.steps[{index}].run", evidence))
                break
    return findings


def detect_suspicious_secrets(workflow: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for job_name, index, step in iter_steps(workflow):
        run = step.get("run")
        env = step.get("env", {})
        evidence_parts: list[str] = []
        # 同时检查 run 命令和 step 级 env，因为敏感值常常在两者之间流动。
        if isinstance(run, str) and SUSPICIOUS_SECRET_RE.search(run):
            evidence_parts.append("run: " + " ".join(run.strip().split())[:120])
        if isinstance(env, dict):
            for key, value in env.items():
                if "SECRET" in str(key).upper() or "TOKEN" in str(key).upper() or "secrets." in str(value):
                    evidence_parts.append(f"env.{key}: {value}")
        if evidence_parts:
            findings.append(build_finding("GHA006", f"jobs.{job_name}.steps[{index}]", "; ".join(evidence_parts)[:220]))
    return findings


def detect_pull_request_target_checkout(workflow: dict[str, Any], events: set[str]) -> list[Finding]:
    if "pull_request_target" not in events:
        return []
    findings: list[Finding] = []
    for job_name, index, step in iter_steps(workflow):
        uses = step.get("uses", "")
        with_value = step.get("with", {})
        if isinstance(uses, str) and uses.startswith("actions/checkout"):
            # pull_request_target 下 checkout PR HEAD 会把不可信代码带入高权限上下文，因此单独提升为组合风险。
            evidence = uses
            if isinstance(with_value, dict) and any("github.event.pull_request" in str(value) for value in with_value.values()):
                evidence += f" with={with_value}"
            findings.append(build_finding("GHA007", f"jobs.{job_name}.steps[{index}].uses", evidence))
    return findings


def scan_workflow_file(path: Path) -> dict[str, Any]:
    workflow = load_workflow(path)
    events = normalize_events(workflow.get("on"))
    findings: list[Finding] = []

    # 规则顺序与报告叙述一致：触发器风险、权限风险、依赖风险、命令和 Secret 风险。
    if "pull_request_target" in events:
        findings.append(build_finding("GHA001", "on", "pull_request_target"))
    if permissions_are_missing(workflow):
        findings.append(build_finding("GHA002", "permissions", "workflow 和 job 均未显式声明 permissions"))
    findings.extend(detect_high_permissions(workflow))
    findings.extend(detect_unpinned_actions(workflow))
    findings.extend(detect_dangerous_commands(workflow))
    findings.extend(detect_suspicious_secrets(workflow))
    findings.extend(detect_pull_request_target_checkout(workflow, events))

    return {
        "file": str(path),
        "events": sorted(events),
        "findings": [finding.to_dict() for finding in findings],
    }
