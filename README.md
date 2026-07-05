# 信息安全技术期末考查

题目：基于 GitHub Actions 工作流的 CI/CD 安全风险检测复现与改进

小组成员：

- 22308043 郭翊涛
- 20337264 贠湘楠

## 项目说明

本项目复现 USENIX Security 2022 论文 *Characterizing the Security of Github CI Workflows* 中关于 GitHub Actions workflow 安全分析的核心思想，并在基础规则检测之上加入风险评分、风险等级、修复建议和可视化输出。

工具会扫描 `.yml` / `.yaml` workflow 文件，检测以下风险：

- `pull_request_target` 触发器风险
- 缺少显式 `permissions`
- `write-all` 或敏感作用域写权限
- 第三方 Action 未固定到完整 40 位 commit SHA
- `curl|bash`、`wget|sh`、`eval` 等危险命令模式
- Secret 或环境变量可疑使用方式
- `pull_request_target` 与 checkout PR HEAD 的组合风险

## 目录结构

```text
.
├── data/                  # 实验 workflow 样例
├── results/               # JSON、CSV 和图表结果
├── screenshots/           # 代码运行截图
├── src/                   # 扫描器源码
├── tools/                 # 报告和截图生成脚本
├── 信息安全技术期末报告.md
├── 信息安全技术期末报告.pdf
├── requirements.txt
└── README.md
```

## 运行方式

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python src/scanner.py data --json results/scan_results.json --csv results/scan_summary.csv --figures results/figures
```

生成最终报告：

```bash
.venv/bin/python tools/generate_report.py
```

## 输出文件

- `results/scan_results.json`：完整扫描结果、风险证据和修复建议
- `results/scan_summary.csv`：样例汇总表
- `results/figures/risk_distribution.png`：风险类型分布图
- `results/figures/risk_scores.png`：不同 workflow 风险评分对比图
- `results/figures/rule_weights.png`：规则权重表
- `信息安全技术期末报告.md`：课程报告 Markdown 版本
- `信息安全技术期末报告.pdf`：课程报告 PDF 版本
