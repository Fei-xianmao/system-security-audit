# system-security-audit

网站 / Web 系统 / 小程序上线前安全检测的 AI 技能包（Agent Skill）：统一检测方案与授权、八维度检测清单（含软件供应链与云暴露面）、渗透与配置核查，并从 Markdown 模板自动生成统一版式的 Word 交付物。

## 交付物（每项目一套）

| 文档 | 说明 |
|---|---|
| 检测方案 | 范围、依据、8 维度检测项、进度与配合事项 |
| 检测授权书 | 渗透测试书面授权，一页式 |
| 系统上线安全检测和安全措施有效性验证报告 | 结论报告，12 个控制域结果表 + 风险登记 + 附录（证据/工具版本/漏洞八要素） |
| 复测报告 | 整改后回归验证 |
| Excel 检测清单 | 42 项，含检测方式（自动/人工/半自动）与结果列 |

## 快速开始

```bash
# 1. 填公司抬头
#    编辑 assets/config.json 的 company_name / contact_* 等字段

# 2. 用模板出空白文档（或复制到项目目录替换【】占位后出正式文档）
pip install pypandoc-binary openpyxl        # 或自行安装 pandoc
python scripts/md2docx_convert.py assets/templates/结论报告.md -o 报告.docx --toc
python scripts/generate_checklist.py 检测清单.xlsx "公司名称" assets/config.json

# 3. 云暴露面探测（授权范围内，只读默认）
pip install -r scripts/cloud/requirements.txt
python scripts/cloud/cloud_scanner.py brute-s3 --domain example.com
python scripts/cloud/cloud_scanner.py probe-ssrf --url "https://example.com/fetch?url=http://169.254.169.254/"
```

## 目录结构

```text
SKILL.md                技能入口：意图分流、四步工作流、命令
references/             检测 SOP、工具矩阵、云攻击面手册、报告填写规范
assets/
  config.json           公司抬头与归档配置（发布版为占位符）
  reference.docx        Word 样式参考（多级编号标题、网格/三线表，无正文）
  templates/            四类交付物 Markdown 模板
scripts/
  md2docx_convert.py    md → docx 转换（pandoc + reference.docx + 样式后处理）
  generate_checklist.py 生成 Excel 检测清单
  cloud/                cloud_scanner 云暴露面工具（第三方，AGPLv3）
```

## 检测依据

GB/T 22239-2019《信息安全技术 网络安全等级保护基本要求》（[全文公开](https://openstd.samr.gov.cn/)）、GB/T 28448-2019、GB/T 35273-2020、OWASP Top 10:2025（含 A03 软件供应链失效）、OWASP API Security Top 10、CVSS 3.1。

## 边界与免责

- 自动化 + 人工结合：业务逻辑、深度越权、合规判断必须人工（详见 SKILL.md 核心原则）。
- 本技能产出为自检性质报告；正式验收、等保测评、应用上架须由具备 CNAS/CMA 资质的第三方机构出具并盖章。
- 所有探测仅在书面授权范围内执行；cloud_scanner 默认只读，写操作类利用须确认。

## 许可

- 技能本体（SKILL.md、references、assets、scripts 中除 cloud/ 外）：MIT，见 LICENSE。
- `scripts/cloud/`：源自 [cloud-vuln-skill](https://github.com/mouren101/cloud-vuln-skill)，AGPLv3，LICENSE 已随目录保留；再分发或修改该目录代码时须遵守 AGPLv3。
