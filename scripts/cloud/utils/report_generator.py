"""
Report Generator — 支持 JSON / Markdown / HTML / SARIF
"""

import json
from datetime import datetime, timezone
from pathlib import Path


class ReportGenerator:

    @staticmethod
    def generate_json(findings, provider, lang='en'):
        summary = ReportGenerator._build_summary(findings)
        report = {
            'scan_info': {
                'provider': provider,
                'scan_date': datetime.now(timezone.utc).isoformat(),
                'language': lang,
            },
            'summary': summary,
            'findings': findings,
        }
        return json.dumps(report, indent=2, ensure_ascii=False, default=str)

    @staticmethod
    def generate_markdown(findings, provider, lang='en'):
        summary = ReportGenerator._build_summary(findings)
        is_cn = lang == 'zh-CN'

        lines = []
        lines.append('# ' + ('云安全审计报告' if is_cn else 'Cloud Security Audit Report'))
        lines.append('')
        lines.append(f'**{'提供商' if is_cn else 'Provider'}**: {provider}')
        lines.append(f'**{'扫描时间' if is_cn else 'Scan Date'}**: {datetime.now(timezone.utc).isoformat()}')
        lines.append('')

        # Summary
        lines.append(f'## {'摘要' if is_cn else 'Summary'}')
        lines.append('')
        lines.append(f'| {'指标' if is_cn else 'Metric'} | {'值' if is_cn else 'Value'} |')
        lines.append('|------|------|')
        lines.append(f'| {'安全评分' if is_cn else 'Security Score'} | **{summary["security_score"]}/100** |')
        lines.append(f'| {'总计' if is_cn else 'Total Findings'} | {summary["total"]} |')
        lines.append(f'| {'严重' if is_cn else 'CRITICAL'} | {summary["critical"]} |')
        lines.append(f'| {'高危' if is_cn else 'HIGH'} | {summary["high"]} |')
        lines.append(f'| {'中危' if is_cn else 'MEDIUM'} | {summary["medium"]} |')
        lines.append(f'| {'低危' if is_cn else 'LOW'} | {summary["low"]} |')
        lines.append('')

        # Findings detail
        lines.append(f'## {'发现详情' if is_cn else 'Findings'}')
        lines.append('')

        for f in findings:
            sev = f.get('severity', 'MEDIUM')
            sev_icon = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡' if sev == 'MEDIUM' else '🔵'
            lines.append(f'### {sev_icon} [{sev}] {f.get("title", "")}')
            lines.append('')
            lines.append(f'- **ID**: `{f.get("id", "")}`')
            lines.append(f'- **{'描述' if is_cn else 'Description'}**: {f.get("description", "")}')
            if f.get('attack_scenario'):
                lines.append(f'- **{'攻击场景' if is_cn else 'Attack Scenario'}**: {f.get("attack_scenario")}')
            if f.get('compliance'):
                lines.append(f'- **{'合规' if is_cn else 'Compliance'}**: {", ".join(f.get("compliance", []))}')
            if f.get('remediation'):
                rem = f['remediation']
                if isinstance(rem, dict):
                    lines.append(f'- **{'修复建议' if is_cn else 'Remediation'}**: {rem.get("description", "")}')
                    if rem.get('cli'):
                        lines.append(f'  ```bash')
                        lines.append(f'  {rem["cli"]}')
                        lines.append(f'  ```')
                else:
                    lines.append(f'- **{'修复建议' if is_cn else 'Remediation'}**: {rem}')
            lines.append('')

        return '\n'.join(lines)

    @staticmethod
    def generate_html(findings, provider, lang='en'):
        is_cn = lang == 'zh-CN'
        summary = ReportGenerator._build_summary(findings)

        finding_rows = ''
        for f in findings:
            sev = f.get('severity', 'MEDIUM')
            sev_class = sev.lower()
            finding_rows += f'''
            <tr class="{sev_class}">
                <td><span class="badge badge-{sev_class}">{sev}</span></td>
                <td>{f.get("title", "")}</td>
                <td>{f.get("description", "")}</td>
                <td>{f.get("remediation", {}).get("description", "") if isinstance(f.get("remediation"), dict) else f.get("remediation", "")}</td>
            </tr>'''

        html = f'''<!DOCTYPE html>
<html lang="{lang}">
<head>
    <meta charset="UTF-8">
    <title>{'云安全审计报告' if is_cn else 'Cloud Security Audit Report'}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: #f5f5f5; }}
        .header {{ background: #1a1a2e; color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }}
        .score {{ font-size: 64px; font-weight: bold; text-align: center; }}
        .summary {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }}
        .summary-card {{ background: white; padding: 15px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .summary-card.critical {{ border-left: 4px solid #e74c3c; }}
        .summary-card.high {{ border-left: 4px solid #e67e22; }}
        .summary-card.medium {{ border-left: 4px solid #f1c40f; }}
        .summary-card.low {{ border-left: 4px solid #3498db; }}
        table {{ width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; }}
        th {{ background: #1a1a2e; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; }}
        .badge {{ padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .badge-critical {{ background: #e74c3c; color: white; }}
        .badge-high {{ background: #e67e22; color: white; }}
        .badge-medium {{ background: #f1c40f; color: black; }}
        .badge-low {{ background: #3498db; color: white; }}
        tr.critical {{ border-left: 4px solid #e74c3c; }}
        tr.high {{ border-left: 4px solid #e67e22; }}
        tr.medium {{ border-left: 4px solid #f1c40f; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{'云安全审计报告' if is_cn else 'Cloud Security Audit Report'}</h1>
        <p>{'提供商' if is_cn else 'Provider'}: {provider} | {'扫描时间' if is_cn else 'Scan Date'}: {datetime.now(timezone.utc).isoformat()}</p>
        <div class="score">{summary['security_score']}<span style="font-size:20px">/100</span></div>
    </div>
    <div class="summary">
        <div class="summary-card critical"><h2>{summary['critical']}</h2><p>CRITICAL</p></div>
        <div class="summary-card high"><h2>{summary['high']}</h2><p>HIGH</p></div>
        <div class="summary-card medium"><h2>{summary['medium']}</h2><p>MEDIUM</p></div>
        <div class="summary-card low"><h2>{summary['low']}</h2><p>LOW</p></div>
        <div class="summary-card"><h2>{summary['total']}</h2><p>TOTAL</p></div>
    </div>
    <h2>{'发现详情' if is_cn else 'Findings'}</h2>
    <table>
        <thead>
            <tr><th>{'严重性' if is_cn else 'Severity'}</th><th>{'标题' if is_cn else 'Title'}</th><th>{'描述' if is_cn else 'Description'}</th><th>{'修复建议' if is_cn else 'Remediation'}</th></tr>
        </thead>
        <tbody>{finding_rows}</tbody>
    </table>
</body>
</html>'''
        return html

    @staticmethod
    def generate_sarif(findings, provider):
        """SARIF v2.1.0 格式, 可导入 GitHub Code Scanning"""
        results = []
        for f in findings:
            results.append({
                'ruleId': f.get('id', ''),
                'level': _sev_to_sarif_level(f.get('severity', 'MEDIUM')),
                'message': {'text': f.get('description', '')},
                'locations': [{'physicalLocation': {'artifactLocation': {'uri': f.get('resource', 'unknown')}}}],
            })

        sarif = {
            '$schema': 'https://json.schemastore.org/sarif-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'cloud-vuln-skill',
                        'informationUri': 'https://github.com/user/cloud-vuln-skill',
                    }
                },
                'results': results,
            }]
        }
        return json.dumps(sarif, indent=2)

    @staticmethod
    def _build_summary(findings):
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        weights = {'CRITICAL': 20, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 1}
        total_deduction = 0

        for f in findings:
            sev = f.get('severity', 'MEDIUM')
            if sev in counts:
                counts[sev] += 1
            total_deduction += weights.get(sev, 5)

        total = sum(counts.values())
        score = max(0, 100 - total_deduction)

        return {
            'total': total,
            'critical': counts['CRITICAL'],
            'high': counts['HIGH'],
            'medium': counts['MEDIUM'],
            'low': counts['LOW'],
            'security_score': score,
        }


def _sev_to_sarif_level(severity):
    return {'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning', 'LOW': 'note'}.get(severity, 'warning')
