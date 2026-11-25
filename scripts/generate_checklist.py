#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate the Excel security detection checklist from the scheme."""
import json, sys
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

CHECKS = [
    ("1 API 接口安全", "未授权访问：去鉴权后接口是否仍返回数据", "半自动", "待检测"),
    ("1 API 接口安全", "水平/垂直越权、IDOR 遍历", "人工", "待检测"),
    ("1 API 接口安全", "参数篡改（金额/状态/角色）", "半自动", "待检测"),
    ("1 API 接口安全", "SQL注入/XSS/SSRF/命令注入", "自动", "待检测"),
    ("1 API 接口安全", "频率限制与防刷", "自动", "待检测"),
    ("1 API 接口安全", "敏感信息泄露（响应含手机号/身份证/openid）", "自动", "待检测"),
    ("2 业务逻辑安全", "支付金额篡改 / 0元购 / 回调验签", "人工", "待检测"),
    ("2 业务逻辑安全", "优惠券重复使用 / 并发超发", "人工", "待检测"),
    ("2 业务逻辑安全", "验证码爆破 / 重放 / 绕过", "人工", "待检测"),
    ("2 业务逻辑安全", "预约时段被占满 / 排队号可预测", "人工", "待检测"),
    ("2 业务逻辑安全", "越权查看他人订单/资料", "人工", "待检测"),
    ("3 代码与配置", ".wxapkg 反编译风险与泄露面", "自动", "待检测"),
    ("3 代码与配置", "硬编码 appsecret/key/token", "自动", "待检测"),
    ("3 代码与配置", "前端校验可绕过", "人工", "待检测"),
    ("3 代码与配置", "调试残留 vConsole / source map", "自动", "待检测"),
    ("3 代码与配置", "本地存储明文敏感数据", "自动", "待检测"),
    ("4 数据与密码学", "全站 HTTPS / TLS1.2+ / 证书有效", "自动", "待检测"),
    ("4 数据与密码学", "敏感数据加密存储与脱敏展示", "半自动", "待检测"),
    ("4 数据与密码学", "密钥管理（前端不落密钥）", "人工", "待检测"),
    ("4 数据与密码学", "Token 绑定设备与越权校验", "半自动", "待检测"),
    ("5 域名与暴露面", "域名白名单规范 / 无测试域名残留", "自动", "待检测"),
    ("5 域名与暴露面", "web-view 任意跳转", "人工", "待检测"),
    ("5 域名与暴露面", "子域名/端口/关联资产暴露", "自动", "待检测"),
    ("5 域名与暴露面", "遗留测试接口/Swagger/调试页面", "自动", "待检测"),
    ("5 域名与暴露面", "默认口令 / 开源组件已知漏洞", "自动", "待检测"),
    ("6 隐私合规", "隐私指引与代码接口调用逐项一致", "半自动", "待检测"),
    ("6 隐私合规", "告知同意：弹窗明示 / 非默认勾选", "人工", "待检测"),
    ("6 隐私合规", "最小必要 / 敏感信息单独同意", "人工", "待检测"),
    ("6 隐私合规", "撤回同意 / 账号注销与数据删除", "人工", "待检测"),
    ("6 隐私合规", "第三方SDK披露 / 内容安全接口", "人工", "待检测"),
    ("7 平台规范", "提审版本与上线版本一致", "人工", "待检测"),
    ("7 平台规范", "类目资质 / 支付合规 / 无诱导分享", "人工", "待检测"),
    ("7 平台规范", "用户协议与隐私政策独立完整", "人工", "待检测"),
    ("8 软件供应链", "SBOM：直接+传递依赖版本清单可追溯", "半自动", "待检测"),
    ("8 软件供应链", "依赖组件无未修复高危 CVE（CVE/NVD/OSV）", "自动", "待检测"),
    ("8 软件供应链", "停维/不可打补丁组件有替换或虚拟补丁方案", "人工", "待检测"),
    ("8 软件供应链", "依赖取官方源 / 优先签名包（含前端与SDK）", "半自动", "待检测"),
    ("8 软件供应链", "CI/CD 职责分离 / 变更留痕 / 灰度发布", "人工", "待检测"),
    ("9 安全管理制度", "管理制度/操作规程/应急预案齐备且现行有效", "人工", "待检测"),
    ("9 安全管理制度", "安全专岗与职责书面化；离岗交接与安全意识培训记录", "人工", "待检测"),
    ("9 安全管理制度", "上线前强制检测流程；变更与发布审批留痕", "人工", "待检测"),
    ("9 安全管理制度", "补丁周期/应急演练/日志审计≥6月/备份恢复验证", "人工", "待检测"),
]

HEAD_FILL = PatternFill("solid", fgColor="1F3A5F")
MODE_FILL = {"自动": PatternFill("solid", fgColor="E1F5EE"),
             "人工": PatternFill("solid", fgColor="FAEEDA"),
             "半自动": PatternFill("solid", fgColor="E6F1FB")}
THIN = Side(style="thin", color="CCCCCC")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)

def style_header(ws, ncol):
    for j in range(1, ncol+1):
        c = ws.cell(row=1, column=j)
        c.fill = HEAD_FILL; c.font = Font(color="FFFFFF", bold=True, size=11)
        c.alignment = Alignment(horizontal="center", vertical="center")
        c.border = BORDER
    ws.row_dimensions[1].height = 24
    ws.freeze_panes = "A2"

def build(path, company, appname):
    wb = Workbook()
    ws = wb.active
    ws.title = "检测清单"
    headers = ["序号", "检测维度", "检测项", "检测方式", "结果(通过/不通过/不适用)", "风险等级", "证据编号", "备注"]
    ws.append(headers)
    for idx, (dim, item, mode, _) in enumerate(CHECKS, 1):
        ws.append([idx, dim, item, mode, "待检测", "", "", ""])
        r = ws.max_row
        ws.cell(row=r, column=4).fill = MODE_FILL.get(mode, PatternFill())
        for j in range(1, 9):
            ws.cell(row=r, column=j).border = BORDER
            ws.cell(row=r, column=j).alignment = Alignment(vertical="center", wrap_text=True)
    style_header(ws, len(headers))
    widths = [6, 18, 40, 10, 22, 12, 12, 24]
    for j, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(j)].width = w

    ws2 = wb.create_sheet("封面与说明")
    info = [
        ("小程序安全检测检查清单", ""),
        ("出具单位", company),
        ("检测对象", appname),
        ("检测方式说明", "自动=工具可批量完成；人工=专家手工推演/判断；半自动=工具辅助+人工复核"),
        ("填写说明", "1) 逐项执行后在『结果』列填写通过/不通过/不适用；2) 不通过项填写风险等级与证据编号；3) 证据截图按编号归档。"),
        ("合规提示", "正式验收/等保/上架用途须由具备 CNAS/CMA 资质的第三方机构出具并盖章。"),
    ]
    for k, v in info:
        ws2.append([k, v])
    ws2.cell(row=1, column=1).font = Font(bold=True, size=14, color="1F3A5F")
    for r in range(2, ws2.max_row+1):
        ws2.cell(row=r, column=1).font = Font(bold=True)
        ws2.cell(row=r, column=2).alignment = Alignment(wrap_text=True, vertical="top")
    ws2.column_dimensions["A"].width = 18
    ws2.column_dimensions["B"].width = 90
    wb.save(path)
    print("SAVED", path, "| checks:", len(CHECKS))

if __name__ == "__main__":
    cfg = {}
    if len(sys.argv) > 3:
        with open(sys.argv[3], encoding="utf-8") as f:
            cfg = json.load(f)
    build(sys.argv[1],
          sys.argv[2] if len(sys.argv) > 4 else cfg.get("company_name", "检测机构"),
          cfg.get("app_name", "小程序"))
