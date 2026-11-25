#!/usr/bin/env python3
"""
Cloud Vulnerability Discovery & Exploitation Scanner
纯漏洞挖掘与利用，不做合规审计

用法:
    # 信息收集（无需凭证）
    python cloud_scanner.py brute-s3 --keyword 公司名
    python cloud_scanner.py check-bucket --name 桶名
    python cloud_scanner.py scan-bucket --url 桶URL
    python cloud_scanner.py probe-ssrf --target URL --param url
    python cloud_scanner.py probe-k8s --node IP
    python cloud_scanner.py container-escape

    # 凭据利用（需要 AK/SK）
    python cloud_scanner.py exploit-creds --ak AKIA... --sk ...
"""

import argparse
import json
import os
import sys
import io
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))

# Windows GBK 终端修复
if sys.stdout.encoding and 'gbk' in sys.stdout.encoding.lower():
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')


def main():
    parser = argparse.ArgumentParser(description='Cloud Vulnerability Discovery & Exploitation')
    subparsers = parser.add_subparsers(dest='command', help='命令')

    # === brute-s3 ===
    p = subparsers.add_parser('brute-s3', help='S3 桶名爆破枚举')
    p.add_argument('--keyword', required=True, help='公司名/关键词')
    p.add_argument('--threads', type=int, default=15)
    p.add_argument('--delay', type=float, default=None,
                   help='请求间隔秒数（默认 0.05，增大可避免触发云端限流）')
    p.add_argument('--format', default='json', choices=['json', 'table'])

    # === check-bucket ===
    p = subparsers.add_parser('check-bucket', help='检查桶的公开读写状态')
    p.add_argument('--name', required=True, help='桶名')
    p.add_argument('--region', default=None)

    # === scan-bucket ===
    p = subparsers.add_parser('scan-bucket', help='扫描公开桶中的敏感文件')
    p.add_argument('--url', required=True, help='桶的公开 URL')
    p.add_argument('--max-files', type=int, default=100)
    p.add_argument('--threads', type=int, default=10)

    # === probe-ssrf ===
    p = subparsers.add_parser('probe-ssrf', help='探测 SSRF→IMDS 凭证窃取')
    p.add_argument('--target', required=True, help='目标 URL')
    p.add_argument('--param', default='url', help='SSRF 参数名')

    # === probe-k8s ===
    p = subparsers.add_parser('probe-k8s', help='探测 K8s 节点未授权访问')
    p.add_argument('--node', required=True, help='节点 IP')

    # === container-escape ===
    subparsers.add_parser('container-escape', help='检测容器逃逸条件')

    # === exploit-creds ===
    p = subparsers.add_parser('exploit-creds', help='AK/SK 验证与权限枚举')
    p.add_argument('--ak', required=True, help='AWS Access Key ID')
    p.add_argument('--sk', required=True, help='AWS Secret Access Key')
    p.add_argument('--token', default=None, help='Session Token（临时凭证）')
    p.add_argument('--output', '-o', default=None)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # ================================================================
    # brute-s3
    # ================================================================
    if args.command == 'brute-s3':
        from modules.discovery import brute_s3_buckets, S3_SUFFIXES
        buckets = brute_s3_buckets(args.keyword, threads=args.threads, delay=args.delay)

        if args.format == 'table':
            print(f"{'Bucket':<50} {'Public':<8} {'Region':<20}")
            print('-' * 80)
            for b in buckets:
                print(f"{b['name']:<50} {'YES' if b['public'] else 'no':<8} {b.get('region', 'N/A'):<20}")
        else:
            print(json.dumps(buckets, indent=2, ensure_ascii=False))

        public_count = sum(1 for b in buckets if b.get('public'))
        print(f"\n[+] 发现 {len(buckets)} 个桶（{len(S3_SUFFIXES)} 变体），{public_count} 个公开")
        return

    # ================================================================
    # check-bucket
    # ================================================================
    if args.command == 'check-bucket':
        from modules.discovery import probe_bucket_public
        result = probe_bucket_public(args.name, region=args.region)
        print(json.dumps(result, indent=2, ensure_ascii=False))

        if result.get('public_write'):
            print("\n🔴 CRITICAL: 桶公开可写！可作为供应链攻击跳板。")
        elif result.get('public_list'):
            print("\n🟠 HIGH: 桶公开可列目录。运行 scan-bucket 扫描敏感文件。")
        elif result.get('public_read'):
            print("\n🟡 MEDIUM: 部分文件公开可读。")
        else:
            print("\n✓ 桶未公开暴露。")
        return

    # ================================================================
    # scan-bucket
    # ================================================================
    if args.command == 'scan-bucket':
        from modules.storage_scanner import scan_public_bucket
        findings = scan_public_bucket(args.url, max_files=args.max_files, threads=args.threads)

        if not findings:
            print("[*] 未发现敏感文件")
            return

        for f in findings:
            sev = f['severity']
            icon = '🔴' if sev == 'CRITICAL' else '🟠' if sev == 'HIGH' else '🟡' if sev == 'MEDIUM' else '🔵'
            print(f"{icon} [{sev}] {f['type']}")
            print(f"    文件: {f['key']}")
            print(f"    URL:  {f['url']}")
            if f.get('keyword'):
                print(f"    命中: {f['keyword']}")
            if f.get('size'):
                print(f"    大小: {f['size']} bytes")
            print()

        critical = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high = sum(1 for f in findings if f['severity'] == 'HIGH')
        print(f"[+] 发现 {len(findings)} 个敏感文件（🔴{critical} 🟠{high}）")
        return

    # ================================================================
    # probe-ssrf
    # ================================================================
    if args.command == 'probe-ssrf':
        from modules.discovery import probe_imds
        findings = probe_imds(args.target, param_name=args.param)

        vulns = [f for f in findings if f.get('vulnerable')]
        safes = [f for f in findings if not f.get('vulnerable')]

        print("=" * 60)
        for f in safes:
            print(f"  ✓ SAFE    {f['probe']} — 未检测到 IMDS 响应")
        for f in vulns:
            print(f"  ⚠ VULN    {f['probe']}")
            print(f"            证据: {f.get('evidence', '')}")
        print("=" * 60)
        print(f"\n[+] {len(vulns)}/{len(findings)} 项存在 SSRF→IMDS 漏洞")

        if vulns:
            print("\n下一步：如果能获取 IAM 凭证，运行 exploit-creds 验证权限。")
        return

    # ================================================================
    # probe-k8s
    # ================================================================
    if args.command == 'probe-k8s':
        from modules.discovery import scan_k8s_node
        findings = scan_k8s_node(args.node)

        if not findings:
            print(f"[*] {args.node} 未发现 K8s 端口开放")
            return

        unauth = [f for f in findings if f.get('unauthorized')]
        auth = [f for f in findings if not f.get('unauthorized')]

        for f in unauth:
            print(f"⚠ UNAUTH  {f['url']} ({f['service']})")
        for f in auth:
            print(f"🔒 AUTH    {f['url']} ({f['service']})")

        print(f"\n[+] 发现 {len(unauth)} 个未授权端点")
        if unauth:
            print("下一步：尝试列出 Pod / Secret / 创建特权 Pod。")
        return

    # ================================================================
    # container-escape
    # ================================================================
    if args.command == 'container-escape':
        from modules.discovery import detect_container_escape_conditions
        findings = detect_container_escape_conditions()

        if not findings:
            print("[✓] 未发现明显逃逸条件。")
            return

        criticals = [f for f in findings if f['severity'] == 'CRITICAL']
        others = [f for f in findings if f['severity'] != 'CRITICAL']

        for f in criticals:
            print(f"🔴 [{f['severity']}] {f['name']}")
            print(f"    {f['impact']}")
            print()
        for f in others:
            print(f"🟠 [{f['severity']}] {f['name']}")
            print(f"    {f['impact']}")
            print()

        print(f"[+] 发现 {len(criticals)} 个严重逃逸条件，{len(others)} 个高危。")
        return

    # ================================================================
    # exploit-creds
    # ================================================================
    if args.command == 'exploit-creds':
        from modules.exploitation import validate_aws_credentials, enumerate_s3_buckets

        print("[*] 正在验证 AK/SK...")
        result = validate_aws_credentials(args.ak, args.sk, args.token)

        if args.output:
            os.makedirs(os.path.dirname(os.path.abspath(args.output)) or '.', exist_ok=True)
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False, default=str)
            print(f"[✓] 详细结果已保存: {args.output}")

        # --- 打印可读摘要 ---
        if not result.get('valid'):
            print(f"\n✗ 凭证无效")
            print(f"  错误: {result.get('error', 'unknown')}")
            return

        print(f"\n{'='*60}")
        print(f"✓ 凭证有效")
        print(f"{'='*60}")
        print(f"  账户ID:  {result['account_id']}")
        print(f"  身份:    {result['identity']}")
        print(f"  类型:    {result['user_type']}")
        print(f"  MFA:     {'✓ 已启用' if result['mfa_enabled'] else '✗ 未启用'}")

        if result['attached_policies']:
            print(f"\n  附加策略:")
            for p in result['attached_policies']:
                print(f"    • {p}")

        if result['groups']:
            print(f"\n  所属组: {', '.join(result['groups'])}")

        if result['dangerous_permissions']:
            print(f"\n{'='*60}")
            print(f"高危权限 ({len(result['dangerous_permissions'])} 项):")
            print(f"{'='*60}")
            for p in result['dangerous_permissions']:
                if p['type'] == 'write':
                    print(f"  ✏️  {p['permission']}")
                    print(f"     {p['description']}")
                    if p.get('note'):
                        print(f"     ⚠ {p['note']}")
                else:
                    print(f"  👀 {p['permission']}: {p['description']}")

        if result['privilege_escalation']:
            print(f"\n{'='*60}")
            print(f"⚠ 权限提升路径 ({len(result['privilege_escalation'])} 条):")
            print(f"{'='*60}")
            for e in result['privilege_escalation']:
                print(f"  🔴 {e['description']}")
                print(f"     需要: {', '.join(e['combo'])}")

        # S3 枚举
        print(f"\n[*] 正在枚举 S3 桶...")
        try:
            buckets = enumerate_s3_buckets(args.ak, args.sk, args.token)
            risky = [b for b in buckets if b.get('public') or not b.get('encrypted')]
            if risky:
                print(f"  ⚠ {len(risky)}/{len(buckets)} 个桶存在风险:")
                for b in risky:
                    issues = []
                    if b.get('public'):
                        issues.append('公开')
                    if not b.get('encrypted'):
                        issues.append('未加密')
                    print(f"    • {b['name']}: {', '.join(issues)}")
            else:
                print(f"  ✓ {len(buckets)} 个桶，状态正常")
        except Exception as e:
            print(f"  ✗ S3 枚举失败: {e}")

        if not result.get('dangerous_permissions') and not result.get('privilege_escalation'):
            print(f"\n[!] 未发现高危权限或提权路径。此凭证权限有限。")

        print(f"\n{'='*60}")
        print(f"⚠ 以上仅为权限探测（读操作）。")
        print(f"如需实际利用（创建用户/修改策略/CreateInstance 等）请向我确认。")
        return


if __name__ == '__main__':
    main()
