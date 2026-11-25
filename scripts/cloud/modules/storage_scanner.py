"""
公开存储桶内容扫描 — 发现敏感文件（.env/credentials/tfstate/backup 等）
"""
import requests
import concurrent.futures
import re
from urllib.parse import urljoin

HEADERS = {'User-Agent': 'Mozilla/5.0 (compatible; cloud-vuln-skill/1.0)'}

# 内容关键词扫描时的最大下载大小（字节）
# 限制为 10KB 以避免下载大量敏感数据。匹配关键词通常只需文件头部。
MAX_KEYWORD_DOWNLOAD_BYTES = 10 * 1024

# ============================================================
# 敏感文件特征库
# ============================================================

SENSITIVE_PATTERNS = [
    # 凭证文件
    {
        'name': '.env 文件',
        'filenames': ['.env', '.env.local', '.env.production', '.env.development', '.env.backup'],
        'keywords': ['DB_PASSWORD=', 'DATABASE_URL=', 'REDIS_PASSWORD=', 'SECRET_KEY=',
                     'API_KEY=', 'ACCESS_KEY=', 'AWS_ACCESS_KEY_ID=', 'PRIVATE_KEY='],
        'severity': 'CRITICAL',
    },
    {
        'name': 'AWS 凭证文件',
        'filenames': ['credentials', 'credentials.csv', 'aws_credentials', '.aws/credentials'],
        'keywords': ['aws_access_key_id', 'aws_secret_access_key', 'AKIA', 'ASIA'],
        'severity': 'CRITICAL',
    },
    {
        'name': 'Terraform State 文件',
        'filenames': ['terraform.tfstate', 'terraform.tfstate.backup', 'tfstate', '*.tfstate'],
        'keywords': ['"password"', '"secret"', '"access_key"', '"private_key"', '"token"'],
        'severity': 'CRITICAL',
    },
    {
        'name': 'CloudFormation 模板含密钥',
        'filenames': ['*.yaml', '*.yml', '*.json', 'template.yaml', 'template.json'],
        'keywords': ['AccessKey', 'SecretAccessKey', 'DBPassword', 'MasterUserPassword'],
        'severity': 'CRITICAL',
    },
    {
        'name': '数据库备份',
        'filenames': ['*.sql', '*.sql.gz', '*.dump', '*.dmp', 'backup.sql', 'dump.sql', 'prod-dump.sql'],
        'keywords': ['CREATE TABLE', 'INSERT INTO', 'CREATE DATABASE'],
        'severity': 'CRITICAL',
    },
    {
        'name': 'SSH 私钥',
        'filenames': ['id_rsa', 'id_ed25519', 'id_ecdsa', '*.pem', '*.key', 'ssh_host_rsa_key'],
        'keywords': ['-----BEGIN RSA PRIVATE KEY-----', '-----BEGIN OPENSSH PRIVATE KEY-----',
                     '-----BEGIN EC PRIVATE KEY-----'],
        'severity': 'CRITICAL',
    },
    {
        'name': '配置文件含密码',
        'filenames': ['config.yml', 'config.yaml', 'config.json', 'settings.py', 'settings.json',
                      'app.config', 'application.properties', 'web.config'],
        'keywords': ['password', 'passwd', 'secret', 'connectionString', 'connection_string'],
        'severity': 'HIGH',
    },
    {
        'name': 'CI/CD 配置文件',
        'filenames': ['.gitlab-ci.yml', '.github/workflows/*.yml', 'Jenkinsfile', '.travis.yml'],
        'keywords': ['AWS_ACCESS_KEY_ID', 'DOCKER_PASSWORD', 'NPM_TOKEN', 'PYPI_TOKEN', 'secret'],
        'severity': 'HIGH',
    },
    {
        'name': 'Docker 相关文件',
        'filenames': ['Dockerfile', 'docker-compose.yml', '.docker/config.json'],
        'keywords': ['ENV PASSWORD', 'ENV SECRET', 'ENV KEY', '"auth":'],
        'severity': 'MEDIUM',
    },
    {
        'name': 'K8s Secret 文件',
        'filenames': ['secret.yaml', 'secrets.yaml', 'secrets.yml'],
        'keywords': ['kind: Secret', 'data:', 'stringData:'],
        'severity': 'HIGH',
    },
    {
        'name': '日志文件',
        'filenames': ['*.log', 'access.log', 'error.log', 'debug.log', 'application.log'],
        'keywords': ['password=', 'token=', 'Authorization:', 'Cookie:', 'AKIA', 'Bearer '],
        'severity': 'MEDIUM',
    },
    {
        'name': '备份归档',
        'filenames': ['*.tar.gz', '*.zip', '*.tar', '*.7z', 'backup.tar.gz', 'backup.zip'],
        'keywords': [],
        'severity': 'MEDIUM',
    },
    {
        'name': 'Office 文档',
        'filenames': ['*.xlsx', '*.xls', '*.docx', '*.pdf', '*.csv'],
        'keywords': [],
        'severity': 'LOW',
    },
]

# 文件名爆破字典
FILE_BRUTE_LIST = [
    '.env', '.env.local', '.env.production', '.env.backup',
    'credentials', 'credentials.csv',
    'terraform.tfstate', 'terraform.tfstate.backup',
    'id_rsa', 'id_ed25519',
    'backup.sql', 'dump.sql', 'prod-dump.sql',
    'config.yml', 'config.yaml', 'config.json',
    '.git/config', '.git/HEAD',
    'docker-compose.yml', 'Dockerfile',
    '.bash_history', '.zsh_history',
    'package.json', 'composer.json', 'requirements.txt',
    'wp-config.php', '.htpasswd',
    'robots.txt', 'sitemap.xml',
]


def scan_public_bucket(bucket_endpoint, max_files=100, threads=10):
    """
    扫描公开桶的内容，发现敏感文件。
    bucket_endpoint: 'https://bucket-name.s3.amazonaws.com' 或同类的 OSS/Blob URL
    """
    findings = []

    # Step 1: 如果能列出，先获取文件列表
    file_list = _list_bucket_files(bucket_endpoint, max_files)

    if file_list:
        # Step 2: 对文件列表进行敏感内容匹配
        findings = _scan_file_list(bucket_endpoint, file_list, threads)

    # Step 3: 如果不能列出，爆破常见文件名
    if not file_list:
        findings = _brute_common_files(bucket_endpoint, threads)

    return findings


def _list_bucket_files(endpoint, max_files):
    """尝试列出桶内文件"""
    files = []
    params = {'max-keys': str(min(max_files, 1000))}
    next_marker = None

    while len(files) < max_files:
        if next_marker:
            params['marker'] = next_marker

        try:
            r = requests.get(endpoint, params=params, headers=HEADERS, timeout=15)
            if r.status_code == 200:
                keys = re.findall(r'<Key>([^<]+)</Key>', r.text)
                sizes = re.findall(r'<Size>(\d+)</Size>', r.text)
                last_mod = re.findall(r'<LastModified>([^<]+)</LastModified>', r.text)

                for i, key in enumerate(keys):
                    size = int(sizes[i]) if i < len(sizes) else 0
                    mod = last_mod[i] if i < len(last_mod) else ''
                    files.append({'key': key, 'size': size, 'last_modified': mod})

                # 检查是否有截断
                if '<IsTruncated>true</IsTruncated>' in r.text:
                    next_marker_match = re.search(r'<NextMarker>([^<]+)</NextMarker>', r.text)
                    if next_marker_match:
                        next_marker = next_marker_match.group(1)
                    else:
                        break
                else:
                    break
            else:
                break
        except:
            break

    return files


def _scan_file_list(endpoint, file_list, threads):
    """对文件列表进行敏感特征匹配"""
    findings = []
    matched_keys = set()

    for pattern in SENSITIVE_PATTERNS:
        for f in file_list:
            key = f['key']
            # 文件名匹配
            if _match_filename(key, pattern['filenames']):
                if key not in matched_keys:
                    matched_keys.add(key)
                    findings.append({
                        'type': pattern['name'],
                        'key': key,
                        'size': f['size'],
                        'last_modified': f['last_modified'],
                        'severity': pattern['severity'],
                        'match_type': 'filename',
                        'url': urljoin(endpoint, key),
                    })

    # 并发抽取小文件做关键词匹配
    # 只下载 MAX_KEYWORD_DOWNLOAD_BYTES 以内的文件，避免大规模数据访问
    small_files = [f for f in file_list if 0 < f['size'] < MAX_KEYWORD_DOWNLOAD_BYTES and f['key'] not in matched_keys]

    def check_keywords(file_info):
        key = file_info['key']
        results = []
        try:
            r = requests.get(urljoin(endpoint, key), headers=HEADERS, timeout=10, stream=True)
            if r.status_code == 200:
                # 只读取前 MAX_KEYWORD_DOWNLOAD_BYTES 字节
                content = r.raw.read(MAX_KEYWORD_DOWNLOAD_BYTES, decode_content=True)
                if isinstance(content, bytes):
                    content = content.decode('utf-8', errors='replace')
                content = content[:MAX_KEYWORD_DOWNLOAD_BYTES]
                for pattern in SENSITIVE_PATTERNS:
                    for kw in pattern.get('keywords', []):
                        if kw.lower() in content.lower():
                            results.append({
                                'type': pattern['name'],
                                'key': key,
                                'size': file_info['size'],
                                'severity': pattern['severity'],
                                'match_type': 'keyword',
                                'keyword': kw,
                                'url': urljoin(endpoint, key),
                            })
                            break  # 每个文件每个 pattern 只报一次
        except:
            pass
        return results

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_keywords, f) for f in small_files[:50]]
        for future in concurrent.futures.as_completed(futures):
            findings.extend(future.result())

    return findings


def _brute_common_files(endpoint, threads):
    """不能列出桶时，爆破常见文件名"""
    findings = []

    def probe_file(filename):
        url = urljoin(endpoint, filename)
        try:
            r = requests.get(url, headers=HEADERS, timeout=8, stream=True)
            if r.status_code == 200:
                # 只读取前 MAX_KEYWORD_DOWNLOAD_BYTES 用于关键词匹配
                raw = r.raw.read(MAX_KEYWORD_DOWNLOAD_BYTES, decode_content=True)
                content = raw.decode('utf-8', errors='replace') if isinstance(raw, bytes) else raw
                content = content[:MAX_KEYWORD_DOWNLOAD_BYTES]
                # 匹配敏感类型
                for pattern in SENSITIVE_PATTERNS:
                    if _match_filename(filename, pattern['filenames']):
                        return {
                            'type': pattern['name'],
                            'key': filename,
                            'size': len(content),
                            'severity': pattern['severity'],
                            'match_type': 'bruted',
                            'url': url,
                        }
                # 匹配关键词
                for pattern in SENSITIVE_PATTERNS:
                    for kw in pattern.get('keywords', []):
                        if kw.lower() in content.lower():
                            return {
                                'type': pattern['name'],
                                'key': filename,
                                'size': len(content),
                                'severity': pattern['severity'],
                                'match_type': 'keyword',
                                'keyword': kw,
                                'url': url,
                            }
        except:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(probe_file, f): f for f in FILE_BRUTE_LIST}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    return findings


def _match_filename(key, patterns):
    """通配符文件名匹配"""
    import fnmatch
    basename = key.split('/')[-1]
    for pattern in patterns:
        if fnmatch.fnmatch(basename, pattern) or fnmatch.fnmatch(key, pattern):
            return True
    return False


# ============================================================
# Azure Blob 公开扫描适配
# ============================================================

def scan_azure_blob(storage_account, container):
    """扫描 Azure Blob 容器的公开暴露"""
    url = f'https://{storage_account}.blob.core.windows.net/{container}'
    findings = []

    try:
        r = requests.get(f'{url}?restype=container&comp=list', headers=HEADERS, timeout=10)
        if r.status_code == 200:
            findings.append({
                'type': 'Public Azure Blob Container',
                'url': url,
                'severity': 'CRITICAL',
                'detail': '容器公开列出',
            })
            # 提取文件名
            blobs = re.findall(r'<Name>([^<]+)</Name>', r.text)
            for blobs_chunk in [blobs[i:i+20] for i in range(0, min(len(blobs), 100), 20)]:
                for blob in blobs_chunk:
                    blob_url = f'{url}/{blob}'
                    # 检查是否有敏感文件名
                    basename = blob.split('/')[-1]
                    for pattern in SENSITIVE_PATTERNS:
                        if _match_filename(basename, pattern['filenames']):
                            findings.append({
                                'type': pattern['name'],
                                'key': blob,
                                'url': blob_url,
                                'severity': pattern['severity'],
                            })
    except Exception as e:
        findings.append({'error': str(e)})

    return findings


def scan_gcp_bucket(bucket_name):
    """扫描 GCP Storage 桶的公开暴露"""
    url = f'https://storage.googleapis.com/storage/v1/b/{bucket_name}/o'
    findings = []

    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            data = r.json()
            items = data.get('items', [])
            findings.append({
                'type': 'Public GCP Storage Bucket',
                'bucket': bucket_name,
                'severity': 'CRITICAL',
                'item_count': len(items),
            })
            for item in items[:50]:
                name = item.get('name', '')
                for pattern in SENSITIVE_PATTERNS:
                    if _match_filename(name, pattern['filenames']):
                        findings.append({
                            'type': pattern['name'],
                            'key': name,
                            'severity': pattern['severity'],
                            'url': f'https://storage.googleapis.com/{bucket_name}/{name}',
                        })
    except:
        pass

    return findings
