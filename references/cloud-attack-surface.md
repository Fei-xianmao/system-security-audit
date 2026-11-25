# 云暴露面检测（cloud_scanner 使用手册）

内置工具来自 cloud-vuln-skill（AGPLv3，见 scripts/cloud/LICENSE），面向云环境攻击面发现与凭据验证。两个阶段：**信息收集（无需凭证）→ 凭据利用（拿到 AK/SK 后）**。依赖：`pip install -r scripts/cloud/requirements.txt`（requests、boto3、pyyaml）。

## 命令一览

在 `scripts/cloud/` 下执行 `python cloud_scanner.py <命令>`：

| 命令 | 需要凭证 | 用途 |
|------|---------|------|
| `brute-s3 --keyword <词> [--threads 20] [--delay 0.1]` | 否 | 关键词拼 70+ 后缀（-prod/-backup/-secrets 等）并发 HEAD 爆破桶名；200=公开可列，403=存在非公开，404=不存在 |
| `check-bucket --name <桶> [--region r]` | 否 | 单桶三项检测：公开可列 / 公开可写（PUT 后自动清理）/ 公开可读 |
| `scan-bucket --url https://<桶>.s3.amazonaws.com` | 否 | 13 类敏感文件名匹配（.env、tfstate、id_rsa、*.sql、*.pem、.git/config 等）+ 小于 1MB 文件内容关键词（AKIA、DB_PASSWORD、Bearer 等）；不可列时自动切 30 个常见文件名爆破 |
| `probe-ssrf --target <URL> --param <参数名>` | 否 | 向参数注入 6 种元数据地址：AWS IMDSv1/IAM 角色、Azure、GCP、阿里云（100.100.100.200）、IPv6 映射绕过；响应含凭证关键词即命中 |
| `probe-k8s --node <IP>` | 否 | 7 端口未授权检测：6443/8080（API）、10250/10255（Kubelet）、2379（etcd）、4194（cAdvisor）、10256（kube-proxy） |
| `container-escape` | 否 | 容器内 11 项逃逸条件检测（docker.sock、privileged、CAP_SYS_ADMIN/SYS_PTRACE、hostPID、hostPath、SA Token、IMDS 可达等），**只检测不逃逸** |
| `exploit-creds --ak <AK> --sk <SK> [--token T]` | 是 | 五步：身份验证 → IAM 收集 → 23 个高危权限采样（CreatePolicyVersion、CreateUser、RunInstances、UpdateFunctionCode、StopLogging 等）→ 10 种危险组合提权路径分析 → S3 桶枚举与公开/加密检查 |

所有命令默认 JSON 输出，支持 `--format table`、`--output <file.json>`。

## SSRF 手动绕过变体

```
http://169.254.169.254@evil.com/        URL 解析差异
http://2852039166/                      十进制 IP
http://0xA9FEA9FE/                      十六进制
http://0177.0176.0251.0376/             八进制
302 重定向 → 元数据地址                  重定向绕过
域名 TTL=0 交替解析                     DNS Rebinding
PUT /latest/api/token 先取令牌          IMDSv2
```

## 人工辅助的泄露挖掘（AI 可指导不能代办）

1. **服务报错泄露**：对 Web/API 输入非预期参数，看 500 页、debug 输出、数据库错误中是否含内部 AK/SK 与端点。
2. **非正式镜像泄露**：购机时抓镜像列表 API，筛含 test/dev/internal 的镜像建实例，查 `/etc/profile`、`~/.bash_history`、`/opt/`。
3. **部署文档/工具包泄露**：GitHub 搜 `filename:.env` + 厂商关键词；官方 CLI 解压找 `.env`/`config.yml`；文档示例代码中的测试凭据。
4. **公开桶内容深挖**：日志里的 `Authorization:` 头、备份 SQL 里的口令 hash、CI/CD 产物里的构建参数。

## 护栏（必须遵守）

- 所有探测仅被动信息收集，不修改目标资源；须在书面授权范围内执行。
- `exploit-creds` 权限探测只做读操作（list/describe/get）与 DryRun 假参数，无副作用。
- S3 可写测试上传后立即删除；桶内容扫描只下载文件头部（≤10KB）。
- **实际利用（创建用户、改策略、起实例）执行前必须向用户确认。**
- 国内云厂商兼容：阿里云走 `probe-ssrf` payload 5（100.100.100.200）；OSS 桶名爆破需改 AWS 端点为厂商端点时，以 check-bucket/scan-bucket 对已知桶名为准。
