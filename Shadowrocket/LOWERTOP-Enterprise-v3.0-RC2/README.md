# LOWERTOP Enterprise v3.0 RC2

本目录保存 Shadowrocket 企业级分流配置的声明式源文件、规则集、生成器、审计与回归测试。

## 推荐配置

- `build/LOWERTOP-Enterprise-v3.0-Performance-Direct.conf`：主力版本，允许 QUIC/HTTP3。
- `build/LOWERTOP-Enterprise-v3.0-Strict-Direct.conf`：稳定性回退版本。
- `experimental/LOWERTOP-Enterprise-v3.0-IPv6-SVCB-Experimental-Direct.conf`：仅用于 IPv6/SVCB 实验。

## 架构

- `manifest.yaml`：声明式单一数据源
- `rules/`：Probe、OpenAI、Apple Global、Apple Core 模块化规则
- `scripts/generate.py`：生成配置
- `scripts/regression.py`：首条命中回归
- `scripts/remote_audit.py`：远程规则审计
- `scripts/service_health.py`：服务端点健康检查
- `regression_cases.yaml`：回归测试用例

## 本地构建

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/generate.py --profile all-release --mode inline
python scripts/regression.py --offline
```

## 路由优先级

1. `captive.apple.com` → DIRECT
2. 检测站 → PROXY
3. OpenAI / ChatGPT → AI
4. Apple Global → AI
5. Apple Core → DIRECT
6. Telegram → Telegram
7. 流媒体 → 独立策略
8. AdvertisingLite → REJECT
9. Lan / ChinaMax → DIRECT
10. FINAL → PROXY

## DNS

- 国内 DoH 作为主 DNS
- Google / Cloudflare DoH 作为代理回退
- 禁止系统 DNS 回退
- 关闭 IPv6 的正式版
- 劫持常见明文 DNS 53
- UDP 不支持时 REJECT，不回落 DIRECT

完整原始工程与构建产物保存在同目录各子文件夹中。