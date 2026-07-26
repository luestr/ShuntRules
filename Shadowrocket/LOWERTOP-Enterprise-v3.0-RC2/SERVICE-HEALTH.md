# 服务级健康检查

运行当前网络检测：

```bash
python scripts/service_health.py --allow-warnings
```

通过代理路径检测：

```bash
python scripts/service_health.py --proxy socks5h://127.0.0.1:1080 --allow-warnings
```

覆盖 OpenAI、Telegram、Apple Core、YouTube、Netflix、Disney+、MAX 与 Spotify 的 TLS/HTTP 状态、重定向和响应延迟。该工具不会自动遍历 iPhone Shadowrocket 中的每个节点，也不能代替账号级地区可用性验证。
