# v3.0 RC2 设备侧回归矩阵

## 必测网络

- 家庭 Wi-Fi
- 蜂窝数据
- Wi-Fi 与蜂窝相互切换后

## 核心路由

| 场景 | 预期 |
|---|---|
| `ios.chat.openai.com` | OpenAI-AI → AI → 日本或美国 |
| `ws.chatgpt.com` | OpenAI-AI → AI |
| `mask.icloud.com` | Apple-Global-AI → AI |
| `push.apple.com` | Apple-Core-Direct → DIRECT |
| `setup.icloud.com` | Apple-Core-Direct → DIRECT |
| Telegram 图片/视频 | Telegram 规则集 → Telegram |
| 未单独配置的国外网站 | FINAL → PROXY |
| 国内网站 | ChinaMax → DIRECT |
| 广告/追踪域名 | AdvertisingLite → REJECT |

## DNS 与出口

1. `dnsleaktest.com` 应命中 Probe-Proxy → PROXY。
2. 标准与扩展测试不应出现当前本地运营商或 Wi-Fi 路由器 DNS。
3. BrowserLeaks 的 Remote IP 与 WebRTC Public IP 应一致。
4. 正式版 IPv6 应不可用或显示 `n/a`。
5. Wi-Fi、蜂窝数据分别重复测试。

## 稳定性

- ChatGPT 连续对话 15 分钟，无地区不可用提示。
- Telegram 连续加载多个图片和视频，无明显卡顿。
- App Store 下载、iCloud 同步、Apple Push 正常。
- YouTube 高码率播放 10 分钟无频繁缓冲。
- 网络切换后无 DNS 查询长时间卡死。

## RC2 晋升 Stable 门槛

- 连续 72 小时未出现规则错误。
- Wi-Fi 与蜂窝 DNS 测试均无本地运营商泄漏。
- OpenAI、Apple、Telegram、流媒体全部符合预期策略。
- 无关键应用被 AdvertisingLite 误杀。
