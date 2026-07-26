# 远程规则审计

运行：

```bash
python scripts/remote_audit.py
```

审计固定 Git Commit、下载内容类型、文件大小、规则数量、未知规则类型、解析错误与 SHA-256。在线审计结果写入 `reports/remote-audit.json`，缓存写入 `.cache/remote-rules/`。
