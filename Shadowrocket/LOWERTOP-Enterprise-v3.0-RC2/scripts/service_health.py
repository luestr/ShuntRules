#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time

import requests

from common import load_yaml


def check_one(session, item):
    started = time.perf_counter()
    result = {
        "id": item["id"], "service": item["service"], "policy": item["policy"],
        "url": item["url"], "status": "FAIL",
    }
    try:
        response = session.request(
            item.get("method", "GET"), item["url"], timeout=item.get("timeout", 12),
            allow_redirects=False, headers={"User-Agent": "LOWERTOP-v3-health/1.0"},
        )
        latency_ms = round((time.perf_counter() - started) * 1000, 1)
        status_code = response.status_code
        body_ok = True
        if item.get("body_contains"):
            body_ok = item["body_contains"] in response.text
        if status_code in item.get("healthy_status", []) and body_ok:
            state = "PASS"
        elif status_code in item.get("warning_status", []) or latency_ms > item.get("max_latency_ms", 999999):
            state = "WARN"
        else:
            state = "FAIL"
        result.update({
            "status": state, "http_status": status_code, "latency_ms": latency_ms,
            "location": response.headers.get("Location"), "body_check": body_ok,
        })
    except Exception as exc:
        result.update({"status": "FAIL", "error": str(exc), "latency_ms": round((time.perf_counter() - started) * 1000, 1)})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--proxy", help="HTTP/HTTPS/SOCKS5 代理，例如 socks5h://127.0.0.1:1080")
    parser.add_argument("--only", action="append", help="仅运行指定 health check id，可重复")
    parser.add_argument("--json-out", default="reports/service-health.json")
    parser.add_argument("--allow-warnings", action="store_true")
    parser.add_argument("--allow-failures", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    manifest = load_yaml(root / "manifest.yaml")
    checks = manifest.get("health_checks", [])
    if args.only:
        wanted = set(args.only)
        checks = [c for c in checks if c["id"] in wanted]
    session = requests.Session()
    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})

    results = [check_one(session, item) for item in checks]
    failures = [r for r in results if r["status"] == "FAIL"]
    warnings = [r for r in results if r["status"] == "WARN"]
    ok = not failures and (args.allow_warnings or not warnings)
    if args.allow_failures:
        ok = True
    report = {
        "ok": ok, "proxy": args.proxy, "note": "该工具验证指定代理路径或当前主机网络，不会自动遍历 iPhone 中的每个节点。",
        "summary": {"pass": sum(r["status"] == "PASS" for r in results), "warn": len(warnings), "fail": len(failures)},
        "results": results,
    }
    out = root / args.json_out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
