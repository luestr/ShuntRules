#!/usr/bin/env python3
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import sys

import requests

from common import ALLOWED_RULE_TYPES, fetch_text, load_yaml, parse_rule, sha256_bytes, upstream_url


def filename_for(item):
    return f'{item["name"]}.list'


def audit_one(manifest, item, cache_dir: Path, session: requests.Session):
    url = upstream_url(manifest, item["path"])
    expected_commit = manifest["meta"]["upstream_commit"]
    audit = item.get("audit", {})
    result = {"name": item["name"], "url": url, "policy": item["policy"], "ok": False}

    if audit.get("require_commit_pin", True) and f'/{expected_commit}/' not in url:
        result["error"] = "URL 未固定到 manifest 的 commit"
        return result

    try:
        text, content = fetch_text(url, timeout=90, session=session)
    except Exception as exc:
        result["error"] = f"下载失败：{exc}"
        return result

    if len(content) > audit.get("max_bytes", 100_000_000):
        result["error"] = f'文件过大：{len(content)} bytes'
        return result

    counts = Counter()
    unknown = Counter()
    invalid_lines = []
    rule_count = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            parts = parse_rule(stripped, allow_unknown=True)
        except Exception as exc:
            invalid_lines.append({"line": lineno, "content": stripped[:200], "error": str(exc)})
            continue
        if not parts:
            continue
        if parts[0] not in ALLOWED_RULE_TYPES:
            unknown[parts[0]] += 1
        else:
            counts[parts[0]] += 1
            rule_count += 1

    min_rules = audit.get("min_rules", 1)
    max_rules = audit.get("max_rules", 10**9)
    errors = []
    if not min_rules <= rule_count <= max_rules:
        errors.append(f"规则数 {rule_count} 不在 [{min_rules}, {max_rules}] 内")
    if invalid_lines:
        errors.append(f"存在 {len(invalid_lines)} 条无法解析的规则")
    if unknown:
        errors.append(f"存在未知规则类型：{dict(unknown)}")

    cache_dir.mkdir(parents=True, exist_ok=True)
    cache_path = cache_dir / filename_for(item)
    cache_path.write_bytes(content)
    result.update({
        "ok": not errors,
        "bytes": len(content),
        "sha256": sha256_bytes(content),
        "rule_count": rule_count,
        "rule_types": dict(counts),
        "unknown_types": dict(unknown),
        "invalid_lines": invalid_lines[:20],
        "cache_file": str(cache_path),
        "errors": errors,
    })
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--cache-dir", default=".cache/remote-rules")
    parser.add_argument("--json-out", default="reports/remote-audit.json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    manifest = load_yaml(root / "manifest.yaml")
    session = requests.Session()
    results = [audit_one(manifest, item, root / args.cache_dir, session) for item in manifest["remote_rulesets"]]
    failures = [item for item in results if not item["ok"]]
    report = {
        "ok": not failures,
        "upstream_commit": manifest["meta"]["upstream_commit"],
        "results": results,
        "failures": failures,
    }
    out = root / args.json_out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
