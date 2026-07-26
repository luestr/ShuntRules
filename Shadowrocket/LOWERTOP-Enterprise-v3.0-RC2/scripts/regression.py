#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from urllib.parse import urlparse

from common import CompiledRule, fetch_text, load_yaml, matches, parse_rule, rule_policy


def cache_name(url: str) -> str:
    parsed = urlparse(url)
    return (parsed.path.strip("/").replace("/", "__") or "rules.list")


def load_remote(url: str, cache_dir: Path, offline: bool) -> str | None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = cache_dir / cache_name(url)
    if path.exists():
        return path.read_text(encoding="utf-8")
    if offline:
        return None
    text, _ = fetch_text(url, timeout=60)
    path.write_text(text, encoding="utf-8")
    return text


def compile_config(config: Path, cache_dir: Path, offline: bool):
    compiled = []
    in_rules = False
    source = "config"
    order = 0
    skipped_remote = []

    for line in config.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[Rule]":
            in_rules = True
            continue
        if in_rules and stripped.startswith("[") and stripped.endswith("]"):
            break
        if not in_rules or not stripped:
            continue
        if stripped.startswith("#"):
            if stripped.startswith("# Local ruleset:"):
                source = stripped.removeprefix("# Local ruleset:").strip().split(" → ", 1)[0]
            elif stripped.startswith("# Remote ruleset:"):
                source = stripped.removeprefix("# Remote ruleset:").strip().split(" → ", 1)[0]
            elif stripped.startswith("# Inline rule:"):
                source = "Inline rule"
            continue

        parts = parse_rule(stripped)
        if parts[0] == "RULE-SET":
            url = parts[1]
            policy = rule_policy(parts)
            remote_text = load_remote(url, cache_dir, offline)
            if remote_text is None:
                skipped_remote.append(url)
                continue
            for remote_line in remote_text.splitlines():
                remote_parts = parse_rule(remote_line, allow_unknown=True)
                if not remote_parts or remote_parts[0] == "RULE-SET":
                    continue
                order += 1
                compiled.append(CompiledRule(remote_parts, policy, source, order, remote_line.strip()))
            continue

        policy = rule_policy(parts)
        if not policy:
            raise ValueError(f"无法识别规则策略：{stripped}")
        order += 1
        compiled.append(CompiledRule(parts, policy, source if parts[0] != "FINAL" else "FINAL", order, stripped))

    return compiled, skipped_remote


def first_match(rules, case):
    for rule in rules:
        if matches(rule.parts, case):
            return rule
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--config", default="build/LOWERTOP-Enterprise-v3.0-Performance-Direct.conf")
    parser.add_argument("--cases", default="regression_cases.yaml")
    parser.add_argument("--cache-dir", default=".cache/remote-rules")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--online", action="store_true")
    mode.add_argument("--offline", action="store_true")
    parser.add_argument("--json-out", default="reports/regression.json")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    offline = not args.online
    rules, skipped = compile_config(root / args.config, root / args.cache_dir, offline)
    cases = load_yaml(root / args.cases)["cases"]
    results, failures, skipped_cases = [], [], []

    for case in cases:
        if case.get("requires_remote", False) and offline:
            skipped_cases.append(case["name"])
            continue
        hit = first_match(rules, case)
        if hit is None:
            result = {"name": case["name"], "ok": False, "error": "无匹配规则"}
        else:
            expected_source = case.get("expected_source_contains")
            ok = hit.policy == case["expected_policy"] and (
                not expected_source or expected_source.lower() in hit.source.lower()
            )
            result = {
                "name": case["name"], "ok": ok, "host": case.get("host"),
                "expected_policy": case["expected_policy"], "actual_policy": hit.policy,
                "expected_source_contains": expected_source, "actual_source": hit.source,
                "matched_rule": hit.raw, "order": hit.order,
            }
        results.append(result)
        if not result["ok"]:
            failures.append(result)

    report = {
        "ok": not failures,
        "mode": "online" if args.online else "offline",
        "config": args.config,
        "compiled_rule_count": len(rules),
        "skipped_remote_urls": skipped,
        "skipped_cases": skipped_cases,
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
