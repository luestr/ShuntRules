#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

from common import (
    BUILTIN_POLICIES, load_yaml, parse_rule, read_rules, rule_key,
    rule_policy, sha256_file, upstream_url,
)


def bool_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def render_group(group):
    fields = [group["type"]]
    fields.extend(group.get("members", []))
    for key, value in group.get("params", {}).items():
        fields.append(f"{key}={value}")
    return f'{group["name"]} = ' + ",".join(map(str, fields))


def validate_manifest(root: Path, manifest: dict):
    errors, warnings = [], []
    groups = {g["name"] for g in manifest["proxy_groups"]}
    valid_policies = BUILTIN_POLICIES | groups
    commit = manifest["meta"]["upstream_commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        errors.append("upstream_commit 不是 40 位小写 Git SHA")

    seen = {}
    for item in manifest["local_rulesets"]:
        policy = item["policy"]
        if policy not in valid_policies:
            errors.append(f'本地规则集 {item["name"]} 引用未知策略：{policy}')
        path = root / item["file"]
        try:
            rules = read_rules(path)
        except Exception as exc:
            errors.append(str(exc))
            continue
        for lineno, raw, parts in rules:
            key = rule_key(parts)
            old = seen.get(key)
            if old and old["policy"] != policy:
                errors.append(
                    f'跨策略冲突：{key} 同时属于 {old["policy"]} '
                    f'({old["file"]}:{old["line"]}) 与 {policy} ({item["file"]}:{lineno})'
                )
            elif old:
                warnings.append(
                    f'重复规则：{key} 同属 {policy}，位于 '
                    f'{old["file"]}:{old["line"]} 与 {item["file"]}:{lineno}'
                )
            else:
                seen[key] = {"policy": policy, "file": item["file"], "line": lineno, "raw": raw}

    for item in manifest["remote_rulesets"]:
        if item["policy"] not in valid_policies:
            errors.append(f'远程规则集 {item["name"]} 引用未知策略：{item["policy"]}')
        audit = item.get("audit", {})
        if audit.get("min_rules", 0) < 1:
            errors.append(f'远程规则集 {item["name"]} 缺少有效 min_rules')
        if audit.get("max_rules", 0) < audit.get("min_rules", 0):
            errors.append(f'远程规则集 {item["name"]} 的 max_rules 小于 min_rules')

    for item in manifest["inline_rules"]:
        try:
            parts = parse_rule(item["rule"])
            policy = rule_policy(parts)
            if policy and policy not in valid_policies:
                errors.append(f'内联规则引用未知策略：{item["rule"]}')
        except Exception as exc:
            errors.append(str(exc))

    return errors, warnings


def selected_profiles(manifest, requested):
    profiles = manifest["profiles"]
    if requested == "all-release":
        return {k: v for k, v in profiles.items() if v.get("release", True)}
    if requested == "all":
        return profiles
    if requested not in profiles:
        raise ValueError(f"不存在的 profile：{requested}")
    return {requested: profiles[requested]}


def render_config(root: Path, manifest: dict, profile_name: str, mode: str, base_url: str | None):
    profile = manifest["profiles"][profile_name]
    meta = manifest["meta"]
    lines = [
        f'# Shadowrocket Enterprise v3.0 - {profile["title"]}',
        f'# Version: {meta["version"]}',
        f'# Generated: {meta["generated_date"]}',
        '# Source of truth: manifest.yaml',
        f'# Front rule mode: {mode}',
        f'# Upstream snapshot: {meta["upstream_repo"]}@{meta["upstream_commit"]}',
    ]
    for warning in profile.get("header_warnings", []):
        lines.append(f'# {warning}')
    lines.extend(['# 请替换导入，不要与旧配置合并。', '', '[General]'])

    general = dict(manifest["general_common"])
    general.update(profile.get("general_overrides", {}))
    for key in ["skip-proxy", "tun-excluded-routes"]:
        lines.append(f'{key} = {bool_value(general.pop(key))}')

    lines.extend([
        '',
        '# 国内直连使用大陆 DoH；备用境外 DoH 请求经默认代理发送；禁止 system 回退。',
        f'dns-server = {profile["dns-server"]}',
        f'fallback-dns-server = {profile["fallback-dns-server"]}',
        f'proxy-dns-server = {profile["proxy-dns-server"]}',
    ])
    for key, value in general.items():
        lines.append(f'{key} = {bool_value(value)}')
    lines.append(f'block-quic = {profile["block-quic"]}')

    lines.extend(['', '[Proxy]', '# 节点由当前订阅提供。', '', '[Proxy Group]'])
    for group in manifest["proxy_groups"]:
        lines.append(render_group(group))

    lines.extend(['', '[Rule]'])
    entries = []
    for item in manifest["inline_rules"]:
        entries.append((item["stage"], "inline", item))
    for item in manifest["local_rulesets"]:
        entries.append((item["stage"], "local", item))
    for item in manifest["remote_rulesets"]:
        entries.append((item["stage"], "remote", item))

    for _, kind, item in sorted(entries, key=lambda x: x[0]):
        if kind == "inline":
            lines.append(f'# Inline rule: {item.get("comment", item["rule"])}')
            lines.append(item["rule"])
        elif kind == "local":
            lines.append(f'# Local ruleset: {item["name"]} → {item["policy"]}')
            if mode == "inline":
                for _, raw, _ in read_rules(root / item["file"]):
                    lines.append(f'{raw},{item["policy"]}')
            elif mode == "remote":
                if not base_url:
                    raise ValueError("remote 模式必须提供 --base-url")
                url = base_url.rstrip("/") + "/" + item["file"]
                lines.append(f'RULE-SET,{url},{item["policy"]}')
            else:
                raise ValueError(mode)
        else:
            lines.append(f'# Remote ruleset: {item["name"]} → {item["policy"]}')
            lines.append(f'RULE-SET,{upstream_url(manifest, item["path"])},{item["policy"]}')

    lines.append(manifest["final_rule"])
    lines.extend(['', '[Host]', 'localhost = 127.0.0.1', ''])
    return "\n".join(lines)


def validate_generated(text: str, manifest: dict):
    errors = []
    sections = set()
    current = None
    group_names = {g["name"] for g in manifest["proxy_groups"]}
    policies = BUILTIN_POLICIES | group_names
    for lineno, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped
            sections.add(current)
            continue
        if current == "[Rule]" and stripped and not stripped.startswith("#"):
            parts = parse_rule(stripped)
            policy = rule_policy(parts)
            if policy and policy not in policies:
                errors.append(f"生成配置第 {lineno} 行引用未知策略：{policy}")
    missing = {"[General]", "[Proxy]", "[Proxy Group]", "[Rule]", "[Host]"} - sections
    if missing:
        errors.append(f"缺少配置段：{sorted(missing)}")
    if not re.search(r"(?m)^FINAL,PROXY$", text):
        errors.append("FINAL,PROXY 缺失或不在独立行")
    return errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--profile", default="all-release")
    parser.add_argument("--mode", choices=["inline", "remote"], default="inline")
    parser.add_argument("--base-url")
    parser.add_argument("--out-dir", default="build")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    manifest = load_yaml(root / "manifest.yaml")
    errors, warnings = validate_manifest(root, manifest)
    if errors:
        print(json.dumps({"ok": False, "errors": errors, "warnings": warnings}, ensure_ascii=False, indent=2))
        sys.exit(1)

    out_dir = root / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    outputs = []
    for name, profile in selected_profiles(manifest, args.profile).items():
        text = render_config(root, manifest, name, args.mode, args.base_url)
        generated_errors = validate_generated(text, manifest)
        if generated_errors:
            print(json.dumps({"ok": False, "errors": generated_errors}, ensure_ascii=False, indent=2))
            sys.exit(1)
        suffix = "Modular" if args.mode == "remote" else "Direct"
        path = out_dir / f'LOWERTOP-Enterprise-v3.0-{profile["title"]}-{suffix}.conf'
        path.write_text(text, encoding="utf-8")
        outputs.append({"profile": name, "file": str(path.relative_to(root)), "sha256": sha256_file(path)})

    report = {"ok": True, "version": manifest["meta"]["version"], "warnings": warnings, "outputs": outputs}
    (out_dir / "audit-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
