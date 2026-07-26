#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
import hashlib
import ipaddress
from pathlib import Path
import re
from typing import Any, Iterable

import requests
import yaml

ALLOWED_RULE_TYPES = {
    "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-WILDCARD",
    "IP-CIDR", "IP-CIDR6", "IP-ASN", "USER-AGENT", "URL-REGEX",
    "RULE-SET", "DOMAIN-SET", "GEOIP", "DST-PORT", "SRC-PORT",
    "SRC-IP", "PROTOCOL", "NETWORK", "SCRIPT", "PROCESS-NAME",
    "AND", "OR", "NOT", "FINAL"
}
BUILTIN_POLICIES = {
    "DIRECT", "PROXY", "REJECT", "REJECT-DROP", "REJECT-NO-DROP",
    "REJECT-200", "REJECT-IMG", "REJECT-TINYGIF", "REJECT-DICT",
    "REJECT-ARRAY"
}


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"YAML 根节点必须是对象：{path}")
    return data


def parse_rule(line: str, *, allow_unknown: bool = False) -> list[str] | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    parts = [part.strip() for part in stripped.split(",")]
    if len(parts) < 2:
        raise ValueError(f"规则字段不足：{line}")
    if parts[0].upper() not in ALLOWED_RULE_TYPES and not allow_unknown:
        raise ValueError(f"未知规则类型：{parts[0]} | {line}")
    parts[0] = parts[0].upper()
    return parts


def rule_policy(parts: list[str], default: str | None = None) -> str | None:
    if parts[0] == "FINAL":
        return parts[1] if len(parts) > 1 else default
    if default is not None:
        return default
    if len(parts) < 3:
        return None
    if parts[-1].lower() == "no-resolve" and len(parts) >= 4:
        return parts[-2]
    return parts[-1]


def rule_key(parts: list[str]) -> tuple[str, ...]:
    if parts[0] == "FINAL":
        return ("FINAL",)
    return (parts[0], parts[1].lower())


def read_rules(path: Path, *, allow_unknown: bool = False) -> list[tuple[int, str, list[str]]]:
    output = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        parts = parse_rule(line, allow_unknown=allow_unknown)
        if parts:
            output.append((lineno, line.strip(), parts))
    return output


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def upstream_url(manifest: dict[str, Any], path: str) -> str:
    meta = manifest["meta"]
    return (
        f'https://raw.githubusercontent.com/{meta["upstream_repo"]}/'
        f'{meta["upstream_commit"]}/{path}'
    )


def fetch_text(url: str, *, timeout: int = 30, session: requests.Session | None = None) -> tuple[str, bytes]:
    client = session or requests.Session()
    response = client.get(url, timeout=timeout, headers={"User-Agent": "LOWERTOP-v3-audit/1.0"})
    response.raise_for_status()
    content = response.content
    if content[:200].lstrip().lower().startswith((b"<!doctype html", b"<html")):
        raise ValueError(f"远程资源返回 HTML，而非规则文件：{url}")
    return response.text, content


@dataclass(frozen=True)
class CompiledRule:
    parts: list[str]
    policy: str
    source: str
    order: int
    raw: str


def _domain_suffix_matches(host: str, suffix: str) -> bool:
    host = host.rstrip(".").lower()
    suffix = suffix.lstrip(".").rstrip(".").lower()
    return host == suffix or host.endswith("." + suffix)


def matches(parts: list[str], case: dict[str, Any]) -> bool:
    kind = parts[0]
    value = parts[1] if len(parts) > 1 else ""
    host = str(case.get("host", "")).rstrip(".").lower()
    url = str(case.get("url", ""))

    if kind == "DOMAIN":
        return bool(host) and host == value.rstrip(".").lower()
    if kind == "DOMAIN-SUFFIX":
        return bool(host) and _domain_suffix_matches(host, value)
    if kind == "DOMAIN-KEYWORD":
        return bool(host) and value.lower() in host
    if kind == "DOMAIN-WILDCARD":
        return bool(host) and fnmatch(host, value.lower())
    if kind in {"IP-CIDR", "IP-CIDR6"}:
        target = case.get("ip")
        if not target:
            return False
        try:
            return ipaddress.ip_address(str(target)) in ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
    if kind == "IP-ASN":
        return str(case.get("asn", "")).upper().removeprefix("AS") == value.upper().removeprefix("AS")
    if kind == "USER-AGENT":
        return fnmatch(str(case.get("user_agent", "")), value)
    if kind == "URL-REGEX":
        try:
            return bool(url) and re.search(value, url) is not None
        except re.error:
            return False
    if kind == "GEOIP":
        return str(case.get("geoip", "")).upper() == value.upper()
    if kind == "DST-PORT":
        return str(case.get("port", "")) == value
    if kind == "PROTOCOL":
        return str(case.get("protocol", "")).upper() == value.upper()
    if kind == "FINAL":
        return True
    return False
