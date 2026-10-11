"""Какие имена SNI шлюз готов прокидывать дальше."""

from __future__ import annotations

import ipaddress

DEFAULT_HOSTS: tuple[str, ...] = (
    "chatgpt.com",
    "*.chatgpt.com",
    "openai.com",
    "*.openai.com",
    "oaistatic.com",
    "*.oaistatic.com",
    "oaiusercontent.com",
    "*.oaiusercontent.com",
    "anthropic.com",
    "*.anthropic.com",
    "claude.ai",
    "*.claude.ai",
    "claude.com",
    "*.claude.com",
)


def normalize_host(host: str) -> str:
    name = host.strip().lower().rstrip(".")
    if not name or len(name) > 253 or "/" in name or " " in name or "\\" in name:
        raise ValueError("некорректное имя")
    try:
        name = name.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("некорректное имя") from exc
    labels = name.split(".")
    if len(labels) < 2:
        raise ValueError("некорректное имя")
    for label in labels:
        if not label or len(label) > 63 or label.startswith("-") or label.endswith("-"):
            raise ValueError("некорректное имя")
        if not all(character.isalnum() or character == "-" for character in label):
            raise ValueError("некорректное имя")
    return name


def host_allowed(host: str, patterns: list[str]) -> bool:
    try:
        normalized = normalize_host(host)
    except ValueError:
        return False
    for pattern in patterns:
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if normalized.endswith(suffix) and normalized != suffix[1:]:
                return True
        elif normalized == pattern:
            return True
    return False


def normalize_ip(raw: str) -> str:
    address = ipaddress.ip_address(raw.split("%", 1)[0])
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return str(address)


def destination_allowed(ip: str, *, allow_private: bool, deny_ips: set[str]) -> bool:
    address = ipaddress.ip_address(normalize_ip(ip))
    if str(address) in deny_ips:
        return False
    if address.is_multicast or address.is_unspecified:
        return False
    if allow_private:
        return True
    return address.is_global
