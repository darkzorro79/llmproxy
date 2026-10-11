"""Разбор config.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from llmproxy.allowlist import parse_networks
from llmproxy.hosts import DEFAULT_HOSTS, normalize_host, normalize_ip

_PLACEHOLDER_SECRETS = {"", "change-me", "replace-me"}
_MIN_SECRET = 16


@dataclass(frozen=True)
class Config:
    enroll_host: str
    enroll_port: int
    proxy_host: str
    proxy_port: int
    secret: str
    ttl_days: int
    allowlist_path: Path
    permanent: tuple[str, ...]
    upstream_port: int
    hosts: list[str]
    allow_private_upstreams: bool
    deny_ips: set[str]
    hello_timeout: float
    connect_timeout: float


def load_config(path: Path) -> Config:
    with path.open("rb") as handle:
        raw = tomllib.load(handle)
    base = path.parent
    listen = _section(raw, "listen")
    enroll = _section(raw, "enroll")
    allow = _section(raw, "allowlist")
    proxy = _section(raw, "proxy")

    secret = str(enroll.get("secret", ""))
    if secret in _PLACEHOLDER_SECRETS or len(secret) < _MIN_SECRET:
        raise ValueError("в enroll.secret нужен свой секрет длиной от 16 символов")

    ttl_days = int(enroll.get("ttl_days", 30))
    if ttl_days < 1:
        raise ValueError("enroll.ttl_days должен быть не меньше 1")

    hosts = _hosts(proxy.get("hosts"))
    deny_ips = {normalize_ip(str(item)) for item in proxy.get("deny_ips", [])}
    allowlist_path = Path(str(allow.get("path", "data/allowlist.json")))
    if not allowlist_path.is_absolute():
        allowlist_path = base / allowlist_path
    permanent = _permanent(allow.get("permanent"))

    return Config(
        enroll_host=str(listen.get("enroll_host", "0.0.0.0")),
        enroll_port=_port(listen.get("enroll_port", 61150), "listen.enroll_port"),
        proxy_host=str(listen.get("proxy_host", "0.0.0.0")),
        proxy_port=_port(listen.get("proxy_port", 443), "listen.proxy_port"),
        secret=secret,
        ttl_days=ttl_days,
        allowlist_path=allowlist_path,
        permanent=permanent,
        upstream_port=_port(proxy.get("upstream_port", 443), "proxy.upstream_port"),
        hosts=hosts,
        allow_private_upstreams=bool(proxy.get("allow_private_upstreams", False)),
        deny_ips=deny_ips,
        hello_timeout=float(proxy.get("hello_timeout", 5)),
        connect_timeout=float(proxy.get("connect_timeout", 10)),
    )


def init_config(path: Path) -> str:
    import secrets

    if path.exists():
        raise FileExistsError(f"файл уже есть: {path}")
    secret = secrets.token_hex(16)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_template(secret), encoding="utf-8")
    return secret


def _section(raw: dict[str, object], name: str) -> dict[str, object]:
    value = raw.get(name, {})
    if not isinstance(value, dict):
        raise ValueError(f"секция {name} должна быть таблицей")
    return value


def _port(value: object, label: str) -> int:
    port = int(value)  # type: ignore[arg-type]
    if port < 1 or port > 65535:
        raise ValueError(f"{label} вне диапазона 1..65535")
    return port


def _permanent(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError("allowlist.permanent должен быть списком")
    entries = [str(item).strip() for item in value]
    parse_networks(entries)
    return tuple(entries)


def _hosts(value: object) -> list[str]:
    if value is None:
        return list(DEFAULT_HOSTS)
    if not isinstance(value, list) or not value:
        raise ValueError("proxy.hosts должен быть непустым списком")
    hosts: list[str] = []
    for item in value:
        pattern = str(item).strip().lower()
        if pattern.startswith("*."):
            normalize_host("a" + pattern[1:])
        else:
            normalize_host(pattern)
        hosts.append(pattern)
    return hosts


def _template(secret: str) -> str:
    host_lines = "\n".join(f'  "{host}",' for host in DEFAULT_HOSTS)
    return f"""# Секретная ссылка: http://<адрес-прокси>:{61150}/{secret}
# На клиентах DNS chatgpt/openai/anthropic/claude смотрит на этот сервер.
# На самом сервере DNS должен оставаться настоящим: шлюз резолвит имя и прокидывает TCP.

[listen]
enroll_host = "0.0.0.0"
enroll_port = 61150
proxy_host = "0.0.0.0"
proxy_port = 443

[enroll]
secret = "{secret}"
ttl_days = 30

[allowlist]
path = "data/allowlist.json"
permanent = [
  "5.167.49.151/32",
  "31.173.214.149/32",
  "31.173.223.194/32",
  "46.0.251.132/32",
  "46.46.144.20/32",
  "46.46.144.24/32",
  "46.46.160.224/27",
  "62.5.191.230/32",
  "62.5.227.198/32",
  "62.105.139.66/32",
  "62.117.103.96/27",
  "62.141.122.208/28",
  "62.152.35.246/32",
  "62.183.46.172/32",
  "62.231.6.59/32",
  "62.231.29.210/32",
  "77.108.110.0/25",
  "78.138.142.150/32",
  "78.140.233.130/32",
  "79.134.200.170/32",
  "79.135.233.174/32",
  "79.137.158.122/32",
  "82.142.155.242/32",
  "82.142.164.226/32",
  "82.144.83.33/32",
  "82.196.141.94/32",
  "82.204.141.230/32",
  "82.204.183.162/32",
  "82.204.202.166/32",
  "82.204.210.214/32",
  "83.69.215.238/32",
  "83.139.181.78/32",
  "83.217.206.62/32",
  "83.239.60.34/32",
  "83.239.62.82/32",
  "84.52.88.92/32",
  "84.204.252.224/27",
  "85.31.179.18/32",
  "85.174.190.46/32",
  "85.174.198.40/32",
  "87.249.23.150/32",
  "89.106.173.18/32",
  "89.113.14.26/32",
  "89.113.100.215/32",
  "89.169.223.200/32",
  "89.175.91.246/32",
  "89.175.99.162/32",
  "89.188.124.13/32",
  "89.207.92.232/32",
  "90.154.123.91/32",
  "90.157.83.158/32",
  "91.210.47.23/32",
  "91.233.222.119/32",
  "93.95.172.74/32",
  "93.186.62.102/32",
  "93.188.204.32/32",
  "93.190.20.11/32",
  "94.73.220.108/32",
  "95.64.135.198/32",
  "95.64.203.174/32",
  "95.78.163.38/32",
  "95.84.136.127/32",
  "95.131.149.96/32",
  "95.139.64.59/32",
  "95.161.190.46/32",
  "95.161.232.254/32",
  "95.165.138.205/32",
  "109.110.59.178/32",
  "109.124.84.150/32",
  "109.126.16.222/32",
  "109.167.214.246/32",
  "109.235.185.48/29",
  "109.235.185.202/32",
  "109.235.187.50/32",
  "109.235.188.216/32",
  "109.235.190.12/32",
  "139.45.224.162/32",
  "149.126.18.78/32",
  "176.32.176.198/32",
  "176.74.13.194/32",
  "176.211.31.174/32",
  "176.211.47.66/32",
  "178.35.228.186/32",
  "178.72.72.9/32",
  "178.72.74.41/32",
  "178.161.148.63/32",
  "178.177.4.96/28",
  "178.178.192.6/32",
  "178.178.223.3/32",
  "178.208.128.26/32",
  "178.208.132.122/32",
  "185.6.172.197/32",
  "185.6.172.221/32",
  "185.22.183.32/27",
  "185.26.205.186/32",
  "185.32.167.107/32",
  "185.36.157.50/32",
  "185.68.146.187/32",
  "185.227.84.0/22",
  "188.170.221.135/32",
  "194.84.6.0/24",
  "194.154.71.62/32",
  "194.186.153.170/32",
  "194.186.197.193/32",
  "195.16.107.24/29",
  "195.28.54.55/32",
  "195.46.167.105/32",
  "195.128.96.229/32",
  "195.151.55.216/29",
  "195.151.250.201/32",
  "195.208.164.24/32",
  "195.239.23.33/32",
  "195.239.106.105/32",
  "195.239.153.11/32",
  "195.239.186.110/32",
  "212.20.41.217/32",
  "212.46.240.231/32",
  "212.46.245.0/28",
  "212.48.32.58/32",
  "212.48.34.67/32",
  "212.119.160.242/32",
  "213.33.200.69/32",
  "217.19.116.151/32",
]

[proxy]
upstream_port = 443
hello_timeout = 5
connect_timeout = 10
# Сюда впишите публичный адрес самого прокси, чтобы не зациклиться,
# если локальный DNS вдруг начнёт отдавать его вместо настоящего.
deny_ips = []
allow_private_upstreams = false
hosts = [
{host_lines}
]
"""
