"""Список IP, которым разрешено ходить через шлюз."""

from __future__ import annotations

import ipaddress
import json
import os
import threading
from collections.abc import Callable
from datetime import date, datetime, timedelta
from pathlib import Path

from llmproxy.hosts import normalize_ip

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_networks(entries: list[str]) -> tuple[Network, ...]:
    networks: list[Network] = []
    for entry in entries:
        text = entry.strip()
        if not text:
            raise ValueError("пустая запись в постоянном списке")
        try:
            if "/" in text:
                network = ipaddress.ip_network(text, strict=True)
            else:
                address = ipaddress.ip_address(normalize_ip(text))
                network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
        except ValueError as exc:
            raise ValueError(f"некорректная сеть или адрес: {text}") from exc
        networks.append(network)
    return tuple(networks)


class Allowlist:
    def __init__(
        self,
        path: Path,
        ttl_days: int,
        now: Callable[[], datetime] | None = None,
        permanent: list[str] | None = None,
    ) -> None:
        if ttl_days < 1:
            raise ValueError("ttl_days должен быть не меньше 1")
        self.path = path
        self.ttl_days = ttl_days
        self._now = now or datetime.now
        self._lock = threading.Lock()
        self._permanent = parse_networks(permanent or [])

    def today(self) -> date:
        return self._now().date()

    def permanent(self, ip: str) -> bool:
        address = ipaddress.ip_address(normalize_ip(ip))
        return any(address in network for network in self._permanent)

    def active(self, ip: str) -> bool:
        if self.permanent(ip):
            return True
        with self._lock:
            expires = self._load().get(ip)
        if expires is None:
            return False
        return date.fromisoformat(expires) >= self.today()

    def register(self, ip: str) -> tuple[bool, date | None]:
        """Возвращает (создан_заново, дата_окончания).

        Постоянная сеть дату не получает. Повторный заход до истечения
        срока дату не сдвигает. Просроченная запись обновляется.
        """
        if self.permanent(ip):
            return False, None
        with self._lock:
            data = self._load()
            today = self.today()
            current = data.get(ip)
            if current is not None:
                expires = date.fromisoformat(current)
                if expires >= today:
                    return False, expires
            expires = today + timedelta(days=self.ttl_days)
            data[ip] = expires.isoformat()
            self._save(data)
            return True, expires

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError(f"повреждён список доступа: {self.path}")
        loaded: dict[str, str] = {}
        for key, value in raw.items():
            loaded[str(key)] = str(value)
            date.fromisoformat(loaded[str(key)])
        return loaded

    def _save(self, data: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.path)
