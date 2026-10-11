"""Секретная ссылка: IP источника попадает в список до даты."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
from html import escape
from urllib.parse import urlsplit

from llmproxy.allowlist import Allowlist
from llmproxy.hosts import normalize_ip

log = logging.getLogger("llmproxy.enroll")

_REQUEST_LIMIT = 8192
_READ_TIMEOUT = 10


def secret_matches(presented: str, secret: str) -> bool:
    presented_hash = hashlib.sha256(presented.encode("utf-8")).digest()
    secret_hash = hashlib.sha256(secret.encode("utf-8")).digest()
    return hmac.compare_digest(presented_hash, secret_hash)


def render_page(title: str, line: str) -> bytes:
    safe_title = escape(title)
    safe_line = escape(line)
    html = (
        "<!DOCTYPE html>\n"
        '<html lang="ru">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        f"<title>{safe_title}</title>\n"
        "</head>\n"
        "<body>\n"
        f"<h1>{safe_title}</h1>\n"
        f"<p>{safe_line}</p>\n"
        "</body>\n"
        "</html>\n"
    )
    return html.encode("utf-8")


class EnrollSite:
    def __init__(self, secret: str, allowlist: Allowlist) -> None:
        self.secret = secret
        self.allowlist = allowlist

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = normalize_ip(peer[0]) if peer else ""
        try:
            method, target = await _read_request(reader)
            if method != "GET":
                await _send(writer, 405, "Method Not Allowed", b"")
                return
            path = urlsplit(target).path
            if path != "/" and path.endswith("/"):
                path = path[:-1]
            if not path.startswith("/") or not secret_matches(path[1:], self.secret):
                await _send(writer, 404, "Not Found", "Не найдено".encode("utf-8"), "text/plain; charset=utf-8")
                return
            created, expires = self.allowlist.register(ip)
            if expires is None:
                title = "Уже в списке"
                line = f"IP {ip} в постоянном списке"
                log.info("IP %s в постоянном списке", ip)
            elif created:
                title = "Готово"
                line = f"IP {ip} добавлен до {expires.isoformat()}"
                log.info("IP %s добавлен до %s", ip, expires.isoformat())
            else:
                title = "Уже в списке"
                line = f"IP {ip} активен до {expires.isoformat()}"
                log.info("IP %s уже в списке до %s", ip, expires.isoformat())
            await _send(writer, 200, "OK", render_page(title, line))
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, ValueError, UnicodeError):
            log.info("некорректный запрос регистрации от %s", ip or "неизвестно")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass


async def _read_request(reader: asyncio.StreamReader) -> tuple[str, str]:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = await asyncio.wait_for(reader.read(1024), _READ_TIMEOUT)
        if not chunk:
            raise ConnectionError("клиент закрыл соединение")
        data += chunk
        if len(data) > _REQUEST_LIMIT:
            raise ValueError("слишком большой запрос")
    head = bytes(data).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
    request_line = head.split("\r\n", 1)[0]
    method, target, *_rest = request_line.split(" ")
    if not method.isalpha() or not target.startswith("/"):
        raise ValueError("некорректная строка запроса")
    return method, target


async def _send(
    writer: asyncio.StreamWriter,
    status: int,
    reason: str,
    body: bytes,
    content_type: str = "text/html; charset=utf-8",
) -> None:
    header = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Connection: close\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n"
    ).encode("ascii")
    writer.write(header + body)
    await writer.drain()
