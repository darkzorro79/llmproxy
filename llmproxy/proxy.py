"""TCP-прокидка TLS: SNI выбирает адрес, байты клиента не расшифровываются."""

from __future__ import annotations

import asyncio
import logging
import socket
from collections.abc import Awaitable, Callable

from llmproxy.allowlist import Allowlist
from llmproxy.hosts import destination_allowed, host_allowed, normalize_ip
from llmproxy.sni import extract_sni, read_client_hello

log = logging.getLogger("llmproxy.proxy")

Resolve = Callable[[str], Awaitable[list[str]]]
_HELLO_TIMEOUT = 5
_CONNECT_TIMEOUT = 10


async def system_resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    addresses: list[str] = []
    for info in infos:
        ip = normalize_ip(info[4][0])
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise OSError(f"нет адресов для {host}")
    return addresses


class TlsPassthrough:
    def __init__(
        self,
        allowlist: Allowlist,
        hosts: list[str],
        upstream_port: int = 443,
        resolve: Resolve = system_resolve,
        allow_private_upstreams: bool = False,
        deny_ips: set[str] | None = None,
        hello_timeout: float = _HELLO_TIMEOUT,
        connect_timeout: float = _CONNECT_TIMEOUT,
    ) -> None:
        self.allowlist = allowlist
        self.hosts = hosts
        self.upstream_port = upstream_port
        self.resolve = resolve
        self.allow_private_upstreams = allow_private_upstreams
        self.deny_ips = deny_ips or set()
        self.hello_timeout = hello_timeout
        self.connect_timeout = connect_timeout

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = normalize_ip(peer[0]) if peer else ""
        upstream: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None
        try:
            if not self.allowlist.active(ip):
                log.info("IP %s не в списке, соединение закрыто", ip)
                return
            try:
                hello = await asyncio.wait_for(read_client_hello(reader), self.hello_timeout)
                sni = extract_sni(hello)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError, ValueError, UnicodeError):
                log.info("IP %s прислал не ClientHello, соединение закрыто", ip)
                return
            if sni is None or not host_allowed(sni, self.hosts):
                log.info("IP %s: имя %s не разрешено", ip, sni or "без SNI")
                return
            try:
                addresses = await self.resolve(sni)
            except OSError:
                log.info("IP %s: не удалось разрешить %s", ip, sni)
                return
            permitted = [item for item in addresses if self._destination_ok(item)]
            if not permitted:
                log.info("IP %s: %s резолвится в запрещённый адрес", ip, sni)
                return
            upstream = await self._connect(permitted)
            if upstream is None:
                log.info("IP %s: нет соединения с %s", ip, sni)
                return
            up_reader, up_writer = upstream
            up_writer.write(hello)
            await up_writer.drain()
            log.info("IP %s прокинут на %s", ip, sni)
            await _relay(reader, writer, up_reader, up_writer)
            upstream = None
        finally:
            writer.close()
            if upstream is not None:
                upstream[1].close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    def _destination_ok(self, ip: str) -> bool:
        return destination_allowed(
            ip,
            allow_private=self.allow_private_upstreams,
            deny_ips=self.deny_ips,
        )

    async def _connect(
        self, addresses: list[str]
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter] | None:
        for address in addresses:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(address, self.upstream_port),
                    self.connect_timeout,
                )
            except (OSError, asyncio.TimeoutError):
                continue
        return None


async def _relay(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> None:
    async def pipe(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
        try:
            while True:
                block = await source.read(65536)
                if not block:
                    break
                destination.write(block)
                await destination.drain()
        except (ConnectionError, asyncio.IncompleteReadError, BrokenPipeError):
            return
        finally:
            _half_close(destination)

    tasks = (
        asyncio.create_task(pipe(client_reader, upstream_writer)),
        asyncio.create_task(pipe(upstream_reader, client_writer)),
    )
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for side in (client_writer, upstream_writer):
            side.close()
            try:
                await side.wait_closed()
            except ConnectionError:
                pass


def _half_close(writer: asyncio.StreamWriter) -> None:
    try:
        if writer.can_write_eof():
            writer.write_eof()
            return
    except (ConnectionError, OSError, RuntimeError):
        pass
    writer.close()
