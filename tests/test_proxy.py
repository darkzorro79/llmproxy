import asyncio
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from llmproxy.allowlist import Allowlist
from llmproxy.proxy import TlsPassthrough, system_resolve
from tests.test_sni import build_client_hello


class ProxyTest(unittest.TestCase):
    def test_resolver_uses_the_system_socket_type(self) -> None:
        addresses = asyncio.run(system_resolve("localhost"))
        self.assertTrue(addresses)
    def test_bytes_are_forwarded_unchanged(self) -> None:
        hello = build_client_hello("api.openai.com")
        received: list[bytes] = []

        async def scenario() -> bytes:
            upstream = await asyncio.start_server(_capture(received), "127.0.0.1", 0)
            upstream_port = upstream.sockets[0].getsockname()[1]
            with tempfile.TemporaryDirectory() as directory:
                book = Allowlist(Path(directory) / "list.json", 30, now=lambda: datetime(2026, 9, 30))
                book.register("127.0.0.1")
                proxy = TlsPassthrough(
                    allowlist=book,
                    hosts=["api.openai.com"],
                    upstream_port=upstream_port,
                    resolve=_resolve_local,
                    allow_private_upstreams=True,
                )
                server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                async with upstream, server:
                    reader, writer = await asyncio.open_connection("127.0.0.1", port)
                    writer.write(hello + b"PING")
                    await writer.drain()
                    if writer.can_write_eof():
                        writer.write_eof()
                    reply = await asyncio.wait_for(reader.read(16), 2)
                    writer.close()
                    await writer.wait_closed()
                    return reply

        reply = asyncio.run(scenario())
        self.assertEqual(reply, b"PONG")
        self.assertEqual(received, [hello + b"PING"])

    def test_unknown_ip_never_reaches_upstream(self) -> None:
        hits: list[int] = []

        async def scenario() -> None:
            upstream = await asyncio.start_server(_capture(hits), "127.0.0.1", 0)
            with tempfile.TemporaryDirectory() as directory:
                book = Allowlist(Path(directory) / "list.json", 30)
                proxy = TlsPassthrough(
                    allowlist=book,
                    hosts=["api.openai.com"],
                    upstream_port=upstream.sockets[0].getsockname()[1],
                    resolve=_resolve_local,
                    allow_private_upstreams=True,
                )
                server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                async with upstream, server:
                    await _expect_closed(port, build_client_hello("api.openai.com"))
                    await asyncio.sleep(0.05)

        asyncio.run(scenario())
        self.assertEqual(hits, [])

    def test_foreign_sni_is_not_an_open_proxy(self) -> None:
        hits: list[bytes] = []

        async def scenario() -> None:
            upstream = await asyncio.start_server(_capture(hits), "127.0.0.1", 0)
            with tempfile.TemporaryDirectory() as directory:
                book = Allowlist(Path(directory) / "list.json", 30)
                book.register("127.0.0.1")
                proxy = TlsPassthrough(
                    allowlist=book,
                    hosts=["api.openai.com", "*.openai.com"],
                    upstream_port=upstream.sockets[0].getsockname()[1],
                    resolve=_resolve_local,
                    allow_private_upstreams=True,
                )
                server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                async with upstream, server:
                    await _expect_closed(port, build_client_hello("example.com"))
                    await asyncio.sleep(0.05)

        asyncio.run(scenario())
        self.assertEqual(hits, [])

    def test_loopback_upstream_is_refused_by_default(self) -> None:
        hits: list[bytes] = []

        async def scenario() -> None:
            upstream = await asyncio.start_server(_capture(hits), "127.0.0.1", 0)
            with tempfile.TemporaryDirectory() as directory:
                book = Allowlist(Path(directory) / "list.json", 30)
                book.register("127.0.0.1")
                proxy = TlsPassthrough(
                    allowlist=book,
                    hosts=["api.openai.com"],
                    upstream_port=upstream.sockets[0].getsockname()[1],
                    resolve=_resolve_local,
                    allow_private_upstreams=False,
                )
                server = await asyncio.start_server(proxy.handle, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                async with upstream, server:
                    await _expect_closed(port, build_client_hello("api.openai.com"))
                    await asyncio.sleep(0.05)

        asyncio.run(scenario())
        self.assertEqual(hits, [])


async def _expect_closed(port: int, payload: bytes) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        writer.write(payload)
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(16), 2)
        except ConnectionError:
            return
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass


def _capture(store: list[bytes]):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        data = bytearray()
        while b"PING" not in data:
            chunk = await reader.read(65536)
            if not chunk:
                break
            data += chunk
        store.append(bytes(data))
        writer.write(b"PONG")
        await writer.drain()
        if writer.can_write_eof():
            writer.write_eof()
        writer.close()
        await writer.wait_closed()

    return handle


async def _resolve_local(_host: str) -> list[str]:
    return ["127.0.0.1"]


if __name__ == "__main__":
    unittest.main()
