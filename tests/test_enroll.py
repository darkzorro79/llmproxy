import asyncio
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from llmproxy.allowlist import Allowlist
from llmproxy.enroll import EnrollSite


SECRET = "200b2fd39939a945178946aa0971bc0f"


class EnrollTest(unittest.TestCase):
    def test_pages_match_the_old_wording(self) -> None:
        async def scenario() -> tuple[bytes, bytes, bytes]:
            with tempfile.TemporaryDirectory() as directory:
                book = Allowlist(Path(directory) / "list.json", 30, now=lambda: datetime(2026, 9, 30, 12, 0))
                site = EnrollSite(SECRET, book)
                server = await asyncio.start_server(site.handle, "127.0.0.1", 0)
                port = server.sockets[0].getsockname()[1]
                async with server:
                    first = await _get(port, f"/{SECRET}")
                    second = await _get(port, f"/{SECRET}/")
                    missing = await _get(port, "/nope")
                return first, second, missing

        first, second, missing = asyncio.run(scenario())
        self.assertIn("HTTP/1.1 200 OK".encode(), first)
        self.assertIn("<h1>Готово</h1>".encode(), first)
        self.assertIn("IP 127.0.0.1 добавлен до 2026-10-30".encode(), first)
        self.assertIn("<h1>Уже в списке</h1>".encode(), second)
        self.assertIn("IP 127.0.0.1 активен до 2026-10-30".encode(), second)
        self.assertIn("HTTP/1.1 404 Not Found".encode(), missing)
        self.assertNotIn(SECRET.encode(), missing)


async def _get(port: int, path: str) -> bytes:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    data = await reader.read(-1)
    writer.close()
    await writer.wait_closed()
    return data


if __name__ == "__main__":
    unittest.main()
