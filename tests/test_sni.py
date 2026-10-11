import asyncio
import unittest

from llmproxy.hosts import destination_allowed, host_allowed, normalize_ip
from llmproxy.sni import extract_sni, read_client_hello


def build_client_hello(hostname: str) -> bytes:
    host = hostname.encode("ascii")
    server_name = b"\x00" + len(host).to_bytes(2, "big") + host
    server_name_list = len(server_name).to_bytes(2, "big") + server_name
    extension = b"\x00\x00" + len(server_name_list).to_bytes(2, "big") + server_name_list
    extensions = len(extension).to_bytes(2, "big") + extension
    body = b"\x03\x03" + bytes(32) + b"\x00" + (2).to_bytes(2, "big") + b"\x00\x2f" + b"\x01\x00" + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def split_records(record: bytes) -> bytes:
    record_length = int.from_bytes(record[3:5], "big")
    fragment = record[5 : 5 + record_length]
    middle = len(fragment) // 2
    parts = (fragment[:middle], fragment[middle:])
    return b"".join(b"\x16\x03\x01" + len(part).to_bytes(2, "big") + part for part in parts)


class SniTest(unittest.TestCase):
    def test_extracts_hostname(self) -> None:
        hello = build_client_hello("api.openai.com")
        self.assertEqual(extract_sni(hello), "api.openai.com")

    def test_split_client_hello_is_reassembled(self) -> None:
        hello = build_client_hello("api.anthropic.com")

        async def scenario() -> bytes:
            reader = asyncio.StreamReader()
            reader.feed_data(split_records(hello))
            reader.feed_eof()
            return await read_client_hello(reader)

        reassembled = asyncio.run(scenario())
        self.assertEqual(extract_sni(reassembled), "api.anthropic.com")


class HostRulesTest(unittest.TestCase):
    patterns = ["chatgpt.com", "*.chatgpt.com", "claude.ai", "*.claude.ai"]

    def test_apex_and_subdomain(self) -> None:
        self.assertTrue(host_allowed("chatgpt.com", self.patterns))
        self.assertTrue(host_allowed("ab.chatgpt.com", self.patterns))
        self.assertTrue(host_allowed("Claude.AI", self.patterns))

    def test_foreign_name_is_rejected(self) -> None:
        self.assertFalse(host_allowed("notchatgpt.com", self.patterns))
        self.assertFalse(host_allowed("chatgpt.com.evil.com", self.patterns))
        self.assertFalse(host_allowed("evil.com", self.patterns))

    def test_ipv4_mapped_address(self) -> None:
        self.assertEqual(normalize_ip("::ffff:89.125.83.182"), "89.125.83.182")

    def test_private_destinations_are_blocked_unless_allowed(self) -> None:
        self.assertFalse(destination_allowed("127.0.0.1", allow_private=False, deny_ips=set()))
        self.assertFalse(destination_allowed("10.1.1.1", allow_private=False, deny_ips=set()))
        self.assertTrue(destination_allowed("1.1.1.1", allow_private=False, deny_ips=set()))
        self.assertFalse(destination_allowed("1.1.1.1", allow_private=False, deny_ips={"1.1.1.1"}))
        self.assertTrue(destination_allowed("127.0.0.1", allow_private=True, deny_ips=set()))


if __name__ == "__main__":
    unittest.main()
