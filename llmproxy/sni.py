"""Чтение TLS ClientHello и извлечение SNI без завершения рукопожатия."""

from __future__ import annotations

import asyncio

_HANDSHAKE = 22
_CLIENT_HELLO = 1
_SNI = 0
_HOST_NAME = 0
_MAX_RECORD = 16384
_MAX_HELLO = 32768


async def read_client_hello(reader: asyncio.StreamReader, limit: int = _MAX_HELLO) -> bytes:
    """Читает одну или несколько TLS-записей, пока не соберётся целый ClientHello."""
    raw = bytearray()
    handshake = bytearray()
    while True:
        header = await reader.readexactly(5)
        if header[0] != _HANDSHAKE:
            raise ValueError("ожидался TLS handshake")
        record_length = int.from_bytes(header[3:5], "big")
        if record_length <= 0 or record_length > _MAX_RECORD:
            raise ValueError("некорректная длина TLS-записи")
        if len(raw) + 5 + record_length > limit:
            raise ValueError("ClientHello слишком большой")
        fragment = await reader.readexactly(record_length)
        raw += header + fragment
        handshake += fragment
        if _client_hello_complete(handshake):
            return bytes(raw)


def extract_sni(records: bytes) -> str | None:
    handshake = _handshake_fragments(records)
    if not _client_hello_complete(handshake):
        raise ValueError("ClientHello собран не полностью")
    message_length = int.from_bytes(handshake[1:4], "big")
    return _sni_from_client_hello(bytes(handshake[4 : 4 + message_length]))


def _client_hello_complete(handshake: bytearray | bytes) -> bool:
    if len(handshake) < 4:
        return False
    if handshake[0] != _CLIENT_HELLO:
        raise ValueError("ожидался ClientHello")
    message_length = int.from_bytes(handshake[1:4], "big")
    return len(handshake) >= 4 + message_length


def _handshake_fragments(records: bytes) -> bytes:
    fragments = bytearray()
    offset = 0
    while offset + 5 <= len(records):
        if records[offset] != _HANDSHAKE:
            raise ValueError("ожидался TLS handshake")
        record_length = int.from_bytes(records[offset + 3 : offset + 5], "big")
        end = offset + 5 + record_length
        if end > len(records):
            raise ValueError("обрезанная TLS-запись")
        fragments += records[offset + 5 : end]
        offset = end
    if offset != len(records):
        raise ValueError("обрезанная TLS-запись")
    return bytes(fragments)


def _sni_from_client_hello(body: bytes) -> str | None:
    if len(body) < 34:
        return None
    offset = 34
    session_length = body[offset]
    offset += 1 + session_length
    if offset + 2 > len(body):
        return None
    cipher_length = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2 + cipher_length
    if offset >= len(body):
        return None
    compression_length = body[offset]
    offset += 1 + compression_length
    if offset + 2 > len(body):
        return None
    extensions_length = int.from_bytes(body[offset : offset + 2], "big")
    offset += 2
    end = offset + extensions_length
    if end > len(body):
        return None
    while offset + 4 <= end:
        extension_type = int.from_bytes(body[offset : offset + 2], "big")
        extension_length = int.from_bytes(body[offset + 2 : offset + 4], "big")
        offset += 4
        extension = body[offset : offset + extension_length]
        offset += extension_length
        if extension_type != _SNI:
            continue
        name = _host_from_sni_extension(extension)
        if name is not None:
            return name
    return None


def _host_from_sni_extension(extension: bytes) -> str | None:
    if len(extension) < 5:
        return None
    offset = 2
    while offset + 3 <= len(extension):
        name_type = extension[offset]
        name_length = int.from_bytes(extension[offset + 1 : offset + 3], "big")
        offset += 3
        name = extension[offset : offset + name_length]
        offset += name_length
        if name_type == _HOST_NAME:
            return name.decode("ascii")
    return None
