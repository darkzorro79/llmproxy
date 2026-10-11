"""Запуск ссылки регистрации и TCP-шлюза в одном процессе."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import socket
from pathlib import Path

from llmproxy.allowlist import Allowlist
from llmproxy.config import Config, init_config, load_config
from llmproxy.enroll import EnrollSite
from llmproxy.hosts import normalize_ip
from llmproxy.proxy import TlsPassthrough

log = logging.getLogger("llmproxy")


def detect_local_ips() -> set[str]:
    found: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(normalize_ip(info[4][0]))
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("1.1.1.1", 80))
            found.add(normalize_ip(probe.getsockname()[0]))
        finally:
            probe.close()
    except OSError:
        pass
    return found


async def serve(config: Config, extra_deny_ips: set[str] | None = None) -> None:
    allowlist = Allowlist(config.allowlist_path, config.ttl_days, permanent=list(config.permanent))
    deny = set(config.deny_ips)
    if extra_deny_ips:
        deny.update(extra_deny_ips)
    enroll = EnrollSite(config.secret, allowlist)
    proxy = TlsPassthrough(
        allowlist=allowlist,
        hosts=config.hosts,
        upstream_port=config.upstream_port,
        allow_private_upstreams=config.allow_private_upstreams,
        deny_ips=deny,
        hello_timeout=config.hello_timeout,
        connect_timeout=config.connect_timeout,
    )
    enroll_server = await asyncio.start_server(enroll.handle, config.enroll_host, config.enroll_port)
    proxy_server = await asyncio.start_server(proxy.handle, config.proxy_host, config.proxy_port)
    enroll_port = enroll_server.sockets[0].getsockname()[1]
    proxy_port = proxy_server.sockets[0].getsockname()[1]
    log.info("регистрация: http://%s:%s/<секрет из config>", config.enroll_host, enroll_port)
    log.info(
        "шлюз: %s:%s, имён в списке: %s, постоянных сетей: %s",
        config.proxy_host,
        proxy_port,
        len(config.hosts),
        len(config.permanent),
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    async with enroll_server, proxy_server:
        await stop.wait()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="llmproxy")
    commands = parser.add_subparsers(dest="command", required=True)

    init_parser = commands.add_parser("init", help="создать config.toml с новым секретом")
    init_parser.add_argument("--config", default="config.toml")

    serve_parser = commands.add_parser("serve", help="запустить ссылку регистрации и TCP-шлюз")
    serve_parser.add_argument("--config", required=True)

    args = parser.parse_args(argv)
    if args.command == "init":
        secret = init_config(Path(args.config))
        print(f"записан {args.config}")
        print(f"ссылка: http://<адрес>:{61150}/{secret}")
        return

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = load_config(Path(args.config))
    local_ips = detect_local_ips()
    if local_ips:
        log.info("локальные адреса, на которые шлюз не пойдёт: %s", ", ".join(sorted(local_ips)))
    try:
        asyncio.run(serve(config, extra_deny_ips=local_ips))
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    main()
