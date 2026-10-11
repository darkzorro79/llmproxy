import tempfile
import unittest
from pathlib import Path

from llmproxy.config import init_config, load_config


class ConfigTest(unittest.TestCase):
    def test_placeholder_secret_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_text(
                '[listen]\n[enroll]\nsecret = "change-me"\n[allowlist]\n[proxy]\n',
                encoding="utf-8",
            )
            with self.assertRaises(ValueError):
                load_config(path)

    def test_init_writes_a_usable_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            secret = init_config(path)
            config = load_config(path)
            self.assertEqual(config.secret, secret)
            self.assertEqual(len(secret), 32)
            self.assertEqual(config.enroll_port, 61150)
            self.assertEqual(config.proxy_port, 443)
            self.assertIn("api.anthropic.com", _covered(config.hosts))
            self.assertFalse(config.allow_private_upstreams)
            self.assertIn("185.227.84.0/22", config.permanent)
            self.assertIn("195.151.250.201", config.permanent)


def _covered(patterns: list[str]) -> set[str]:
    from llmproxy.hosts import host_allowed

    names = ["api.openai.com", "chatgpt.com", "api.anthropic.com", "claude.ai"]
    return {name for name in names if host_allowed(name, patterns)}


if __name__ == "__main__":
    unittest.main()
