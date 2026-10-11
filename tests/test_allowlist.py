import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from llmproxy.allowlist import Allowlist


class AllowlistTest(unittest.TestCase):
    def test_new_ip_gets_thirty_days_like_the_old_page(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            book = Allowlist(Path(directory) / "list.json", 30, now=lambda: datetime(2026, 9, 30, 15, 0))
            created, expires = book.register("89.125.83.182")
            self.assertTrue(created)
            self.assertEqual(expires.isoformat(), "2026-10-30")
            self.assertTrue(book.active("89.125.83.182"))

    def test_repeat_visit_keeps_the_same_date(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            book = Allowlist(Path(directory) / "list.json", 30, now=lambda: datetime(2026, 9, 30))
            book.register("89.125.83.182")
            later = Allowlist(Path(directory) / "list.json", 30, now=lambda: datetime(2026, 10, 1))
            created, expires = later.register("89.125.83.182")
            self.assertFalse(created)
            self.assertEqual(expires.isoformat(), "2026-10-30")

    def test_permanent_network_and_address_do_not_expire(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "list.json"
            book = Allowlist(
                path,
                30,
                permanent=["185.227.84.0/22", "195.151.250.201", "195.151.55.216/29"],
            )
            self.assertTrue(book.active("185.227.84.10"))
            self.assertTrue(book.active("185.227.87.255"))
            self.assertFalse(book.active("185.227.88.1"))
            self.assertTrue(book.active("195.151.250.201"))
            self.assertFalse(book.active("195.151.250.202"))
            self.assertTrue(book.active("195.151.55.220"))
            self.assertFalse(book.active("195.151.55.224"))
            created, expires = book.register("185.227.84.10")
            self.assertFalse(created)
            self.assertIsNone(expires)
            self.assertFalse(path.exists())

    def test_expired_ip_is_added_again(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            book = Allowlist(Path(directory) / "list.json", 30, now=lambda: datetime(2026, 9, 30))
            book.register("89.125.83.182")
            after = Allowlist(Path(directory) / "list.json", 30, now=lambda: datetime(2026, 10, 31))
            self.assertFalse(after.active("89.125.83.182"))
            created, expires = after.register("89.125.83.182")
            self.assertTrue(created)
            self.assertEqual(expires.isoformat(), "2026-11-30")


if __name__ == "__main__":
    unittest.main()
