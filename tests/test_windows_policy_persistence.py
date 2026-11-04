"""Windows revocation persistence must never silently succeed on failed writes."""

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from nightrecon_shared_core.engagement_policy import (
    EngagementExecutionPolicy, FileEngagementPolicyStore, _replace_policy_file,
)


def sharing_error(code=5):
    exc = PermissionError("temporary Windows file sharing refusal")
    exc.winerror = code
    return exc


class WindowsPolicyPersistenceTests(unittest.TestCase):
    def test_transient_windows_sharing_failure_retries_and_succeeds(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "policy.tmp"
            target = Path(folder) / "policy.json"
            source.write_text("new policy", encoding="utf-8")
            from os import replace as real_replace
            calls = [0]
            def transient(src, dest):
                calls[0] += 1
                if calls[0] <= 2:
                    raise sharing_error(5)
                return real_replace(src, dest)
            with patch(
                "nightrecon_shared_core.engagement_policy.os.replace",
                side_effect=transient,
            ), patch("nightrecon_shared_core.engagement_policy.time.sleep") as sleep:
                _replace_policy_file(str(source), target, platform="nt")
            self.assertEqual(calls[0], 3)
            self.assertEqual(sleep.call_count, 2)
            self.assertEqual(target.read_text(encoding="utf-8"), "new policy")

    def test_persistent_windows_denial_raises_without_claimed_write(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "policy.tmp"
            target = Path(folder) / "policy.json"
            source.write_text("new", encoding="utf-8")
            target.write_text("existing", encoding="utf-8")
            with patch("nightrecon_shared_core.engagement_policy.os.replace", side_effect=sharing_error(32)) as replace:
                with patch("nightrecon_shared_core.engagement_policy.time.sleep"):
                    with self.assertRaises(PermissionError):
                        _replace_policy_file(str(source), target, platform="nt")
            self.assertEqual(replace.call_count, 6)
            self.assertEqual(target.read_text(encoding="utf-8"), "existing")

    def test_non_windows_or_nonsharing_failure_does_not_retry(self):
        for platform, error in (("posix", sharing_error(5)), ("nt", sharing_error(13))):
            with self.subTest(platform=platform):
                with patch("nightrecon_shared_core.engagement_policy.os.replace", side_effect=error) as replace:
                    with patch("nightrecon_shared_core.engagement_policy.time.sleep") as sleep:
                        with self.assertRaises(PermissionError):
                            _replace_policy_file("src", Path("dest"), platform=platform)
                replace.assert_called_once()
                sleep.assert_not_called()

    def test_failed_revocation_rolls_back_in_memory_and_disk(self):
        with tempfile.TemporaryDirectory() as folder:
            db = Path(folder) / "policy.json"
            store = FileEngagementPolicyStore(db)
            now = datetime.now(timezone.utc)
            store.set_policy(EngagementExecutionPolicy(
                engagement_id="eng-worker",
                scope=("192.0.2.1",),
                valid_from=(now-timedelta(minutes=1)).isoformat(),
                valid_until=(now+timedelta(minutes=10)).isoformat(),
                max_actions=2, permitted_capabilities=("external.nmap.discovery",),
            ))
            with patch("nightrecon_shared_core.engagement_policy._replace_policy_file", side_effect=PermissionError("persistent")):
                with self.assertRaises(PermissionError):
                    store.revoke("eng-worker")
            self.assertFalse(store.policy("eng-worker").revoked)
            self.assertFalse(FileEngagementPolicyStore(db).policy("eng-worker").revoked)
            store.revoke("eng-worker")
            self.assertTrue(FileEngagementPolicyStore(db).policy("eng-worker").revoked)

    def test_failed_initial_write_does_not_leave_phantom_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            store = FileEngagementPolicyStore(Path(folder) / "policy.json")
            now = datetime.now(timezone.utc)
            candidate = EngagementExecutionPolicy(
                engagement_id="eng-worker",
                scope=("192.0.2.1",),
                valid_from=(now-timedelta(minutes=1)).isoformat(),
                valid_until=(now+timedelta(minutes=10)).isoformat(),
                max_actions=1, permitted_capabilities=("external.nmap.discovery",),
            )
            with patch("nightrecon_shared_core.engagement_policy._replace_policy_file", side_effect=PermissionError("persistent")):
                with self.assertRaises(PermissionError):
                    store.set_policy(candidate)
            self.assertIsNone(store.policy("eng-worker"))


if __name__ == "__main__":
    unittest.main()
