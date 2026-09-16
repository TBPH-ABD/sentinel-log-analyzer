"""Tests for sentinel-log-analyzer detection logic."""
from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import sentinel
from sentinel import IPActivity, detect, ingest, max_in_window
from tests.support.fakes import capture_cli

SAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "samples")


def ssh_failure(ip: str, user: str, second: int) -> str:
    return (f"Sep 16 03:{second // 60:02d}:{second % 60:02d} srv sshd[1]: "
            f"Failed password for invalid user {user} from {ip} port 4000 ssh2\n")


def ssh_success(ip: str, user: str, second: int) -> str:
    return (f"Sep 16 03:{second // 60:02d}:{second % 60:02d} srv sshd[1]: "
            f"Accepted password for {user} from {ip} port 4000 ssh2\n")


def web_line(ip: str, path: str, status: int = 200,
             agent: str = "Mozilla/5.0") -> str:
    return (f'{ip} - - [16/Sep/2026:09:00:00 +0000] "GET {path} HTTP/1.1" '
            f'{status} 100 "-" "{agent}"\n')


def analyse(lines: list[str], window: int = 5, failures: int = 5,
            notfound: int = 20):
    """Write lines to a temp log, ingest, and run detection."""
    activity: dict[str, IPActivity] = {}
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "test.log")
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(lines)
        ingest(path, activity, 2026)
    return detect(activity, window, failures, notfound), activity


def categories(alerts) -> set[str]:
    return {a.category for a in alerts}


class TestSlidingWindow(unittest.TestCase):
    base = datetime(2026, 9, 16, 3, 0, 0, tzinfo=timezone.utc)

    def test_empty_list_is_zero(self):
        self.assertEqual(max_in_window([], timedelta(minutes=5)), 0)

    def test_all_inside_window(self):
        times = [self.base + timedelta(seconds=s) for s in (0, 10, 20)]
        self.assertEqual(max_in_window(times, timedelta(minutes=5)), 3)

    def test_spread_beyond_window_counts_densest_burst(self):
        # Two clusters of two, hours apart: the densest burst is 2, not 4.
        times = [self.base, self.base + timedelta(seconds=5),
                 self.base + timedelta(hours=6),
                 self.base + timedelta(hours=6, seconds=5)]
        self.assertEqual(max_in_window(times, timedelta(minutes=5)), 2)

    def test_unsorted_input_is_handled(self):
        times = [self.base + timedelta(seconds=s) for s in (30, 0, 15)]
        self.assertEqual(max_in_window(times, timedelta(minutes=5)), 3)


class TestSshDetection(unittest.TestCase):
    def test_brute_force_is_detected(self):
        lines = [ssh_failure("10.0.0.5", f"user{i}", i) for i in range(6)]
        alerts, _ = analyse(lines)
        self.assertIn("ssh-brute-force", categories(alerts))

    def test_below_threshold_is_not_flagged(self):
        lines = [ssh_failure("10.0.0.5", f"user{i}", i) for i in range(3)]
        alerts, _ = analyse(lines)
        self.assertNotIn("ssh-brute-force", categories(alerts))

    def test_failures_spread_over_time_are_not_brute_force(self):
        # One failure per hour is a forgetful user, not an attack.
        lines = [f"Sep 16 {h:02d}:00:00 srv sshd[1]: Failed password for "
                 f"invalid user bob from 10.0.0.9 port 40 ssh2\n"
                 for h in range(8)]
        alerts, _ = analyse(lines)
        self.assertNotIn("ssh-brute-force", categories(alerts))

    def test_success_after_brute_force_is_critical(self):
        lines = [ssh_failure("10.0.0.7", "backup", i) for i in range(6)]
        lines.append(ssh_success("10.0.0.7", "backup", 10))
        alerts, _ = analyse(lines)
        self.assertIn("ssh-compromise", categories(alerts))
        compromise = next(a for a in alerts if a.category == "ssh-compromise")
        self.assertEqual(compromise.severity, "critical")

    def test_clean_login_is_not_flagged(self):
        alerts, _ = analyse([ssh_success("10.0.0.2", "deploy", 5)])
        self.assertEqual(alerts, [])

    def test_success_before_failures_is_not_compromise(self):
        # The login happened first, so the later failures cannot have led to it.
        lines = [ssh_success("10.0.0.8", "deploy", 0)]
        lines += [ssh_failure("10.0.0.8", "deploy", i) for i in range(1, 7)]
        alerts, _ = analyse(lines)
        self.assertNotIn("ssh-compromise", categories(alerts))


class TestWebDetection(unittest.TestCase):
    def test_content_discovery_is_detected(self):
        lines = [web_line("10.0.0.3", f"/dir{i}", 404) for i in range(25)]
        alerts, _ = analyse(lines)
        self.assertIn("content-discovery", categories(alerts))

    def test_few_404s_are_not_flagged(self):
        lines = [web_line("10.0.0.3", f"/dir{i}", 404) for i in range(3)]
        alerts, _ = analyse(lines)
        self.assertNotIn("content-discovery", categories(alerts))

    def test_plus_encoded_sql_injection_is_decoded(self):
        # A request line cannot contain a raw space, so real payloads arrive
        # encoded. '+' must be decoded back to a space before matching.
        alerts, _ = analyse([web_line("10.0.0.4", "/p?id=1+UNION+SELECT+a,b")])
        self.assertIn("web-attack-pattern", categories(alerts))

    def test_percent_encoded_sql_injection_is_decoded(self):
        alerts, _ = analyse(
            [web_line("10.0.0.4", "/p?id=1%20UNION%20SELECT%20a,b")])
        self.assertIn("web-attack-pattern", categories(alerts))

    def test_raw_space_truncates_the_path_without_crashing(self):
        # A request line cannot legally contain a raw space. If one appears,
        # the path is captured up to the space and the rest is discarded: the
        # request is still counted, but the truncated payload raises no alert.
        # Documented limitation, not a crash.
        alerts, activity = analyse([web_line("10.0.0.4", "/p?id=1 UNION SELECT")])
        self.assertEqual(activity["10.0.0.4"].requests, 1)
        self.assertEqual(activity["10.0.0.4"].paths, ["/p?id=1"])
        self.assertEqual(alerts, [])

    def test_path_traversal_pattern(self):
        alerts, _ = analyse([web_line("10.0.0.4", "/../../etc/passwd")])
        self.assertIn("web-attack-pattern", categories(alerts))

    def test_sensitive_file_probe(self):
        alerts, _ = analyse([web_line("10.0.0.4", "/.env")])
        self.assertIn("web-attack-pattern", categories(alerts))

    def test_xss_pattern(self):
        alerts, _ = analyse([web_line("10.0.0.4", "/s?q=<script>alert(1)</script>")])
        self.assertIn("web-attack-pattern", categories(alerts))

    def test_scanner_user_agent(self):
        alerts, _ = analyse([web_line("10.0.0.6", "/", 200, "sqlmap/1.8")])
        self.assertIn("scanner-agent", categories(alerts))

    def test_ordinary_browsing_is_clean(self):
        lines = [web_line("10.0.0.1", p) for p in ("/", "/about", "/contact")]
        alerts, _ = analyse(lines)
        self.assertEqual(alerts, [])

    def test_repeated_server_errors_are_flagged(self):
        lines = [web_line("10.0.0.9", f"/api/{i}", 500) for i in range(12)]
        alerts, _ = analyse(lines)
        self.assertIn("server-errors", categories(alerts))


class TestParsing(unittest.TestCase):
    def test_unparseable_lines_are_skipped(self):
        activity: dict[str, IPActivity] = {}
        self.assertFalse(sentinel.activity_for("garbage\n", activity, 2026))
        self.assertEqual(activity, {})

    def test_web_request_counts_are_tracked(self):
        _, activity = analyse([web_line("10.0.0.1", "/", 200),
                               web_line("10.0.0.1", "/x", 404)])
        self.assertEqual(activity["10.0.0.1"].requests, 2)
        self.assertEqual(activity["10.0.0.1"].not_found, 1)

    def test_mixed_ssh_and_web_lines_in_one_file(self):
        lines = [ssh_failure("10.0.0.5", "root", 1), web_line("10.0.0.6", "/")]
        _, activity = analyse(lines)
        self.assertEqual(set(activity), {"10.0.0.5", "10.0.0.6"})


class TestAlertOrdering(unittest.TestCase):
    def test_alerts_are_sorted_most_severe_first(self):
        lines = [ssh_failure("10.0.0.7", "backup", i) for i in range(6)]
        lines.append(ssh_success("10.0.0.7", "backup", 10))
        lines += [web_line("10.0.0.8", "/", 200, "nikto/2.5")]
        alerts, _ = analyse(lines)
        order = [sentinel.SEVERITY_ORDER[a.severity] for a in alerts]
        self.assertEqual(order, sorted(order))


class TestBundledSamples(unittest.TestCase):
    """The samples shipped in the repo must keep producing the documented result."""

    def test_samples_produce_expected_alerts(self):
        activity: dict[str, IPActivity] = {}
        ingest(os.path.join(SAMPLES, "auth.log"), activity, 2026)
        ingest(os.path.join(SAMPLES, "access.log"), activity, 2026)
        alerts = detect(activity, 5, 5, 20)
        found = categories(alerts)
        self.assertIn("ssh-compromise", found)
        self.assertIn("ssh-brute-force", found)
        self.assertIn("content-discovery", found)
        self.assertIn("web-attack-pattern", found)


class TestCli(unittest.TestCase):
    def test_exits_nonzero_when_high_severity_found(self):
        code, _ = capture_cli(sentinel.main, [
            os.path.join(SAMPLES, "auth.log"), "--year", "2026"])
        self.assertEqual(code, 1)

    def test_missing_file_reports_error(self):
        code, out = capture_cli(sentinel.main, ["/nonexistent/path.log"])
        self.assertEqual(code, 1)
        self.assertIn("Could not read", out)


if __name__ == "__main__":
    unittest.main()
