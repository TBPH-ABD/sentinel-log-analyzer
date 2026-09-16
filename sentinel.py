#!/usr/bin/env python3
"""sentinel-log-analyzer — detect attacks in SSH and web server logs.

A blue-team log triage tool. It parses SSH authentication logs and web
server access logs, correlates events per source IP, and raises graded
alerts for brute-force attempts, credential-stuffing success, content
discovery scans, and known attack patterns in request paths.

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone

# --- SSH (syslog "auth.log" style) -----------------------------------------
SSH_FAILED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}).*sshd.*Failed password for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d.]+)")
SSH_ACCEPTED = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s[\d:]{8}).*sshd.*Accepted \S+ for (?P<user>\S+) "
    r"from (?P<ip>[\d.]+)")

# --- Web server (NCSA combined) --------------------------------------------
WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<agent>[^"]*)")?')

# Request paths that indicate someone probing for a known weakness.
SUSPICIOUS_PATTERNS = [
    (re.compile(r"\.\./|%2e%2e", re.I), "path traversal attempt"),
    (re.compile(r"\b(union\s+select|or\s+1=1|sleep\(|benchmark\()", re.I), "SQL injection attempt"),
    (re.compile(r"<script|javascript:|onerror=", re.I), "cross-site scripting attempt"),
    (re.compile(r"/\.(env|git|aws|ssh)\b", re.I), "sensitive file probe"),
    (re.compile(r"/(wp-login|wp-admin|xmlrpc\.php)", re.I), "WordPress attack surface probe"),
    (re.compile(r"/(phpmyadmin|adminer|pma)\b", re.I), "database console probe"),
    (re.compile(r";\s*(cat|wget|curl|nc|bash)\s|%3b", re.I), "command injection attempt"),
]

# User agents belonging to automated scanners.
SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|"
    r"havij|zgrab|python-requests|curl/)", re.I)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Alert:
    severity: str
    category: str
    source_ip: str
    summary: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class IPActivity:
    ip: str = ""
    ssh_failures: list[tuple[datetime, str]] = field(default_factory=list)
    ssh_successes: list[tuple[datetime, str]] = field(default_factory=list)
    requests: int = 0
    not_found: int = 0
    server_errors: int = 0
    patterns: list[str] = field(default_factory=list)
    agents: set = field(default_factory=set)
    paths: list[str] = field(default_factory=list)


def parse_syslog_time(raw: str, year: int) -> datetime:
    """Syslog timestamps omit the year, so the caller supplies one."""
    return datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S").replace(
        tzinfo=timezone.utc)


def parse_web_time(raw: str) -> datetime:
    return datetime.strptime(raw.split()[0], "%d/%b/%Y:%H:%M:%S").replace(
        tzinfo=timezone.utc)


def ingest(path: str, activity: dict[str, IPActivity], year: int) -> int:
    """Read one log file, routing each line to the matching parser."""
    lines_parsed = 0
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            record = activity_for(line, activity, year)
            if record:
                lines_parsed += 1
    return lines_parsed


def activity_for(line: str, activity: dict[str, IPActivity], year: int) -> bool:
    match = SSH_FAILED.search(line)
    if match:
        entry = activity.setdefault(match["ip"], IPActivity(ip=match["ip"]))
        entry.ssh_failures.append(
            (parse_syslog_time(match["ts"], year), match["user"]))
        return True

    match = SSH_ACCEPTED.search(line)
    if match:
        entry = activity.setdefault(match["ip"], IPActivity(ip=match["ip"]))
        entry.ssh_successes.append(
            (parse_syslog_time(match["ts"], year), match["user"]))
        return True

    match = WEB_LINE.search(line)
    if match:
        entry = activity.setdefault(match["ip"], IPActivity(ip=match["ip"]))
        entry.requests += 1
        status = int(match["status"])
        if status == 404:
            entry.not_found += 1
        elif status >= 500:
            entry.server_errors += 1
        path = match["path"]
        entry.paths.append(path)
        # Attackers percent-encode payloads to slip past naive pattern matching,
        # so test the decoded form as well as the raw one.
        decoded = urllib.parse.unquote_plus(path)
        for pattern, label in SUSPICIOUS_PATTERNS:
            if pattern.search(path) or pattern.search(decoded):
                entry.patterns.append(f"{label}: {path[:120]}")
                break  # one label per request is enough evidence
        agent = match["agent"] or ""
        if agent:
            entry.agents.add(agent)
        return True

    return False


def detect(activity: dict[str, IPActivity], window_minutes: int,
           failure_threshold: int, notfound_threshold: int) -> list[Alert]:
    """Correlate per-IP activity into graded alerts."""
    alerts: list[Alert] = []
    window = timedelta(minutes=window_minutes)

    for entry in activity.values():
        # --- SSH brute force: N failures inside a sliding time window ---
        failures = sorted(entry.ssh_failures)
        if len(failures) >= failure_threshold:
            burst = max_in_window([t for t, _ in failures], window)
            if burst >= failure_threshold:
                users = sorted({u for _, u in failures})
                alerts.append(Alert(
                    "high", "ssh-brute-force", entry.ip,
                    f"{burst} failed SSH logins within {window_minutes} minutes "
                    f"across {len(users)} username(s).",
                    [f"usernames tried: {', '.join(users[:10])}"]))

        # --- Successful login from an IP that was brute forcing: critical ---
        if entry.ssh_successes and len(entry.ssh_failures) >= failure_threshold:
            first_success = min(t for t, _ in entry.ssh_successes)
            prior = [t for t, _ in entry.ssh_failures if t <= first_success]
            if len(prior) >= failure_threshold:
                user = next(u for t, u in entry.ssh_successes if t == first_success)
                alerts.append(Alert(
                    "critical", "ssh-compromise", entry.ip,
                    f"Successful SSH login as '{user}' after {len(prior)} failed "
                    f"attempts — likely credential compromise.",
                    [f"successful at {first_success.isoformat()}"]))

        # --- Content discovery / directory brute forcing ---
        if entry.not_found >= notfound_threshold:
            alerts.append(Alert(
                "medium", "content-discovery", entry.ip,
                f"{entry.not_found} HTTP 404 responses out of {entry.requests} "
                f"requests — consistent with directory brute forcing.",
                [f"sample paths: {', '.join(entry.paths[:5])}"]))

        # --- Known attack patterns in request paths ---
        if entry.patterns:
            categories = sorted({p.split(":")[0] for p in entry.patterns})
            alerts.append(Alert(
                "high", "web-attack-pattern", entry.ip,
                f"{len(entry.patterns)} request(s) matched known attack "
                f"patterns: {', '.join(categories)}.",
                entry.patterns[:6]))

        # --- Automated scanner user agents ---
        scanners = [a for a in entry.agents if SCANNER_AGENTS.search(a)]
        if scanners:
            alerts.append(Alert(
                "medium", "scanner-agent", entry.ip,
                "Requests sent with an automated scanner user agent.",
                scanners[:4]))

        # --- Server errors triggered repeatedly (possible fuzzing) ---
        if entry.server_errors >= 10:
            alerts.append(Alert(
                "low", "server-errors", entry.ip,
                f"Triggered {entry.server_errors} HTTP 5xx responses — the "
                f"input may be reaching unhandled code paths.", []))

    return sorted(alerts, key=lambda a: SEVERITY_ORDER[a.severity])


def max_in_window(times: list[datetime], window: timedelta) -> int:
    """Largest number of timestamps falling inside any sliding window."""
    times = sorted(times)
    best = 0
    left = 0
    for right, moment in enumerate(times):
        while moment - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def print_report(alerts: list[Alert], activity: dict[str, IPActivity],
                 lines: int) -> None:
    print(f"\n  Parsed {lines} log entries from {len(activity)} unique source IPs.")
    print(f"  Alerts raised: {len(alerts)}\n")

    if not alerts:
        print("  No suspicious activity detected.\n")
        return

    counts = defaultdict(int)
    for alert in alerts:
        counts[alert.severity] += 1
    summary = "  ".join(f"{sev}: {counts[sev]}" for sev in
                        ("critical", "high", "medium", "low") if counts[sev])
    print(f"  {summary}\n")

    for alert in alerts:
        print(f"  [{alert.severity.upper():<8}] {alert.category}  <- {alert.source_ip}")
        print(f"             {alert.summary}")
        for line in alert.evidence:
            print(f"             . {line}")
        print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Detect attacks in SSH and web server logs.")
    parser.add_argument("logs", nargs="+", help="log files to analyse")
    parser.add_argument("--window", type=int, default=5,
                        help="brute-force correlation window in minutes (default 5)")
    parser.add_argument("--failures", type=int, default=5,
                        help="failed logins that constitute brute force (default 5)")
    parser.add_argument("--notfound", type=int, default=20,
                        help="404s that constitute content discovery (default 20)")
    parser.add_argument("--year", type=int, default=datetime.now().year,
                        help="year to assume for syslog timestamps")
    parser.add_argument("-o", "--output", help="write the JSON report to this file")
    args = parser.parse_args(argv)

    activity: dict[str, IPActivity] = {}
    total = 0
    for path in args.logs:
        try:
            total += ingest(path, activity, args.year)
        except OSError as exc:
            print(f"Could not read {path}: {exc}", file=sys.stderr)
            return 1

    alerts = detect(activity, args.window, args.failures, args.notfound)
    print_report(alerts, activity, total)

    if args.output:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "entries_parsed": total,
            "unique_sources": len(activity),
            "alerts": [asdict(a) for a in alerts],
        }
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"  Report written to {args.output}\n")

    # Non-zero exit when something needs a human — useful for cron/monitoring.
    return 1 if any(a.severity in ("critical", "high") for a in alerts) else 0


if __name__ == "__main__":
    raise SystemExit(main())
