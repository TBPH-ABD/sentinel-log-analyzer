# sentinel-log-analyzer

Blue-team log triage. Parses SSH authentication logs and web server access
logs, correlates events per source IP, and raises graded alerts for
brute-force attacks, credential compromise, content discovery scans, and
known attack patterns in request paths.

Built to answer the question that matters after an incident: *who touched
this box, what did they try, and did anything succeed?*

## Detections

| Alert | Severity | Trigger |
| --- | --- | --- |
| `ssh-compromise` | critical | A successful SSH login from an IP that was brute forcing moments earlier |
| `ssh-brute-force` | high | N failed logins from one IP inside a sliding time window |
| `web-attack-pattern` | high | SQL injection, XSS, path traversal, command injection, or sensitive-file probes in request paths |
| `content-discovery` | medium | A burst of 404s from a single IP — directory brute forcing |
| `scanner-agent` | medium | Requests carrying a known scanner user agent (sqlmap, nikto, gobuster, nmap, …) |
| `server-errors` | low | Repeated 5xx responses, suggesting input is reaching unhandled code paths |

Attack patterns are matched against both the raw and the percent-decoded
request path, so payloads encoded to evade naive matching are still caught.

## Supported formats

- **SSH** — syslog `auth.log` style (`Failed password for … from …`)
- **Web** — NCSA combined log format (nginx and Apache defaults)

Mixed files are fine; each line is routed to whichever parser matches.

## Requirements

Python 3.10 or newer. No packages to install.

## Usage

```bash
# Analyse the bundled samples
python3 sentinel.py samples/auth.log samples/access.log --year 2026

# Analyse real logs and save a JSON report
python3 sentinel.py /var/log/auth.log /var/log/nginx/access.log -o incident.json

# Tighten the brute-force threshold
python3 sentinel.py /var/log/auth.log --failures 3 --window 2
```

### Options

| Flag | Description | Default |
| --- | --- | --- |
| `--window` | Brute-force correlation window, in minutes | `5` |
| `--failures` | Failed logins that constitute brute force | `5` |
| `--notfound` | 404s that constitute content discovery | `20` |
| `--year` | Year to assume for syslog timestamps (syslog omits it) | current year |
| `-o`, `--output` | Write the JSON report to this file | none |

## Example output

```
  Parsed 45 log entries from 7 unique source IPs.
  Alerts raised: 8

  critical: 1  high: 4  medium: 3

  [CRITICAL] ssh-compromise  <- 198.51.100.77
             Successful SSH login as 'backup' after 5 failed attempts —
             likely credential compromise.
             . successful at 2026-09-16T03:22:27+00:00

  [HIGH    ] ssh-brute-force  <- 203.0.113.44
             7 failed SSH logins within 5 minutes across 7 username(s).
             . usernames tried: admin, git, oracle, postgres, root, test, ubuntu

  [MEDIUM  ] content-discovery  <- 192.0.2.55
             20 HTTP 404 responses out of 20 requests — consistent with
             directory brute forcing.
```

## Running it on a schedule

The tool exits `1` when any critical or high alert fires, so it drops straight
into cron or a monitoring job:

```cron
*/15 * * * * /usr/bin/python3 /opt/sentinel/sentinel.py /var/log/auth.log \
  -o /var/log/sentinel-latest.json || /usr/local/bin/notify-oncall
```

## How brute-force correlation works

Rather than counting failures over the whole file, the analyser slides a time
window across the sorted failure timestamps and reports the densest burst.
Five failures spread over a day is a forgetful user; five failures in ninety
seconds is an attack. The window and threshold are both tunable.

## License

MIT — see [LICENSE](LICENSE).
