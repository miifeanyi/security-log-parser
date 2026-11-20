# security-log-parser

Parse an auth log and flag brute-force login attempts — with a plain-English summary, not just a count.

```bash
python parser.py examples/sample-auth.log
# examples/sample-auth.log
#   Total lines:   18
#   Failed logins: 12
#   Accepted logins: 2
#   IPs with failures: 4
#   Flagged (>= 5 failures): 1
#     203.0.113.45 — 7 failed (users: admin, root, ubuntu)
```

## What it does

Given an sshd-style auth log, it:

| Step | What it does |
|---|---|
| **Parse** | Extracts `Failed password` and `Accepted password/publickey` lines with regex, pulling out user + source IP. Ignores session, disconnect, and other noise lines. |
| **Count** | Counts failures per IP and per user, and successes per IP. |
| **Flag** | Flags any IP with failures at or above a threshold (default 5). The threshold is a CLI flag, not hard-coded. |
| **Report** | Prints a short text summary, or `--json` for machine-readable output. |

Exit codes: `0` = no IP flagged, `2` = at least one IP flagged, `1` = file not found.

## Why I built this

I do production GKE support work, and in October 2026 I worked for Mercor as an AI Generalist — creating research questions, answers, and evaluation materials to train LLMs. Day-to-day support work is mostly log work: read a log, find the pattern, decide what matters, and explain it.

This is Module 2 of my Python interview prep (strings, files, and log parsing), turned into a runnable tool. Same skill as the [k8s-yaml-evaluator](https://github.com/miifeanyi/k8s-yaml-evaluator) — structured reasoning over messy text — applied to detection instead of YAML.

No real logs, credentials, or client data in here — the sample log is invented, using TEST-NET documentation IPs (`203.0.113.x`, `198.51.100.x`, `192.0.2.x`).

## How to run it

```bash
# Text summary (default threshold: 5 failures per IP)
python parser.py examples/sample-auth.log

# Lower the threshold — 198.51.100.23 (3 failures) now flags too
python parser.py examples/sample-auth.log --threshold 3

# Machine-readable output for CI / SIEM-style review
python parser.py examples/sample-auth.log --json
```

Example JSON output:

```json
{
  "file": "examples/sample-auth.log",
  "threshold": 5,
  "total_lines": 18,
  "failed": 12,
  "accepted": 2,
  "failed_by_ip": {
    "203.0.113.45": 7,
    "198.51.100.23": 3,
    "192.0.2.10": 1,
    "203.0.113.99": 1
  },
  "flagged": [
    {
      "ip": "203.0.113.45",
      "failed_count": 7,
      "users": ["admin", "root", "ubuntu"]
    }
  ]
}
```

## Tech decisions & trade-offs

- **Python stdlib only.** `re`, `argparse`, `json`, `collections`. No dependencies to install, nothing to break. The point is the parsing and detection logic.
- **Threshold is a flag, not a magic number.** 5 is a reasonable default for a demo log. A real SOC would tune it per service, per time window, and per baseline — I kept the rule blunt and explicit so it's easy to argue with.
- **Counts, not timestamps (yet).** This version flags on total failures per IP in the file, not failures per minute. That's simpler and honest for a static file. Time-window detection is the obvious next step — see below.
- **Noise lines return `None`.** Session open/close, disconnects, and preauth closes are ignored rather than counted. A parser that counts everything is a parser that cries wolf.
- **Failed vs accepted are tracked separately.** One failed login followed by a success from the same IP is a different story from 7 failures and no success. The summary keeps both visible.

## What I'd improve

1. Time-window detection: flag 5+ failures from one IP within 10 minutes, not just in the whole file.
2. Support `journalctl` / JSON log formats, not just sshd text lines.
3. Add a `--top N` view: most-targeted users and most-active IPs.
4. Add allowlisting for known scanner IPs / VPN egress, so the flagged list stays actionable.
5. Add IPv6 parsing.

## Tests

```bash
python -m pytest tests/ -q
```

CI runs the same checks on every push (`.github/workflows/ci.yml`).

## Files

```
parser.py                   # the parser + CLI
examples/sample-auth.log    # invented auth log — 12 failures, 2 successes, 1 flagged IP
tests/test_parser.py         # parsing, counting, and threshold tests
```
