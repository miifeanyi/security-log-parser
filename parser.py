#!/usr/bin/env python3
"""security-log-parser — flag brute-force login attempts in an auth log.

Reads an sshd-style auth log, counts failed logins per IP and per user,
and flags any IP at or above a threshold (default: 5 failures).

Stdlib only. No real logs, credentials, or client data in here — the
sample log is invented, using TEST-NET documentation IPs.

Usage:
    python parser.py examples/sample-auth.log
    python parser.py examples/sample-auth.log --threshold 3
    python parser.py examples/sample-auth.log --json
    python parser.py examples/sample-auth.log --json --threshold 3

Exit codes: 0 = no IP at/above threshold, 2 = at least one IP flagged.
"""

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# sshd lines we care about. Port is optional — some log formats omit it.
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from "
    r"(\d{1,3}(?:\.\d{1,3}){3})(?: port \d+)?"
)
ACCEPTED_RE = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from "
    r"(\d{1,3}(?:\.\d{1,3}){3})(?: port \d+)?"
)


def parse_line(line):
    """Parse one log line.

    Returns {"event": "failed"|"accepted", "user": str, "ip": str}
    or None for lines that are not a login success/failure
    (session open/close, disconnects, etc.).
    """
    m = FAILED_RE.search(line)
    if m:
        return {"event": "failed", "user": m.group(1), "ip": m.group(2)}
    m = ACCEPTED_RE.search(line)
    if m:
        return {"event": "accepted", "user": m.group(1), "ip": m.group(2)}
    return None


def parse_log(path):
    """Parse a whole log file. Returns a summary dict."""
    failed_by_ip = Counter()
    failed_by_user = Counter()
    accepted_by_ip = Counter()
    users_by_ip = defaultdict(set)
    total = failed = accepted = 0

    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            total += 1
            event = parse_line(line)
            if event is None:
                continue
            if event["event"] == "failed":
                failed += 1
                failed_by_ip[event["ip"]] += 1
                failed_by_user[event["user"]] += 1
                users_by_ip[event["ip"]].add(event["user"])
            else:
                accepted += 1
                accepted_by_ip[event["ip"]] += 1

    return {
        "total_lines": total,
        "failed": failed,
        "accepted": accepted,
        "failed_by_ip": dict(failed_by_ip),
        "failed_by_user": dict(failed_by_user),
        "accepted_by_ip": dict(accepted_by_ip),
        "users_by_ip": {ip: sorted(users) for ip, users in users_by_ip.items()},
    }


def flagged_ips(summary, threshold=5):
    """IPs with failed logins at or above threshold, most failures first.

    Returns a list of {"ip", "failed_count", "users"} dicts.
    """
    flagged = [
        {
            "ip": ip,
            "failed_count": count,
            "users": summary["users_by_ip"].get(ip, []),
        }
        for ip, count in summary["failed_by_ip"].items()
        if count >= threshold
    ]
    return sorted(flagged, key=lambda d: d["failed_count"], reverse=True)


def report_text(path, summary, flagged, threshold):
    """Human-readable summary."""
    lines = [
        str(path),
        f"  Total lines:   {summary['total_lines']}",
        f"  Failed logins: {summary['failed']}",
        f"  Accepted logins: {summary['accepted']}",
        f"  IPs with failures: {len(summary['failed_by_ip'])}",
        f"  Flagged (>= {threshold} failures): {len(flagged)}",
    ]
    for entry in flagged:
        users = ", ".join(entry["users"]) or "(unknown)"
        lines.append(
            f"    {entry['ip']} — {entry['failed_count']} failed "
            f"(users: {users})"
        )
    if not flagged:
        lines.append("  No brute-force pattern found at this threshold.")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Flag brute-force login attempts in an auth log."
    )
    parser.add_argument("logfile", help="Path to an auth log file")
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Failures per IP needed to flag it (default: 5)",
    )
    parser.add_argument(
        "--json", action="store_true", help="Print JSON instead of text"
    )
    args = parser.parse_args(argv)

    path = Path(args.logfile)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 1

    summary = parse_log(path)
    flagged = flagged_ips(summary, threshold=args.threshold)

    if args.json:
        output = {
            "file": str(path),
            "threshold": args.threshold,
            "total_lines": summary["total_lines"],
            "failed": summary["failed"],
            "accepted": summary["accepted"],
            "failed_by_ip": summary["failed_by_ip"],
            "failed_by_user": summary["failed_by_user"],
            "flagged": flagged,
        }
        print(json.dumps(output, indent=2))
    else:
        print(report_text(path, summary, flagged, args.threshold))

    return 2 if flagged else 0


if __name__ == "__main__":
    raise SystemExit(main())
