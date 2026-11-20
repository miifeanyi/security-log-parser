from pathlib import Path

from parser import flagged_ips, parse_line, parse_log

SAMPLE = Path(__file__).parent.parent / "examples" / "sample-auth.log"


def test_parse_failed_line():
    event = parse_line(
        "Nov 19 10:01:12 host sshd[1234]: Failed password for root "
        "from 203.0.113.45 port 51234 ssh2"
    )
    assert event == {"event": "failed", "user": "root", "ip": "203.0.113.45"}


def test_parse_invalid_user_line():
    event = parse_line(
        "Nov 19 10:05:11 host sshd[1247]: Failed password for invalid user "
        "guest from 203.0.113.99 port 54444 ssh2"
    )
    assert event == {"event": "failed", "user": "guest", "ip": "203.0.113.99"}


def test_parse_accepted_line():
    event = parse_line(
        "Nov 19 10:04:30 host sshd[1246]: Accepted publickey for michael "
        "from 192.0.2.10 port 53446 ssh2"
    )
    assert event == {"event": "accepted", "user": "michael", "ip": "192.0.2.10"}


def test_parse_ignores_noise_lines():
    assert parse_line("Nov 19 10:05:12 host sshd[1247]: Connection closed by 203.0.113.45 port 51234 [preauth]") is None
    assert parse_line("Nov 19 10:07:01 host sshd[1299]: pam_unix(sshd:session): session opened for user michael by (uid=0)") is None


def test_sample_counts():
    summary = parse_log(SAMPLE)
    assert summary["total_lines"] == 18
    assert summary["failed"] == 12
    assert summary["accepted"] == 2
    assert summary["failed_by_ip"] == {
        "203.0.113.45": 7,
        "198.51.100.23": 3,
        "192.0.2.10": 1,
        "203.0.113.99": 1,
    }


def test_flagged_at_default_threshold():
    summary = parse_log(SAMPLE)
    flagged = flagged_ips(summary, threshold=5)
    assert [f["ip"] for f in flagged] == ["203.0.113.45"]
    assert flagged[0]["failed_count"] == 7
    assert flagged[0]["users"] == ["admin", "root", "ubuntu"]


def test_flagged_at_lower_threshold():
    summary = parse_log(SAMPLE)
    flagged = flagged_ips(summary, threshold=3)
    assert [f["ip"] for f in flagged] == ["203.0.113.45", "198.51.100.23"]
