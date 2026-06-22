#!/usr/bin/env python3
import json
import re
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone

AUTHORIZED_KEYS = "/home/tunnel/.ssh/authorized_keys"
OUTPUT_JSON = "/var/lib/tunnel-registry/active-tunnels.json"

PORT_MIN = 1024
PORT_MAX = 65535
IGNORED_PORTS = {22, 443, 2222, 4443}


def run(cmd, input_text=None):
    return subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        check=False,
    ).stdout


def key_fingerprint_from_line(line):
    with tempfile.NamedTemporaryFile("w+", delete=True) as f:
        f.write(line.strip() + "\n")
        f.flush()
        out = run(["ssh-keygen", "-lf", f.name])

    m = re.search(r"(SHA256:[A-Za-z0-9+/=_-]+)", out)
    return m.group(1) if m else None


def get_authorized_key_maps():
    by_line = {}
    by_fingerprint = {}

    with open(AUTHORIZED_KEYS, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue

            parts = s.split()
            if len(parts) < 2:
                continue

            comment = parts[-1] if len(parts) >= 3 else f"line-{line_no}"
            by_line[line_no] = comment

            fp = key_fingerprint_from_line(s)
            if fp:
                by_fingerprint[fp] = comment

    return by_line, by_fingerprint


def get_tunnel_processes():
    out = run(["ps", "-eo", "pid=,ppid=,user=,args="])
    priv = {}
    user_procs = {}

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue

        parts = line.split(None, 3)
        if len(parts) < 4:
            continue

        pid_s, ppid_s, user, args = parts

        try:
            pid = int(pid_s)
            ppid = int(ppid_s)
        except ValueError:
            continue

        if args == "sshd: tunnel [priv]":
            priv[pid] = {"pid": pid, "ppid": ppid, "user": user, "args": args}
        elif args == "sshd: tunnel":
            user_procs[pid] = {"pid": pid, "ppid": ppid, "user": user, "args": args}

    return priv, user_procs


def get_listen_ports_for_pid(pid):
    out = run(["ss", "-tlnp"])
    ports = []

    for line in out.splitlines():
        if f"pid={pid}," not in line:
            continue
        if "LISTEN" not in line:
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        local_addr = parts[3]
        m = re.search(r":(\d+)$", local_addr)
        if not m:
            continue

        port = int(m.group(1))

        if port in IGNORED_PORTS:
            continue

        if PORT_MIN <= port <= PORT_MAX:
            ports.append(port)

    return sorted(set(ports))


def extract_timestamp(line):
    m = re.match(r"^(\S+)\s+\S+\s+sshd\[\d+\]:", line)
    return m.group(1) if m else None


def parse_journal_for_pid(pid):
    out = run([
        "journalctl",
        "-u", "ssh",
        "-b",
        f"_PID={pid}",
        "--no-pager",
        "-o", "short-iso",
    ])

    if not out.strip():
        out = run([
            "journalctl",
            "-u", "sshd",
            "-b",
            f"_PID={pid}",
            "--no-pager",
            "-o", "short-iso",
        ])

    entry = {
        "session_pid": pid,
        "client_ip": None,
        "client_port": None,
        "key_fingerprint": None,
        "authorized_keys_line": None,
        "connected_at": None,
    }

    for line in out.splitlines():
        if entry["connected_at"] is None:
            ts = extract_timestamp(line)
            if ts:
                entry["connected_at"] = ts

        m_key = re.search(
            r"Accepted key \S+ (SHA256:[A-Za-z0-9+/=_-]+) found at .+authorized_keys:(\d+)",
            line,
        )
        if m_key:
            entry["key_fingerprint"] = m_key.group(1)
            entry["authorized_keys_line"] = int(m_key.group(2))
            ts = extract_timestamp(line)
            if ts:
                entry["connected_at"] = ts

        m_pub = re.search(
            r"Accepted publickey for tunnel from (\S+) port (\d+) ssh2: \S+ (SHA256:[A-Za-z0-9+/=_-]+)",
            line,
        )
        if m_pub:
            entry["client_ip"] = m_pub.group(1)
            entry["client_port"] = int(m_pub.group(2))
            entry["key_fingerprint"] = m_pub.group(3)
            ts = extract_timestamp(line)
            if ts:
                entry["connected_at"] = ts

    return entry


def resolve_device_name(journal_entry, by_line, by_fingerprint):
    fp = journal_entry.get("key_fingerprint")
    line_no = journal_entry.get("authorized_keys_line")

    if fp and fp in by_fingerprint:
        return by_fingerprint[fp]

    if line_no and line_no in by_line:
        return by_line[line_no]

    if fp:
        return f"unknown-fp-{fp}"

    if line_no:
        return f"unknown-line-{line_no}"

    return "unknown"


def build_registry():
    comments_by_line, comments_by_fingerprint = get_authorized_key_maps()
    priv_procs, user_procs = get_tunnel_processes()

    result = []

    for priv_pid in sorted(priv_procs):
        user_proc = None

        for _, uinfo in user_procs.items():
            if uinfo["ppid"] == priv_pid:
                user_proc = uinfo
                break

        if not user_proc:
            continue

        ports = get_listen_ports_for_pid(user_proc["pid"])
        if not ports:
            continue

        journal_entry = parse_journal_for_pid(priv_pid)
        device_name = resolve_device_name(
            journal_entry,
            comments_by_line,
            comments_by_fingerprint,
        )

        result.append({
            "device": device_name,
            "clientIp": journal_entry.get("client_ip"),
            "clientPort": journal_entry.get("client_port"),
            "fingerprint": journal_entry.get("key_fingerprint"),
            "authorizedKeysLine": journal_entry.get("authorized_keys_line"),
            "sessionPid": priv_pid,
            "userPid": user_proc["pid"],
            "ports": ports,
            "connectedAt": journal_entry.get("connected_at"),
            "updatedAt": datetime.now(timezone.utc).isoformat(),
        })

    result.sort(key=lambda x: (x.get("device") or "").lower())
    return result


def main():
    data = build_registry()

    out_path = Path(OUTPUT_JSON)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    out_path.chmod(0o644)


if __name__ == "__main__":
    main()
