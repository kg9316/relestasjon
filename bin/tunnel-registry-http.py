#!/usr/bin/env python3
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ACTIVE_TUNNELS_FILE = Path("/var/lib/tunnel-registry/active-tunnels.json")
DEVICES_FILE = Path("/var/lib/tunnel-registry/devices.json")
RELAY_STATE_FILE = Path("/var/lib/tunnel-registry/relay-state.json")
PUBLIC_SESSION_STATE_FILE = Path("/var/lib/tunnel-registry/public-session-state.json")

HOST = "127.0.0.1"
PORT = 8080


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    path.chmod(0o644)


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False).stdout


def pid_alive(pid):
    if not pid:
        return False
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


def utc_now():
    return datetime.now(timezone.utc)


def utc_now_iso():
    return utc_now().isoformat()


def parse_dt(value):
    if not value:
        return None
    try:
        if value.endswith("Z"):
            return datetime.fromisoformat(value[:-1] + "+00:00")
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def format_duration_seconds(total):
    if total is None:
        return "-"
    total = int(total)
    if total < 0:
        return "-"

    days = total // 86400
    total %= 86400
    hours = total // 3600
    total %= 3600
    minutes = total // 60
    seconds = total % 60

    if days > 0:
        return f"{days}d {hours}h {minutes}m"
    if hours > 0:
        return f"{hours}h {minutes}m"
    if minutes > 0:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def format_uptime(value):
    dt = parse_dt(value)
    if not dt:
        return "-"

    now = utc_now()
    delta = now - dt
    total = int(delta.total_seconds())
    return format_duration_seconds(total)


def get_established_counts_by_local_port():
    out = run(["ss", "-tn"])
    counts = {}

    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("ESTAB"):
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        local_addr = parts[3]
        m = re.search(r":(\d+)$", local_addr)
        if not m:
            continue

        port = int(m.group(1))
        counts[port] = counts.get(port, 0) + 1

    return counts


def update_public_session_state(devices, established_counts):
    """
    Rules:
    - 0 -> >0  : start new uptime window from now, lastDurationSeconds = 0
    - >0 -> >0 : keep counting from activeSince
    - >0 -> 0  : freeze current duration into lastDurationSeconds, clear activeSince
    - 0 -> 0   : keep lastDurationSeconds unchanged
    """
    state = load_json(PUBLIC_SESSION_STATE_FILE, {})
    now = utc_now()
    now_iso = now.isoformat()

    valid_devices = set()

    for d in devices:
        device = d.get("device")
        public_port = d.get("publicPort")
        if not device or public_port is None:
            continue

        public_port = int(public_port)
        valid_devices.add(device)
        sessions = int(established_counts.get(public_port, 0))
        is_connected = sessions > 0

        entry = state.get(device, {})
        prev_connected = bool(entry.get("connected", False))
        active_since = entry.get("activeSince")
        last_duration_seconds = int(entry.get("lastDurationSeconds", 0) or 0)

        # NO -> YES
        if is_connected and not prev_connected:
            state[device] = {
                "connected": True,
                "activeSince": now_iso,
                "lastDurationSeconds": 0,
                "lastSessionCount": sessions,
                "publicPort": public_port,
            }
            continue

        # YES -> YES
        if is_connected and prev_connected:
            state[device] = {
                "connected": True,
                "activeSince": active_since or now_iso,
                "lastDurationSeconds": 0,
                "lastSessionCount": sessions,
                "publicPort": public_port,
            }
            continue

        # YES -> NO
        if (not is_connected) and prev_connected:
            duration = 0
            start_dt = parse_dt(active_since)
            if start_dt:
                duration = max(0, int((now - start_dt).total_seconds()))

            state[device] = {
                "connected": False,
                "activeSince": None,
                "lastDurationSeconds": duration,
                "lastSessionCount": 0,
                "publicPort": public_port,
            }
            continue

        # NO -> NO
        state[device] = {
            "connected": False,
            "activeSince": None,
            "lastDurationSeconds": last_duration_seconds,
            "lastSessionCount": 0,
            "publicPort": public_port,
        }

    for device in list(state.keys()):
        if device not in valid_devices:
            del state[device]

    save_json(PUBLIC_SESSION_STATE_FILE, state)
    return state


def current_or_last_public_uptime(session_state):
    if not session_state:
        return "-"

    connected = bool(session_state.get("connected", False))
    active_since = session_state.get("activeSince")
    last_duration_seconds = int(session_state.get("lastDurationSeconds", 0) or 0)

    # If currently connected, calculate live duration from activeSince
    if connected:
        start_dt = parse_dt(active_since)
        if start_dt:
            duration = max(0, int((utc_now() - start_dt).total_seconds()))
            return format_duration_seconds(duration)
        return "0s"

    # If not connected, freeze on last measured duration
    return format_duration_seconds(last_duration_seconds)


def build_combined_data():
    active = load_json(ACTIVE_TUNNELS_FILE, [])
    devices = load_json(DEVICES_FILE, [])
    relay_state = load_json(RELAY_STATE_FILE, {})
    established_counts = get_established_counts_by_local_port()
    public_session_state = update_public_session_state(devices, established_counts)

    devices_by_name = {}
    for d in devices:
        name = d.get("device")
        if name:
            devices_by_name[name] = d

    active_by_name = {}
    for item in active:
        device = item.get("device")
        if device:
            active_by_name[device] = item

    result = []
    all_names = sorted(set(devices_by_name.keys()) | set(active_by_name.keys()))

    for device in all_names:
        cfg = devices_by_name.get(device, {})
        act = active_by_name.get(device, {})
        relay = relay_state.get(device, {})
        session_state = public_session_state.get(device, {})

        ports = act.get("ports") or []
        remote_tunnel_port = ports[0] if ports else None
        mapped_public_port = cfg.get("publicPort")
        connected_at = act.get("connectedAt")
        relay_active = pid_alive(relay.get("pid"))

        public_port_sessions = 0
        if mapped_public_port is not None:
            public_port_sessions = established_counts.get(int(mapped_public_port), 0)

        public_port_connected = public_port_sessions > 0
        online = remote_tunnel_port is not None

        result.append({
            "device": device,
            "status": "ONLINE" if online else "OFFLINE",
            "clientIp": act.get("clientIp"),
            "clientPort": act.get("clientPort"),
            "remoteTunnelPort": remote_tunnel_port,
            "mappedPublicPort": mapped_public_port,
            "relayActive": relay_active,
            "publicPortConnected": public_port_connected,
            "publicPortSessions": public_port_sessions,
            "connectedAt": connected_at,
            "uptime": format_uptime(connected_at),
            "publicPortUptime": current_or_last_public_uptime(session_state),
        })

    return result


def html_page(data):
    rows = []
    for item in data:
        rows.append(
            f"""
            <tr>
              <td>{item.get("device") or "-"}</td>
              <td>{item.get("status") or "-"}</td>
              <td>{item.get("clientIp") or "-"}</td>
              <td>{item.get("clientPort") if item.get("clientPort") is not None else "-"}</td>
              <td>{item.get("remoteTunnelPort") if item.get("remoteTunnelPort") is not None else "-"}</td>
              <td>{item.get("mappedPublicPort") if item.get("mappedPublicPort") is not None else "-"}</td>
              <td>{"YES" if item.get("relayActive") else "NO"}</td>
              <td>{"YES" if item.get("publicPortConnected") else "NO"}</td>
              <td>{item.get("publicPortSessions") if item.get("publicPortSessions") is not None else 0}</td>
              <td>{item.get("connectedAt") or "-"}</td>
              <td>{item.get("uptime") or "-"}</td>
              <td>{item.get("publicPortUptime") or "-"}</td>
            </tr>
            """
        )

    rows_html = "\n".join(rows) if rows else '<tr><td colspan="12">No devices</td></tr>'

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Tunnel Registry</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 24px;
      background: #f7f7f7;
      color: #222;
    }}
    table {{
      border-collapse: collapse;
      width: 100%;
      background: white;
      font-size: 14px;
    }}
    th, td {{
      border: 1px solid #ddd;
      padding: 8px 10px;
      text-align: left;
      vertical-align: top;
      white-space: nowrap;
    }}
    th {{
      background: #efefef;
    }}
  </style>
</head>
<body>
  <h1>Tunnel Registry</h1>
  <table>
    <thead>
      <tr>
        <th>Device</th>
        <th>Status</th>
        <th>Client IP</th>
        <th>Client port</th>
        <th>Remote tunnel port</th>
        <th>Mapped public port</th>
        <th>Relay active</th>
        <th>Public port connected</th>
        <th>Public port sessions</th>
        <th>Connected</th>
        <th>Uptime</th>
        <th>Public port uptime</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = build_combined_data()

        if self.path in ("/", "/index.html"):
            body = html_page(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/api/tunnels":
            body = json.dumps(data, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.send_header("Expires", "0")
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def log_message(self, format, *args):
        return


def main():
    server = HTTPServer((HOST, PORT), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
