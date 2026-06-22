#!/usr/bin/env python3
import html
import json
import os
import re
import subprocess
import tempfile
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import fcntl

HOST = "127.0.0.1"
PORT = 8081
BASE_PATH = "/admin/devices"

AUTHORIZED_KEYS = Path("/home/tunnel/.ssh/authorized_keys")
LOCK_FILE = Path("/home/tunnel/.ssh/authorized_keys.lock")
AUDIT_LOG = Path("/var/log/tunnel-admin.log")
DEVICES_FILE = Path("/var/lib/tunnel-registry/devices.json")


def log_audit(message: str) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().isoformat() + "Z"
    with AUDIT_LOG.open("a", encoding="utf-8") as f:
        f.write(f"{timestamp} {message}\n")


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=True)


def load_devices_config():
    if not DEVICES_FILE.exists():
        return []
    try:
        return json.loads(DEVICES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def save_devices_config(devices):
    DEVICES_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEVICES_FILE.write_text(json.dumps(devices, indent=2), encoding="utf-8")
    DEVICES_FILE.chmod(0o644)


def parse_authorized_keys():
    devices_cfg = {d["device"]: d for d in load_devices_config() if "device" in d}

    devices = []
    if not AUTHORIZED_KEYS.exists():
        return devices

    with AUTHORIZED_KEYS.open("r", encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            original_line = raw.rstrip("\n")
            line = original_line.strip()
            if not line or line.startswith("#"):
                continue

            parts = line.split()
            key_index = None
            for i, token in enumerate(parts):
                if token in (
                    "ssh-rsa",
                    "ssh-ed25519",
                    "ecdsa-sha2-nistp256",
                    "ecdsa-sha2-nistp384",
                    "ecdsa-sha2-nistp521",
                ):
                    key_index = i
                    break

            if key_index is None or len(parts) < key_index + 2:
                continue

            options = " ".join(parts[:key_index]).strip()
            key_type = parts[key_index]
            pubkey = parts[key_index + 1]
            comment = " ".join(parts[key_index + 2:]).strip() if len(parts) > key_index + 2 else ""

            fingerprint = ""
            try:
                with tempfile.TemporaryDirectory() as td:
                    pub = Path(td) / "tmp.pub"
                    pub.write_text(f"{key_type} {pubkey} {comment}\n", encoding="utf-8")
                    out = run(["ssh-keygen", "-lf", str(pub), "-E", "sha256"]).stdout.strip()
                    m = re.search(r"\s(SHA256:[A-Za-z0-9+/=_-]+)\s", f" {out} ")
                    if m:
                        fingerprint = m.group(1)
            except Exception:
                pass

            cfg = devices_cfg.get(comment, {})

            devices.append({
                "line": lineno,
                "raw": original_line,
                "options": options,
                "keyType": key_type,
                "comment": comment,
                "fingerprint": fingerprint,
                "publicPort": cfg.get("publicPort"),
            })

    return devices


def write_authorized_keys_lines(lines):
    LOCK_FILE.touch(mode=0o600, exist_ok=True)

    with LOCK_FILE.open("r+") as lockf:
        fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)

        AUTHORIZED_KEYS.parent.mkdir(parents=True, exist_ok=True)
        if not AUTHORIZED_KEYS.exists():
            AUTHORIZED_KEYS.touch(mode=0o600, exist_ok=True)

        content = "".join(line.rstrip("\n") + "\n" for line in lines)
        with AUTHORIZED_KEYS.open("w", encoding="utf-8") as f:
            f.write(content)

        os.chmod(AUTHORIZED_KEYS, 0o600)

        fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)


def append_public_key_line(public_key_line: str) -> None:
    LOCK_FILE.touch(mode=0o600, exist_ok=True)

    with LOCK_FILE.open("r+") as lockf:
        fcntl.flock(lockf.fileno(), fcntl.LOCK_EX)

        AUTHORIZED_KEYS.parent.mkdir(parents=True, exist_ok=True)
        if not AUTHORIZED_KEYS.exists():
            AUTHORIZED_KEYS.touch(mode=0o600, exist_ok=True)

        existing = AUTHORIZED_KEYS.read_text(encoding="utf-8", errors="ignore")
        if public_key_line.strip() in existing:
            raise ValueError("Public key already exists in authorized_keys")

        with AUTHORIZED_KEYS.open("a", encoding="utf-8") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write(public_key_line.strip() + "\n")

        os.chmod(AUTHORIZED_KEYS, 0o600)

        fcntl.flock(lockf.fileno(), fcntl.LOCK_UN)


def delete_device_by_line(line_no: int):
    if line_no <= 0:
        raise ValueError("Invalid line number")

    lines = AUTHORIZED_KEYS.read_text(encoding="utf-8", errors="ignore").splitlines()
    if line_no > len(lines):
        raise ValueError("Line number not found")

    devices = parse_authorized_keys()
    matched = next((d for d in devices if d["line"] == line_no), None)
    if not matched:
        raise ValueError("Selected line is not a valid device entry")

    new_lines = [line for idx, line in enumerate(lines, start=1) if idx != line_no]
    write_authorized_keys_lines(new_lines)

    devices_cfg = load_devices_config()
    devices_cfg = [d for d in devices_cfg if d.get("device") != matched["comment"]]
    save_devices_config(devices_cfg)

    return matched


def sanitize_device_name(name: str) -> str:
    name = name.strip()
    if not name:
        raise ValueError("Device name is required")

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", name):
        raise ValueError("Device name may only contain letters, numbers, dot, underscore and hyphen")

    return name



def parse_public_port(value: str) -> int:
    value = value.strip()
    if not value:
        raise ValueError("Public port is required")

    try:
        port = int(value)
    except ValueError:
        raise ValueError("Public port must be a number")

    if port < 20000 or port > 29999:
        raise ValueError("Public port must be between 20000 and 29999")

    return port

def public_port_in_use(port: int) -> bool:
    for d in load_devices_config():
        if d.get("publicPort") == port:
            return True
    return False


def generate_rsa_2048_pem(device_name: str):
    with tempfile.TemporaryDirectory() as td:
        key_base = Path(td) / device_name

        run([
            "ssh-keygen",
            "-t", "rsa",
            "-b", "2048",
            "-m", "PEM",
            "-N", "",
            "-C", device_name,
            "-f", str(key_base),
        ])

        private_key = key_base.read_text(encoding="utf-8")
        public_key = key_base.with_suffix(".pub").read_text(encoding="utf-8").strip()

        return private_key, public_key


def build_url(path: str, query: str = "") -> str:
    url = BASE_PATH + path
    if query:
        url += "?" + query
    return url


def html_page(message="", error=""):
    devices = parse_authorized_keys()

    rows = []
    for d in devices:
        public_port = "-" if d.get("publicPort") is None else str(d["publicPort"])
        rows.append(
            f"""
            <tr>
              <td>{d['line']}</td>
              <td>{html.escape(d['comment'])}</td>
              <td>{html.escape(d['keyType'])}</td>
              <td>{html.escape(public_port)}</td>
              <td><code>{html.escape(d['fingerprint'])}</code></td>
              <td><code>{html.escape(d['options'])}</code></td>
              <td>
                <form method="post" action="{BASE_PATH}/delete" onsubmit="return confirm('Delete device {html.escape(d['comment'])}?');">
                  <input type="hidden" name="line" value="{d['line']}">
                  <button type="submit">Delete</button>
                </form>
              </td>
            </tr>
            """
        )

    rows_html = "\n".join(rows) if rows else '<tr><td colspan="7">No devices</td></tr>'

    msg_html = f'<div class="msg ok">{html.escape(message)}</div>' if message else ""
    err_html = f'<div class="msg err">{html.escape(error)}</div>' if error else ""

    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Tunnel Device Admin</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 24px;
      background: #f6f7f9;
      color: #222;
    }}
    h1, h2 {{
      margin-bottom: 8px;
    }}
    .card {{
      background: #fff;
      border: 1px solid #ddd;
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 18px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: #fff;
    }}
    th, td {{
      border: 1px solid #ddd;
      padding: 8px 10px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: #efefef;
    }}
    input[type=text], input[type=number] {{
      width: 360px;
      max-width: 100%;
      padding: 8px;
      box-sizing: border-box;
    }}
    button {{
      padding: 10px 14px;
      cursor: pointer;
    }}
    .msg {{
      padding: 10px 12px;
      margin-bottom: 12px;
      border-radius: 6px;
    }}
    .ok {{
      background: #e9f7ef;
      border: 1px solid #b7e1c3;
    }}
    .err {{
      background: #fdecec;
      border: 1px solid #f2b8b5;
    }}
    code {{
      font-size: 12px;
      word-break: break-all;
    }}
    .hint {{
      color: #555;
      margin-top: 8px;
    }}
    form {{
      margin: 0;
    }}
  </style>
</head>
<body>
  <h1>Tunnel Device Admin</h1>

  {msg_html}
  {err_html}

  <div class="card">
    <h2>Add new device</h2>
    <form method="post" action="{BASE_PATH}/new">
      <div>
        <label for="device_name">Device name</label><br>
        <input id="device_name" name="device_name" type="text" placeholder="device1" required>
      </div>
      <div style="margin-top: 12px;">
        <label for="public_port">Fixed public relay port</label><br>
        <input id="public_port" name="public_port" type="number" min="20000" max="29999" placeholder="20023" required>	 
      </div>
      <div class="hint">
        Generates RSA 2048 keypair, stores public key in tunnel user's authorized_keys,
        stores fixed public relay port, and downloads the private key as PEM.
      </div>
      <div style="margin-top: 12px;">
        <button type="submit">Create device and download PEM</button>
      </div>
    </form>
  </div>

  <div class="card">
    <h2>Existing devices</h2>
    <table>
      <thead>
        <tr>
          <th>Line</th>
          <th>Device</th>
          <th>Key type</th>
          <th>Public port</th>
          <th>Fingerprint</th>
          <th>Options</th>
          <th>Delete</th>
        </tr>
      </thead>
      <tbody>
        {rows_html}
      </tbody>
    </table>
  </div>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def send_html(self, body: str, status=200):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str):
        self.send_response(303)
        self.send_header("Location", location)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in (BASE_PATH, BASE_PATH + "/"):
            qs = urllib.parse.parse_qs(parsed.query)
            message = qs.get("msg", [""])[0]
            error = qs.get("err", [""])[0]
            self.send_html(html_page(message=message, error=error))
            return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(content_length).decode("utf-8", errors="replace")
            form = urllib.parse.parse_qs(raw)
        except Exception:
            form = {}

        if parsed.path == BASE_PATH + "/new":
            try:
                device_name = sanitize_device_name(form.get("device_name", [""])[0])
                public_port = parse_public_port(form.get("public_port", [""])[0])

                for d in parse_authorized_keys():
                    if d["comment"] == device_name:
                        raise ValueError(f"Device '{device_name}' already exists")

                if public_port_in_use(public_port):
                    raise ValueError(f"Public port {public_port} is already assigned")

                private_key_pem, public_key = generate_rsa_2048_pem(device_name)
                public_key_line = f"restrict,port-forwarding {public_key}"
                append_public_key_line(public_key_line)

                devices_cfg = load_devices_config()
                devices_cfg.append({
                    "device": device_name,
                    "publicPort": public_port,
                })
                devices_cfg.sort(key=lambda x: x.get("publicPort", 0))
                save_devices_config(devices_cfg)

                log_audit(f"created device={device_name} publicPort={public_port}")

                filename = f"{device_name}.pem"
                data = private_key_pem.encode("utf-8")

                self.send_response(200)
                self.send_header("Content-Type", "application/x-pem-file")
                self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return

            except Exception as e:
                log_audit(f"error creating device: {e}")
                self.redirect(build_url("", "err=" + urllib.parse.quote(str(e))))
                return

        if parsed.path == BASE_PATH + "/delete":
            try:
                line_no = int(form.get("line", ["0"])[0])
                deleted = delete_device_by_line(line_no)
                device_name = deleted.get("comment", f"line {line_no}")
                log_audit(f"deleted device={device_name} line={line_no}")
                self.redirect(build_url("", "msg=" + urllib.parse.quote(f"Deleted device '{device_name}'")))
                return
            except Exception as e:
                log_audit(f"error deleting device: {e}")
                self.redirect(build_url("", "err=" + urllib.parse.quote(str(e))))
                return

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def log_message(self, format, *args):
        return


def main():
    DEVICES_FILE.parent.mkdir(parents=True, exist_ok=True)
    if not DEVICES_FILE.exists():
        save_devices_config([])

    server = HTTPServer((HOST, PORT), Handler)
    print(f"Listening on http://{HOST}:{PORT}{BASE_PATH}/")
    server.serve_forever()


if __name__ == "__main__":
    main()
