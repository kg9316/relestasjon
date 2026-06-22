#!/usr/bin/env python3
import json
import os
import signal
import socket
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

DEVICES_FILE = Path("/var/lib/tunnel-registry/devices.json")
ACTIVE_TUNNELS_FILE = Path("/var/lib/tunnel-registry/active-tunnels.json")
STATE_FILE = Path("/var/lib/tunnel-registry/relay-state.json")
LOG_FILE = Path("/var/log/tunnel-relay-manager.log")


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def log(msg):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"{utc_now_iso()} {msg}\n")


def load_json(path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def save_state(state):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    STATE_FILE.chmod(0o644)


def port_is_free(port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def is_pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def stop_pid(pid: int):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return

    for _ in range(20):
        if not is_pid_alive(pid):
            return
        time.sleep(0.2)

    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def start_relay(public_port: int, tunnel_port: int):
    cmd = [
        "socat",
        f"TCP-LISTEN:{public_port},reuseaddr,fork",
        f"TCP:127.0.0.1:{tunnel_port}",
    ]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return proc.pid


def build_desired_relays():
    devices = load_json(DEVICES_FILE, [])
    active = load_json(ACTIVE_TUNNELS_FILE, [])

    active_by_device = {}
    for item in active:
        device = item.get("device")
        ports = item.get("ports") or []
        if device and ports:
            active_by_device[device] = int(ports[0])

    desired = {}
    for d in devices:
        device = d.get("device")
        public_port = d.get("publicPort")
        tunnel_port = active_by_device.get(device)
        if device and public_port and tunnel_port:
            desired[device] = {
                "device": device,
                "publicPort": int(public_port),
                "tunnelPort": int(tunnel_port),
            }

    return desired


def reconcile():
    state = load_json(STATE_FILE, {})
    desired = build_desired_relays()

    cleaned_state = {}
    for device, entry in state.items():
        pid = entry.get("pid")
        if pid and is_pid_alive(pid):
            cleaned_state[device] = entry
    state = cleaned_state

    for device, entry in list(state.items()):
        wanted = desired.get(device)
        pid = entry.get("pid")

        if not wanted:
            log(f"Stopping relay for offline/deleted device {device}, pid={pid}")
            stop_pid(pid)
            state.pop(device, None)
            continue

        if (
            entry.get("publicPort") != wanted["publicPort"]
            or entry.get("tunnelPort") != wanted["tunnelPort"]
        ):
            log(
                f"Restarting relay for {device}: "
                f"{entry.get('publicPort')}->{entry.get('tunnelPort')} "
                f"to {wanted['publicPort']}->{wanted['tunnelPort']}"
            )
            stop_pid(pid)
            state.pop(device, None)

    used_public_ports = {entry["publicPort"] for entry in state.values()}

    for device, wanted in desired.items():
        if device in state:
            continue

        public_port = wanted["publicPort"]
        tunnel_port = wanted["tunnelPort"]

        if public_port in used_public_ports:
            log(f"Cannot start relay for {device}, public port {public_port} already in use in state")
            continue

        if not port_is_free(public_port):
            log(f"Cannot start relay for {device}, public port {public_port} is busy on system")
            continue

        pid = start_relay(public_port, tunnel_port)
        state[device] = {
            "pid": pid,
            "device": device,
            "publicPort": public_port,
            "tunnelPort": tunnel_port,
            "startedAt": utc_now_iso(),
        }
        used_public_ports.add(public_port)
        log(f"Started relay for {device}: 0.0.0.0:{public_port} -> 127.0.0.1:{tunnel_port}, pid={pid}")

    save_state(state)


def main():
    while True:
        try:
            reconcile()
        except Exception as e:
            log(f"ERROR: {e}")
        time.sleep(2)


if __name__ == "__main__":
    main()
