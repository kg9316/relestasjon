#!/usr/bin/env bash
set -euo pipefail

REPO_TARBALL_URL="${RELESTASJON_REPO_TARBALL_URL:-https://github.com/kg9316/relestasjon/archive/refs/heads/main.tar.gz}"
WORK_DIR="${RELESTASJON_WORK_DIR:-/tmp/relestasjon-install}"
BACKUP_DIR="/root/relestasjon-restore-backup-$(date +%F-%H%M%S)"
BASE_DIR="$(cd "$(dirname "$0")" && pwd)"
DRY_RUN=0
ALLOW_MISSING_CERTS=0

for arg in "$@"; do
  case "$arg" in
    --check|--dry-run) DRY_RUN=1 ;;
    --allow-missing-certs) ALLOW_MISSING_CERTS=1 ;;
    *) echo "Unknown argument: $arg"; exit 2 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo ./install.sh"
  exit 1
fi

has_export_tree() {
  [[ -d "$BASE_DIR/bin" && -d "$BASE_DIR/systemd" && -d "$BASE_DIR/config" ]]
}

# Support curl | sudo bash from GitHub.
# In that mode $BASE_DIR is not a repo/export dir, so fetch the repo tarball.
if ! has_export_tree; then
  echo "No local export tree found beside install.sh. Fetching repository tarball."
  rm -rf "$WORK_DIR"
  mkdir -p "$WORK_DIR"
  apt-get update
  apt-get install -y curl tar gzip
  curl -fsSL "$REPO_TARBALL_URL" -o "$WORK_DIR/repo.tar.gz"
  tar xzf "$WORK_DIR/repo.tar.gz" -C "$WORK_DIR"
  BASE_DIR="$(find "$WORK_DIR" -maxdepth 1 -type d -name 'relestasjon-*' | head -1)"
fi

if ! has_export_tree; then
  cat >&2 <<EOF
ERROR: no installable export tree found.

This installer requires an exported tree containing:
  bin/
  systemd/
  config/

On the live server, run:
  curl -fsSL https://raw.githubusercontent.com/kg9316/relestasjon/main/backup-relestasjon.sh | sudo tee /usr/local/bin/backup-relestasjon.sh >/dev/null
  sudo chmod +x /usr/local/bin/backup-relestasjon.sh
  cd /home/kg9316
  sudo /usr/local/bin/backup-relestasjon.sh

Then install from the generated relestasjon-export directory:
  cd /home/kg9316/relestasjon-export
  sudo ./install.sh
EOF
  exit 1
fi

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf 'DRY-RUN:'
    printf ' %q' "$@"
    printf '\n'
  else
    "$@"
  fi
}

copy_dir_contents() {
  local src="$1"
  local dst="$2"
  [[ -d "$src" ]] || return 0
  run mkdir -p "$dst"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "DRY-RUN: copy contents $src -> $dst"
  else
    cp -a "$src"/. "$dst"/
  fi
}

copy_file() {
  local src="$1"
  local dst="$2"
  [[ -f "$src" ]] || return 0
  run mkdir -p "$(dirname "$dst")"
  run cp -a "$src" "$dst"
}

backup_path() {
  local p="$1"
  [[ -e "$p" ]] || return 0
  mkdir -p "$BACKUP_DIR$(dirname "$p")"
  cp -a "$p" "$BACKUP_DIR$p"
}

require_file() {
  local p="$1"
  if [[ ! -f "$p" ]]; then
    echo "ERROR: missing required file in export: $p" >&2
    exit 1
  fi
}

require_dir() {
  local p="$1"
  if [[ ! -d "$p" ]]; then
    echo "ERROR: missing required directory in export: $p" >&2
    exit 1
  fi
}

echo "[1/10] Validate export tree"
require_dir "$BASE_DIR/bin"
require_dir "$BASE_DIR/systemd"
require_dir "$BASE_DIR/config/nginx"
require_dir "$BASE_DIR/config/ssh"
require_file "$BASE_DIR/config/sslh/sslh"
require_file "$BASE_DIR/tunnel-user/authorized_keys"

if compgen -G "$BASE_DIR/bin/tunnel-*.py" >/dev/null; then
  true
else
  echo "ERROR: no tunnel Python scripts found in $BASE_DIR/bin" >&2
  exit 1
fi

echo "[2/10] Install packages"
export DEBIAN_FRONTEND=noninteractive
run apt-get update
run apt-get install -y \
  openssh-server \
  nginx \
  sslh \
  python3 \
  socat \
  ufw \
  fail2ban \
  apache2-utils \
  certbot \
  python3-certbot-nginx \
  lemonldap-ng

echo "[3/10] Backup current config to $BACKUP_DIR"
if [[ "$DRY_RUN" -eq 0 ]]; then
  mkdir -p "$BACKUP_DIR"
  backup_path /usr/local/bin/backup-relestasjon.sh
  backup_path /usr/local/bin/tunnel-admin.py
  backup_path /usr/local/bin/tunnel-registry.py
  backup_path /usr/local/bin/tunnel-registry-http.py
  backup_path /usr/local/bin/tunnel-relay-manager.py
  backup_path /etc/systemd/system/tunnel-admin.service
  backup_path /etc/systemd/system/tunnel-registry.service
  backup_path /etc/systemd/system/tunnel-registry.timer
  backup_path /etc/systemd/system/tunnel-registry-http.service
  backup_path /etc/systemd/system/tunnel-relay-manager.service
  backup_path /etc/nginx
  backup_path /etc/ssh/sshd_config
  backup_path /etc/ssh/sshd_config.d
  backup_path /etc/default/sslh
  backup_path /etc/fail2ban
  backup_path /etc/lemonldap-ng
  backup_path /var/lib/lemonldap-ng
  backup_path /var/lib/tunnel-registry
  backup_path /home/tunnel/.ssh/authorized_keys
fi

echo "[4/10] Restore files"
if [[ "$DRY_RUN" -eq 0 ]]; then
  cp -a "$BASE_DIR/bin"/tunnel-*.py /usr/local/bin/
  chmod 0755 /usr/local/bin/tunnel-*.py

  cp -a "$BASE_DIR/systemd"/tunnel-* /etc/systemd/system/ 2>/dev/null || true

  rm -rf /etc/nginx
  cp -a "$BASE_DIR/config/nginx" /etc/nginx

  cp -a "$BASE_DIR/config/ssh/sshd_config" /etc/ssh/sshd_config
  rm -rf /etc/ssh/sshd_config.d
  cp -a "$BASE_DIR/config/ssh/sshd_config.d" /etc/ssh/sshd_config.d

  cp -a "$BASE_DIR/config/sslh/sslh" /etc/default/sslh

  rm -rf /etc/fail2ban
  cp -a "$BASE_DIR/config/fail2ban" /etc/fail2ban

  rm -rf /etc/lemonldap-ng
  cp -a "$BASE_DIR/config/lemonldap/etc-lemonldap-ng" /etc/lemonldap-ng

  mkdir -p /var/lib/lemonldap-ng
  if [[ -d "$BASE_DIR/config/lemonldap/var-lib-lemonldap-ng" ]]; then
    cp -a "$BASE_DIR/config/lemonldap/var-lib-lemonldap-ng"/. /var/lib/lemonldap-ng/
  fi

  mkdir -p /var/lib/tunnel-registry
  cp -a "$BASE_DIR/state/tunnel-registry"/. /var/lib/tunnel-registry/ 2>/dev/null || true

  cp -a "$BASE_DIR/backup/backup-relestasjon.sh" /usr/local/bin/backup-relestasjon.sh 2>/dev/null || true
  chmod 0755 /usr/local/bin/backup-relestasjon.sh 2>/dev/null || true
fi

echo "[5/10] Ensure tunnel user"
if [[ "$DRY_RUN" -eq 0 ]]; then
  id tunnel >/dev/null 2>&1 || useradd -m -s /bin/bash tunnel
  mkdir -p /home/tunnel/.ssh
  cp -a "$BASE_DIR/tunnel-user/authorized_keys" /home/tunnel/.ssh/authorized_keys
  chown -R tunnel:tunnel /home/tunnel/.ssh
  chmod 700 /home/tunnel/.ssh
  chmod 600 /home/tunnel/.ssh/authorized_keys
fi

echo "[6/10] Check certificate references"
missing_cert_refs=0
if grep -R "/etc/letsencrypt/live\|/etc/letsencrypt/archive" /etc/nginx /etc/lemonldap-ng >/tmp/relestasjon-cert-refs.txt 2>/dev/null; then
  while IFS= read -r line; do
    cert_path="$(printf '%s\n' "$line" | grep -oE '/etc/letsencrypt/[^ ;]+' | head -1 || true)"
    cert_path="${cert_path%;}"
    cert_path="${cert_path%\"}"
    cert_path="${cert_path%'}"
    if [[ -n "$cert_path" && ! -e "$cert_path" ]]; then
      echo "Missing certificate path referenced by config: $cert_path"
      missing_cert_refs=1
    fi
  done < /tmp/relestasjon-cert-refs.txt
fi

if [[ "$missing_cert_refs" -eq 1 && "$ALLOW_MISSING_CERTS" -ne 1 ]]; then
  cat >&2 <<EOF
ERROR: certificate files referenced by config are missing.

This backup intentionally does not include Let's Encrypt private keys.
Restore/create certificates first, or rerun with:
  sudo ./install.sh --allow-missing-certs

Note: nginx restart will still fail if required cert files are missing.
EOF
  exit 1
fi

echo "[7/10] Validate ssh/nginx"
run systemctl daemon-reload
run sshd -t
run nginx -t

echo "[8/10] Validate effective SSH security"
if [[ "$DRY_RUN" -eq 0 ]]; then
  sshd -T | grep -qx 'pubkeyauthentication yes'
  sshd -T | grep -qx 'passwordauthentication no'
  sshd -T | grep -qx 'kbdinteractiveauthentication no'
fi

echo "[9/10] Enable and restart services"
run systemctl enable --now ssh
run systemctl enable --now sslh
run systemctl enable --now nginx
run systemctl enable --now fail2ban
run systemctl restart ssh
run systemctl restart sslh
run systemctl restart nginx
run systemctl restart fail2ban
run systemctl enable --now tunnel-admin.service
run systemctl enable --now tunnel-registry.timer
run systemctl enable --now tunnel-registry-http.service
run systemctl enable --now tunnel-relay-manager.service

echo "[10/10] Done"
echo "Previous config backup: $BACKUP_DIR"
echo
echo "Verify:"
echo "  systemctl status sslh nginx ssh fail2ban"
echo "  systemctl status tunnel-registry.timer tunnel-registry-http.service tunnel-relay-manager.service"
echo "  cat /var/lib/tunnel-registry/active-tunnels.json"
