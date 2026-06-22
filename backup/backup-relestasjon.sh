#!/usr/bin/env bash
set -euo pipefail

OWNER="${RELESTASJON_OWNER:-kg9316}"
USER_HOME="/home/${OWNER}"
TS="$(date +%F-%H%M%S)"
EXPORT_NAME="relestasjon-export"
EXPORT_DIR="${USER_HOME}/${EXPORT_NAME}"
ARCHIVE="${USER_HOME}/${EXPORT_NAME}-${TS}.tar.gz"
REPO_RAW_BASE="${RELESTASJON_REPO_RAW_BASE:-https://raw.githubusercontent.com/kg9316/relestasjon/main}"

current_dir="$(pwd -P 2>/dev/null || true)"
if [[ -n "$current_dir" && "$current_dir" == "$EXPORT_DIR"* ]]; then
  echo "ERROR: current directory is inside $EXPORT_DIR"
  echo "Run: cd $USER_HOME"
  exit 1
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo /usr/local/bin/backup-relestasjon.sh"
  exit 1
fi

if ! id "$OWNER" >/dev/null 2>&1; then
  echo "ERROR: user $OWNER does not exist"
  exit 1
fi

copy_dir_contents() {
  local src="$1"
  local dst="$2"
  mkdir -p "$dst"
  if [[ -d "$src" ]]; then
    cp -a "$src"/. "$dst"/
  fi
}

copy_file() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
  fi
}

safe_json_copy() {
  local src="$1"
  local dst="$2"
  if [[ -f "$src" ]]; then
    mkdir -p "$(dirname "$dst")"
    cp -a "$src" "$dst"
  fi
}

rm -rf "$EXPORT_DIR"
mkdir -p \
  "$EXPORT_DIR/bin" \
  "$EXPORT_DIR/systemd" \
  "$EXPORT_DIR/config/nginx" \
  "$EXPORT_DIR/config/ssh" \
  "$EXPORT_DIR/config/sslh" \
  "$EXPORT_DIR/config/fail2ban" \
  "$EXPORT_DIR/config/lemonldap/etc-lemonldap-ng" \
  "$EXPORT_DIR/config/lemonldap/var-lib-lemonldap-ng" \
  "$EXPORT_DIR/state/tunnel-registry" \
  "$EXPORT_DIR/tunnel-user" \
  "$EXPORT_DIR/docs" \
  "$EXPORT_DIR/backup"

echo "[1/11] Export tunnel scripts"
cp -a /usr/local/bin/tunnel-*.py "$EXPORT_DIR/bin/" 2>/dev/null || true
rm -rf "$EXPORT_DIR/bin/__pycache__"
find "$EXPORT_DIR/bin" -name '*.bak*' -delete 2>/dev/null || true

# Keep the backup script itself in the export.
copy_file /usr/local/bin/backup-relestasjon.sh "$EXPORT_DIR/backup/backup-relestasjon.sh"

# If this script was run directly from a repo checkout, include the repo install.sh.
if [[ -f "$(dirname "$0")/install.sh" ]]; then
  copy_file "$(dirname "$0")/install.sh" "$EXPORT_DIR/install.sh"
fi

# If install.sh was not copied from a local checkout, download from repo raw URL.
if [[ ! -f "$EXPORT_DIR/install.sh" ]]; then
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$REPO_RAW_BASE/install.sh" -o "$EXPORT_DIR/install.sh" || true
  fi
fi
chmod 0755 "$EXPORT_DIR/install.sh" 2>/dev/null || true

echo "[2/11] Export systemd tunnel units"
cp -a /etc/systemd/system/tunnel-* "$EXPORT_DIR/systemd/" 2>/dev/null || true
rm -rf "$EXPORT_DIR/systemd"/*.wants 2>/dev/null || true

echo "[3/11] Export nginx"
copy_dir_contents /etc/nginx "$EXPORT_DIR/config/nginx"
rm -rf "$EXPORT_DIR/config/nginx"/**/__pycache__ 2>/dev/null || true

echo "[4/11] Export sshd"
copy_file /etc/ssh/sshd_config "$EXPORT_DIR/config/ssh/sshd_config"
copy_dir_contents /etc/ssh/sshd_config.d "$EXPORT_DIR/config/ssh/sshd_config.d"

echo "[5/11] Export sslh"
copy_file /etc/default/sslh "$EXPORT_DIR/config/sslh/sslh"

echo "[6/11] Export fail2ban"
copy_dir_contents /etc/fail2ban "$EXPORT_DIR/config/fail2ban"
# Defend against accidental nested copies from earlier manual exports.
rm -rf "$EXPORT_DIR/config/fail2ban/fail2ban" 2>/dev/null || true

echo "[7/11] Export LemonLDAP config"
copy_dir_contents /etc/lemonldap-ng "$EXPORT_DIR/config/lemonldap/etc-lemonldap-ng"
copy_dir_contents /var/lib/lemonldap-ng/conf "$EXPORT_DIR/config/lemonldap/var-lib-lemonldap-ng/conf"
# Deliberately do not export LemonLDAP sessions, psessions, locks, or private runtime files.

echo "[8/11] Export tunnel registry state"
safe_json_copy /var/lib/tunnel-registry/devices.json "$EXPORT_DIR/state/tunnel-registry/devices.json"
safe_json_copy /var/lib/tunnel-registry/active-tunnels.json "$EXPORT_DIR/state/tunnel-registry/active-tunnels.json"
safe_json_copy /var/lib/tunnel-registry/relay-state.json "$EXPORT_DIR/state/tunnel-registry/relay-state.json"
safe_json_copy /var/lib/tunnel-registry/public-session-state.json "$EXPORT_DIR/state/tunnel-registry/public-session-state.json"

echo "[9/11] Export tunnel authorized_keys"
copy_file /home/tunnel/.ssh/authorized_keys "$EXPORT_DIR/tunnel-user/authorized_keys"

echo "[10/11] Write diagnostics"
sshd -T > "$EXPORT_DIR/docs/sshd-effective.txt" 2>&1 || true
nginx -T > "$EXPORT_DIR/docs/nginx-effective.conf" 2>&1 || true
certbot certificates > "$EXPORT_DIR/docs/certbot-certificates.txt" 2>&1 || true
ss -ltnp > "$EXPORT_DIR/docs/listening-ports.txt" 2>&1 || true
fail2ban-client status sshd > "$EXPORT_DIR/docs/fail2ban-sshd-status.txt" 2>&1 || true
systemctl list-unit-files | grep -E 'tunnel|sslh|fail2ban|nginx|ssh' > "$EXPORT_DIR/docs/unit-files.txt" 2>&1 || true
systemctl cat sslh ssh nginx fail2ban tunnel-admin.service tunnel-registry.service tunnel-registry.timer tunnel-registry-http.service tunnel-relay-manager.service \
  > "$EXPORT_DIR/docs/systemd-current.txt" 2>&1 || true
find /etc/letsencrypt/live -maxdepth 2 -type l -o -type f 2>/dev/null > "$EXPORT_DIR/docs/letsencrypt-layout.txt" || true
find "$EXPORT_DIR" -xtype l -print > "$EXPORT_DIR/docs/broken-symlinks.txt" || true
find "$EXPORT_DIR" -type f | sort > "$EXPORT_DIR/docs/file-list.txt"

cat > "$EXPORT_DIR/README.md" <<README
# Relestasjon exported server state

Created: ${TS}
Source host: $(hostname)

This directory is generated from the running server state.

Restore:

\`\`\`bash
cd relestasjon-export
sudo ./install.sh
\`\`\`

Included:

- tunnel Python scripts
- tunnel systemd units
- nginx config
- sshd config
- sslh config
- fail2ban config
- LemonLDAP::NG config and configuration state
- tunnel registry state
- tunnel user's authorized_keys
- backup script
- diagnostics

Excluded intentionally:

- Let's Encrypt private keys and archive material
- LemonLDAP sessions and locks
- system logs
- Python __pycache__
- old .bak tunnel scripts
README

# Remove unwanted generated/runtime files from the exported copy.
find "$EXPORT_DIR" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
find "$EXPORT_DIR" -type f -name '*.pyc' -delete 2>/dev/null || true
find "$EXPORT_DIR" -type f -name '*.bak' -delete 2>/dev/null || true
find "$EXPORT_DIR" -type f -name '*.bak.*' -delete 2>/dev/null || true

echo "[11/11] Set ownership and archive"
chown -R "$OWNER:$OWNER" "$EXPORT_DIR"

cd "$USER_HOME"
tar czf "$ARCHIVE" "$EXPORT_NAME"
chown "$OWNER:$OWNER" "$ARCHIVE"

echo
echo "Backup complete:"
echo "$ARCHIVE"
ls -lh "$ARCHIVE"
echo
echo "Sanity checks:"
echo "  tar tzf '$ARCHIVE' | grep '/install.sh'"
echo "  tar tzf '$ARCHIVE' | grep '__pycache__' || true"
echo "  tar tzf '$ARCHIVE' | grep 'letsencrypt/archive' || true"
