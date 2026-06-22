#!/usr/bin/env bash
set -euo pipefail

OWNER="${RELESTASJON_OWNER:-kg9316}"
REPO_URL="${RELESTASJON_REPO_URL:-https://github.com/kg9316/relestasjon.git}"
BRANCH="${RELESTASJON_BRANCH:-main}"
USER_HOME="/home/${OWNER}"
EXPORT_DIR="${USER_HOME}/relestasjon-export"
WORK_DIR="${RELESTASJON_SYNC_WORKDIR:-/tmp/relestasjon-repo-sync}"
COMMIT_MESSAGE="${RELESTASJON_COMMIT_MESSAGE:-Sync exported relestasjon server state}"

if [[ "${EUID}" -eq 0 ]]; then
  echo "Do not run this as root. Run as ${OWNER}."
  echo "It will call sudo only for backup generation."
  exit 1
fi

if [[ "$(id -un)" != "$OWNER" ]]; then
  echo "Expected to run as $OWNER, currently $(id -un)"
  exit 1
fi

command -v git >/dev/null || { echo "git is required"; exit 1; }
command -v rsync >/dev/null || { echo "rsync is required: sudo apt install rsync"; exit 1; }

cd "$USER_HOME"

if [[ ! -x /usr/local/bin/backup-relestasjon.sh ]]; then
  echo "Installing backup script from repo"
  curl -fsSL https://raw.githubusercontent.com/kg9316/relestasjon/main/backup-relestasjon.sh \
    | sudo tee /usr/local/bin/backup-relestasjon.sh >/dev/null
  sudo chmod +x /usr/local/bin/backup-relestasjon.sh
fi

echo "[1/6] Generate fresh export"
sudo /usr/local/bin/backup-relestasjon.sh

if [[ ! -d "$EXPORT_DIR" ]]; then
  echo "ERROR: export directory missing: $EXPORT_DIR"
  exit 1
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

echo "[2/6] Clone repository"
git clone --branch "$BRANCH" "$REPO_URL" "$WORK_DIR/repo"
cd "$WORK_DIR/repo"

echo "[3/6] Sync exported tree into repo"
rsync -a --delete \
  --exclude='.git/' \
  --exclude='*.tar.gz' \
  --exclude='*.tgz' \
  --exclude='__pycache__/' \
  --exclude='*.pyc' \
  --exclude='*.bak' \
  --exclude='*.bak.*' \
  --exclude='config/letsencrypt/' \
  --exclude='**/letsencrypt/live/**' \
  --exclude='**/letsencrypt/archive/**' \
  --exclude='**/letsencrypt/renewal/**' \
  --exclude='**/sessions/**' \
  --exclude='**/psessions/**' \
  --exclude='**/lock/**' \
  "$EXPORT_DIR"/ ./

# Keep repository helper scripts if the export did not include them for any reason.
if [[ ! -f backup-relestasjon.sh ]]; then
  curl -fsSL https://raw.githubusercontent.com/kg9316/relestasjon/main/backup-relestasjon.sh -o backup-relestasjon.sh
fi
if [[ ! -f sync-current-server-to-repo.sh ]]; then
  curl -fsSL https://raw.githubusercontent.com/kg9316/relestasjon/main/sync-current-server-to-repo.sh -o sync-current-server-to-repo.sh
fi
chmod 0755 install.sh backup-relestasjon.sh sync-current-server-to-repo.sh 2>/dev/null || true

echo "[4/6] Safety scan"
if find . -path './.git' -prune -o -type f -print | grep -E 'letsencrypt/(live|archive|renewal)|/sessions/|/psessions/|__pycache__|\.pyc$|\.tar\.gz$'; then
  echo "ERROR: forbidden files found in repo sync"
  exit 1
fi

# Basic secret scan. This is intentionally narrow; it prevents obvious private key commits.
if grep -R --line-number --binary-files=without-match \
  -E 'BEGIN (RSA |DSA |EC |OPENSSH |)PRIVATE KEY|BEGIN CERTIFICATE REQUEST' . \
  --exclude-dir=.git; then
  echo "ERROR: possible private key material found. Refusing to commit."
  exit 1
fi

# Ensure minimum install tree exists.
for p in install.sh backup-relestasjon.sh bin systemd config/nginx config/ssh config/sslh config/fail2ban config/lemonldap state/tunnel-registry tunnel-user; do
  if [[ ! -e "$p" ]]; then
    echo "ERROR: required repo path missing after sync: $p"
    exit 1
  fi
done

echo "[5/6] Git status"
git status --short

if [[ -z "$(git status --porcelain)" ]]; then
  echo "No changes to commit."
  exit 0
fi

echo "[6/6] Commit and push"
git add -A
git commit -m "$COMMIT_MESSAGE"
git push origin "$BRANCH"

echo "Done. Repo updated: $REPO_URL"
