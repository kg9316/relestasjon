# relestasjon

Backup and restore tooling for the running `relestasjon.no` tunnel/LemonLDAP server.

This repository is intended to be built from the **actual server state**, not from the older `tunnel-node` repository.

## Current live architecture

- Ubuntu 24.04 server: `vm171`
- Public domain: `relestasjon.no`
- SSLH listens on public TCP/443
  - SSH -> `127.0.0.1:2222`
  - TLS/HTTPS -> `127.0.0.1:4443`
- nginx serves HTTPS behind SSLH
- LemonLDAP::NG protects web access
- JACE devices use reverse SSH through port 443
- Tunnel registry tracks dynamic SSH remote ports
- Relay manager maps fixed public ports to dynamic tunnel ports
- Fail2Ban protects SSH

## Active services expected

```bash
systemctl list-unit-files | grep -E 'tunnel|sslh|fail2ban|nginx|ssh'
```

Expected services:

```text
fail2ban.service
a nginx.service
ssh.service
sslh.service
tunnel-admin.service
tunnel-registry-http.service
tunnel-registry.service
tunnel-relay-manager.service
tunnel-registry.timer
```

## Backup on the live server

Install/update the backup script from this repository:

```bash
curl -fsSL https://raw.githubusercontent.com/kg9316/relestasjon/main/backup-relestasjon.sh | sudo tee /usr/local/bin/backup-relestasjon.sh >/dev/null
sudo chmod +x /usr/local/bin/backup-relestasjon.sh
```

Run backup:

```bash
cd /home/kg9316
sudo /usr/local/bin/backup-relestasjon.sh
```

Output:

```text
/home/kg9316/relestasjon-export-YYYY-MM-DD-HHMMSS.tar.gz
/home/kg9316/relestasjon-export/
```

The archive can be downloaded with WinSCP from `/home/kg9316`.

## Restore on a blank server

Upload or clone the generated `relestasjon-export` folder, then run:

```bash
cd relestasjon-export
sudo ./install.sh
```

Or install directly from repo defaults:

```bash
curl -fsSL https://raw.githubusercontent.com/kg9316/relestasjon/main/install.sh | sudo bash
```

Direct repo install only works after this repo contains a valid exported config tree.

## Important security note

Do not commit private keys or active session files.

The backup script intentionally excludes:

- `/etc/letsencrypt/live`, `/etc/letsencrypt/archive`, `/etc/letsencrypt/renewal` private cert material
- LemonLDAP session directories
- Python `__pycache__`
- local backup tarballs

Certificates must be recreated/restored separately on a new host.
