# Relestasjon exported server state

Created: 2026-06-22-145407
Source host: vm171

This directory is generated from the running server state.

Restore:

```bash
cd relestasjon-export
sudo ./install.sh
```

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
