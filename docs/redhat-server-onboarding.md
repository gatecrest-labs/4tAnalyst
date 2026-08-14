# Deploying to an Existing Red Hat Server

This guide covers adding 4tAnalyst to a Red Hat Enterprise Linux (RHEL 8/9) server
that is already running — alongside other services. It assumes the base installation
steps in [installation.md](installation.md) have been completed (Python 3.11, uv,
4tanalyst service account, repo clone, virtualenv, credentials.yaml).

If you are starting from scratch on a new server, follow [installation.md](installation.md)
first, then return here for the web admin specific steps.

---

## 1. Verify the existing service is running

```bash
sudo systemctl status 4tanalyst
# Should show: active (running)
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health || echo "not yet running"
```

---

## 2. Pull the mcp-web branch

```bash
sudo -u 4tanalyst git -C /opt/4tanalyst pull
sudo -u 4tanalyst git -C /opt/4tanalyst checkout mcp-web
```

If you are already on `main`/`development` and the branch has been merged:

```bash
sudo -u 4tanalyst git -C /opt/4tanalyst pull origin main
```

---

## 3. Install new Python dependencies

The web admin adds `fastapi`, `python-multipart`, `psutil`, and `bcrypt`:

```bash
sudo -u 4tanalyst bash -c "
  cd /opt/4tanalyst
  uv pip install -e mcp_common/ -e standards_mcp/ -e fortimanager_mcp/ \
      -e feedback_mcp/ -e intake_mcp/ -e zone_mcp/ -e planner/ -e fwanalyst_server/
"
```

Verify:
```bash
sudo -u 4tanalyst uv run python -c "import fastapi, psutil, bcrypt; print('OK')"
```

---

## 4. Add web_admin config to credentials.yaml

```bash
# Generate a secret key
python3 -c "import secrets; print(secrets.token_hex(32))"
```

Edit `/opt/4tanalyst/credentials.yaml` and add:

```yaml
web_admin:
  secret_key: "<output from above>"    # required — keep this secret
  session_lifetime_hours: 8
  analytics_retention_days: 90

pricing:
  claude-sonnet-5:
    input_per_million: 3.00
    output_per_million: 15.00
  default:
    input_per_million: 3.00
    output_per_million: 15.00
```

Protect the file (it now holds the web secret key as well as API keys):

```bash
sudo chmod 600 /opt/4tanalyst/credentials.yaml
sudo chown 4tanalyst:4tanalyst /opt/4tanalyst/credentials.yaml
```

---

## 5. Ensure the data/ directory exists and is writable

```bash
sudo mkdir -p /opt/4tanalyst/data
sudo chown 4tanalyst:4tanalyst /opt/4tanalyst/data
sudo chmod 750 /opt/4tanalyst/data
```

The service writes `analytics.db` and `users.json` here at runtime.

---

## 6. Create the first admin user

```bash
sudo -u 4tanalyst bash -c "
  cd /opt/4tanalyst
  uv run python -m fwanalyst_server.admin create-user <your-username> --role admin
"
# Password prompted interactively
```

---

## 7. Restart the service

```bash
sudo systemctl restart 4tanalyst
sudo systemctl status 4tanalyst
```

Verify the admin UI is reachable locally:

```bash
curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/admin/login
# Expected: 200
```

---

## 8. Open port 8000 in firewalld (if not already open)

If engineers access the server directly on port 8000 (no nginx yet):

```bash
sudo firewall-cmd --permanent --add-port=8000/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-ports   # confirm
```

If you are running nginx as a TLS reverse proxy (recommended — see [tls-setup.md](tls-setup.md)),
port 8000 should remain restricted to `localhost` and only port 443 opened:

```bash
# Do NOT open 8000 externally if nginx is in place
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

---

## 9. SELinux considerations (RHEL with enforcing mode)

If SELinux is enforcing, the Python process may be blocked from binding to port 8000
or writing to `/opt/4tanalyst/data/`:

```bash
# Check current mode
getenforce

# Allow the 4tanalyst service user to write to the data directory
sudo semanage fcontext -a -t var_t "/opt/4tanalyst/data(/.*)?"
sudo restorecon -Rv /opt/4tanalyst/data/

# If the port is not in SELinux's allowed list for the service user:
sudo semanage port -a -t http_port_t -p tcp 8000
```

If you hit `Permission denied` errors in `journalctl -u 4tanalyst`, check with:
```bash
sudo ausearch -m avc -ts recent | audit2why
```

---

## 10. nginx reverse proxy for the admin UI

If you already have nginx serving the MCP server on port 443, the admin UI is
included automatically — it runs on the same port 8000. No nginx config change is
needed unless you want to restrict `/admin` to an internal CIDR:

```nginx
# Optional: restrict admin to internal network only
location /admin {
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    deny all;
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}

location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    # SSE / long-poll support for MCP streaming
    proxy_read_timeout 600s;
    proxy_buffering off;
}
```

---

## 11. Verify the full deployment

```bash
# Service is running
sudo systemctl is-active 4tanalyst

# MCP endpoint still responds (requires bearer token)
curl -s -o /dev/null -w "MCP: %{http_code}\n" \
    -H "Authorization: Bearer <your-token>" \
    http://localhost:8000/mcp

# Admin login page loads
curl -s -o /dev/null -w "Admin: %{http_code}\n" http://localhost:8000/admin/login

# No errors in the last 50 log lines
sudo journalctl -u 4tanalyst -n 50 --no-pager | grep -i error || echo "No errors"
```

---

## Rollback

If anything goes wrong:

```bash
sudo systemctl stop 4tanalyst
sudo -u 4tanalyst git -C /opt/4tanalyst checkout development   # or main
sudo -u 4tanalyst uv pip install -e fwanalyst_server/
sudo systemctl start 4tanalyst
```

The `data/analytics.db` and `data/users.json` files are not affected by a branch switch
and do not need to be restored.
