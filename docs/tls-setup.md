# TLS Setup

The 4tAnalyst MCP server listens on port 8000 over plain HTTP. Before engineers connect from their workstations — especially in any regulated environment (NERC CIP, HIPAA, PCI-DSS, SOX) — TLS must be in place so that bearer tokens and firewall data are not transmitted in cleartext.

Two paths are covered below:
- **Direct uvicorn TLS** — simplest for a pilot: uvicorn terminates TLS itself, no reverse proxy. Fewer moving parts, but no rotation/mTLS/HA story.
- **nginx reverse proxy** — the scale-up path once you need certificate rotation, mTLS, or to put more than one service behind the same host. Two certificate options are covered under it:
  - **Option A: Self-signed certificate** — quick to set up, suitable for lab/pilot use; engineers must trust the cert manually
  - **Option B: Internal CA certificate** — proper for production; uses your organization's certificate authority so engineers trust it automatically via their existing domain trust

---

## Option: direct uvicorn TLS (simplest for pilot)

uvicorn (the ASGI server `fwanalyst_server/__main__.py` runs under in HTTP mode) accepts `ssl_certfile`/`ssl_keyfile` directly — no nginx, no reverse proxy, one process terminates TLS and serves `/mcp`. This is the fastest way to get off plain HTTP for a pilot; graduate to the nginx path below when you need certificate rotation without a restart, mTLS, or to host more than one service on the box.

Get a cert from your internal CA the same way as Option B below (CSR → sign → copy `server.crt`/`server.key` to the server), then point the server at them via environment variables:

```bash
export FW_ANALYST_SSL_CERTFILE=/etc/4tanalyst/tls/server.crt
export FW_ANALYST_SSL_KEYFILE=/etc/4tanalyst/tls/server.key
```

Setting both env vars is sufficient: `fwanalyst_server/__main__.py` starts uvicorn with `ssl_certfile=`/`ssl_keyfile=` when they are present. The equivalent `credentials.yaml` keys are `server.ssl_certfile` / `server.ssl_keyfile`; the environment variables win, matching the precedence used for `FW_ANALYST_TOKEN` and `FW_ANALYST_ALLOWED_HOSTS`. Set **both or neither** — setting only one is a configuration error and the server refuses to start rather than silently falling back to plain HTTP.

> **Warning:** If nginx is handling TLS termination (Options A and B below), do NOT set `ssl_certfile`/`ssl_keyfile` in `credentials.yaml` or as environment variables. Those settings are only for the direct-uvicorn-TLS path.

**Critical coupling — do not skip this:** the hostname engineers connect to (the TLS cert's CN/SAN) must also be added to `FW_ANALYST_ALLOWED_HOSTS` (or `credentials.yaml` `server.allowed_hosts`). DNS-rebinding protection checks the `Host` header against that allowlist independently of TLS — a valid cert with an unlisted hostname still gets every engineer request rejected. See [Configuration](configuration.md) for `FW_ANALYST_ALLOWED_HOSTS`.

> **Note:** When nginx is terminating TLS, set `allowed_hosts` to the bare hostname with no port — e.g. `["4tanalyst.xcelenergy.com"]`, not `["4tanalyst.xcelenergy.com:8000"]`. The `:port` form is only correct when engineers connect directly to uvicorn.

With this approach the server listens on 443 directly (or another port of your choosing) — there is no separate nginx `location /mcp` config to keep in sync, and no `127.0.0.1:8000`-only lockdown step. Firewall/security-group rules should still restrict inbound access to the engineer subnet.

---

## Prerequisites

Install nginx on the server:

```bash
# RHEL 8/9
sudo dnf install -y nginx

# Ubuntu 22.04
sudo apt install -y nginx
```

Enable and start nginx:

```bash
sudo systemctl enable nginx
sudo systemctl start nginx
```

---

## Option A: Self-signed certificate

### 1. Generate the certificate

```bash
sudo mkdir -p /etc/4tanalyst/tls
sudo chown root:4tanalyst /etc/4tanalyst
sudo chmod 750 /etc/4tanalyst
sudo chown root:4tanalyst /etc/4tanalyst/tls
sudo chmod 750 /etc/4tanalyst/tls
sudo openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout /etc/4tanalyst/tls/server.key \
  -out /etc/4tanalyst/tls/server.crt \
  -days 825 \
  -subj "/CN=4tanalyst-server" \
  -addext "subjectAltName=IP:<server-ip>"
sudo chmod 600 /etc/4tanalyst/tls/server.key
```

> **Note:** Both the parent directory and `tls/` subdirectory must be group-accessible to the `4tanalyst` service account — a common miss that causes `PermissionError` on startup.

Replace `<server-ip>` with the server's IP address (e.g. `10.0.0.1`). The SAN extension is required — modern clients reject certs without it.

### 2. Configure nginx

Create `/etc/nginx/conf.d/4tanalyst.conf`:

```nginx
server {
    listen 443 ssl;
    server_name _;

    ssl_certificate     /etc/4tanalyst/tls/server.crt;
    ssl_certificate_key /etc/4tanalyst/tls/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location /mcp {
        proxy_pass         http://127.0.0.1:8000/mcp;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   Connection "";
        proxy_buffering    off;
        proxy_read_timeout 300s;
    }

    location /admin {
        proxy_pass         http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_buffering    off;
        proxy_read_timeout 60s;
    }

    location /api {
        proxy_pass         http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_buffering    off;
        proxy_read_timeout 60s;
    }
}

# Redirect plain HTTP to HTTPS
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

### 3. Test and reload nginx

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 4. Open port 443 in the firewall

```bash
# RHEL
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

# Ubuntu
sudo ufw allow 443/tcp
```

### 5. Distribute the certificate to engineers

Engineers must trust the self-signed cert manually. Send them `/etc/4tanalyst/tls/server.crt` over a secure channel and have them add it to their system trust store:

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain server.crt
```

**Windows (run as Administrator):**
```powershell
Import-Certificate -FilePath server.crt -CertStoreLocation Cert:\LocalMachine\Root
```

**Linux:**
```bash
sudo cp server.crt /etc/pki/ca-trust/source/anchors/   # RHEL
sudo update-ca-trust                                    # RHEL
# or
sudo cp server.crt /usr/local/share/ca-certificates/   # Ubuntu
sudo update-ca-certificates                             # Ubuntu
```

---

## Option B: Internal CA certificate

This is the correct approach for production. Your organization's CA is already trusted on all domain-joined machines, so engineers need no manual steps.

### 1. Generate a certificate signing request (CSR)

```bash
sudo mkdir -p /etc/4tanalyst/tls
sudo chown root:4tanalyst /etc/4tanalyst
sudo chmod 750 /etc/4tanalyst
sudo chown root:4tanalyst /etc/4tanalyst/tls
sudo chmod 750 /etc/4tanalyst/tls
sudo openssl req -new -newkey rsa:4096 -nodes \
  -keyout /etc/4tanalyst/tls/server.key \
  -out /etc/4tanalyst/tls/server.csr \
  -subj "/CN=<server-hostname-or-ip>/O=<your-org>"
sudo chmod 600 /etc/4tanalyst/tls/server.key
```

> **Note:** Both the parent directory and `tls/` subdirectory must be group-accessible to the `4tanalyst` service account — a common miss that causes `PermissionError` on startup.

If your CA requires a SAN extension in the CSR, create an extensions file first:

```bash
cat <<EOF | sudo tee /etc/4tanalyst/tls/san.cnf
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
[req_distinguished_name]
[v3_req]
subjectAltName = IP:<server-ip>
EOF

sudo openssl req -new -newkey rsa:4096 -nodes \
  -keyout /etc/4tanalyst/tls/server.key \
  -out /etc/4tanalyst/tls/server.csr \
  -subj "/CN=<server-hostname-or-ip>/O=<your-org>" \
  -config /etc/4tanalyst/tls/san.cnf
```

### 2. Submit the CSR to your internal CA

Send `/etc/4tanalyst/tls/server.csr` to your PKI/certificate team. They will return a signed certificate file (typically `server.crt` or `server.cer`).

Copy the signed certificate to the server:

```bash
sudo cp server.crt /etc/4tanalyst/tls/server.crt
```

If your CA also provides an intermediate/chain certificate, concatenate it:

```bash
sudo cat server.crt intermediate.crt | sudo tee /etc/4tanalyst/tls/server-chain.crt
```

### 3. Configure nginx

Create `/etc/nginx/conf.d/4tanalyst.conf` (use `server-chain.crt` if you have an intermediate cert, otherwise `server.crt`):

```nginx
server {
    listen 443 ssl;
    server_name <server-hostname-or-ip>;

    ssl_certificate     /etc/4tanalyst/tls/server-chain.crt;
    ssl_certificate_key /etc/4tanalyst/tls/server.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location /mcp {
        proxy_pass         http://127.0.0.1:8000/mcp;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   Connection "";
        proxy_buffering    off;
        proxy_read_timeout 300s;
    }

    location /admin {
        proxy_pass         http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_buffering    off;
        proxy_read_timeout 60s;
    }

    location /api {
        proxy_pass         http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_buffering    off;
        proxy_read_timeout 60s;
    }
}

# Redirect plain HTTP to HTTPS
server {
    listen 80;
    return 301 https://$host$request_uri;
}
```

### 4. Test and reload nginx

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 5. Open port 443 in the firewall

```bash
# RHEL
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload

# Ubuntu
sudo ufw allow 443/tcp
```

---

## Verify TLS is working

From the server:

```bash
# Option A (self-signed — skip cert verification)
curl -k -s -o /dev/null -w "%{http_code}\n" https://localhost/mcp

# Option B (CA-signed — full verification)
curl -s -o /dev/null -w "%{http_code}\n" https://<server-hostname>/mcp
```

Both should return `401` — the auth wrapper is working over HTTPS.

From an engineer workstation:

```bash
# Option A (after trusting the cert)
curl -s -o /dev/null -w "%{http_code}\n" https://<server-ip>/mcp

# Option B
curl -s -o /dev/null -w "%{http_code}\n" https://<server-hostname>/mcp
```

---

## Update engineer MCP config

Once TLS is live, engineers update their `.mcp.json` URL from `http://` to `https://` and change the port from `8000` to `443` (or whatever port direct uvicorn TLS was configured on):

```json
{
  "mcpServers": {
    "4tanalyst": {
      "type": "http",
      "url": "https://<server-hostname-or-ip>/mcp",
      "headers": {
        "Authorization": "Bearer ${FW_ANALYST_CLIENT_TOKEN}"
      }
    }
  }
}
```

---

## Lock down port 8000

Once nginx is handling all traffic, restrict port 8000 to localhost only so it is no longer reachable directly from the network:

```bash
# RHEL
sudo firewall-cmd --permanent --remove-port=8000/tcp
sudo firewall-cmd --reload
```

The 4tAnalyst service continues to listen on `127.0.0.1:8000` — only nginx can reach it.
