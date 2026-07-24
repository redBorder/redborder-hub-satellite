# Nginx SSL/TLS and WebSocket Reverse Proxy Guide

This guide details how to configure **Nginx** as a secure SSL/TLS termination proxy for the `redborder-hub` server. This ensures all communication over the WebSocket channel (`wss://`) is encrypted in transit, protecting signatures, tokens, and monitoring command execution.

---

## 1. How Nginx Fits Into the Architecture

```mermaid
graph LR
    Agent[redborder-satellite] -- wss:// (encrypted) --> Nginx[Nginx Reverse Proxy]
    Nginx -- ws:// (localhost) --> Hub[redborder-hub]
```

Nginx runs on the same machine (or network) as the Hub, listens on port `443` (HTTPS/WSS), handles the SSL/TLS handshake using your server certificates, and proxies the decrypted traffic locally to `redborder-hub` (port `8080`).

---

## 2. Nginx Configuration

Create or edit your Nginx server block (e.g., `/etc/nginx/conf.d/redborder-hub.conf` or `/etc/nginx/sites-available/default`):

```nginx
# Map block to handle WebSocket Upgrade headers dynamically
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

upstream redborder_hub_upstream {
    # Port on which the Go redborder-hub listens
    server 127.0.0.1:8080;
}

server {
    listen 80;
    server_name hub.redborder.internal;

    # Redirect all HTTP traffic to HTTPS
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name hub.redborder.cluster;

    # SSL Certificates Configuration
    ssl_certificate /etc/nginx/ssl/redborder-hub.crt;
    ssl_certificate_key /etc/nginx/ssl/redborder-hub.key;

    # Strong SSL Hardening Settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Client Request Body Limits (aligned with Hub message size limit of 512KB)
    client_max_body_size 1M;

    # Log Locations
    access_log /var/log/nginx/redborder_hub_access.log;
    error_log /var/log/nginx/redborder_hub_error.log;

    # Proxy WebSocket connections to the Hub
    location /ws {
        proxy_pass http://redborder_hub_upstream;
        proxy_http_version 1.1;

        # Establish WebSocket Handshake headers
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;

        # Forward core client identification headers to Hub
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Ensure security headers are forwarded (important for asymmetric/token/bootstrap auth)
        proxy_set_header X-Agent-ID $http_x_agent_id;
        proxy_set_header X-Agent-Token $http_x_agent_token;
        proxy_set_header X-Agent-Signature $http_x_agent_signature;
        proxy_set_header X-Agent-Timestamp $http_x_agent_timestamp;
        proxy_set_header X-Agent-PublicKey $http_x_agent_publickey;

        # WebSocket Keepalive / Timeout settings
        proxy_read_timeout 70s;
        proxy_send_timeout 70s;
    }

    # Proxy REST API commands (e.g., /agents, /dispatch)
    location / {
        proxy_pass http://redborder_hub_upstream;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 3. Key Configuration Settings Explained

### A. The WebSocket Connection Upgrade
By default, Nginx is a hop-by-hop proxy and will strip the `Upgrade` and `Connection` headers from HTTP requests. 
```nginx
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
```
These settings combined with the `map` block at the top ensure that Nginx dynamically upgrades the TCP connection to a persistent WebSocket tunnel when requested by the Satellite.

### B. Forwarding Signature Headers
Since the Agent authenticates using custom headers, we must ensure Nginx doesn't strip or ignore them. Standard custom headers are automatically passed, but explicitly adding them is safe:
```nginx
proxy_set_header X-Agent-ID $http_x_agent_id;
proxy_set_header X-Agent-Signature $http_x_agent_signature;
proxy_set_header X-Agent-Timestamp $http_x_agent_timestamp;
proxy_set_header X-Agent-Token $http_x_agent_token;
proxy_set_header X-Agent-PublicKey $http_x_agent_publickey;
```

### C. Connection Timeouts
The Hub implements a keepalive Ping/Pong loop every 54 seconds. Nginx's default connection read timeout is 60 seconds, which would prematurely terminate the connection. Setting:
```nginx
proxy_read_timeout 70s;
proxy_send_timeout 70s;
```
Ensures Nginx leaves the WebSocket connection open so that the Go application can manage heartbeats natively.

---

## 4. Setting up Self-Signed Certificates (For Internal Networks)

Modern Go applications (Go 1.15+) strictly require TLS certificates to include **Subject Alternative Name (SAN)** extensions. Standard certificates that rely solely on the legacy `Common Name` (CN) field will cause the following connection error:
`x509: certificate relies on legacy Common Name field, use SANs instead`

### A. Generating a Self-Signed Certificate with SAN Extensions

To generate a valid self-signed certificate for `hub.vhk.cluster`:

```bash
# Generate private key and self-signed certificate with SAN extension
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout /etc/nginx/ssl/redborder-hub.key \
  -out /etc/nginx/ssl/redborder-hub.crt \
  -subj "/CN=hub.vhk.cluster" \
  -addext "subjectAltName=DNS:hub.vhk.cluster,IP:10.1.33.160,IP:10.1.33.161"
```

### B. Satellite Agent Configuration for WSS (`satellite.json`)

Configure the Satellite's `hub_url` to connect via secure WebSocket:
```json
{
  "hub_url": "wss://hub.vhk.cluster/ws",
  "agent_id": "proxyD"
}
```

### C. Bypassing TLS Verification for Local Testing (`insecure_skip_verify`)

If you are using self-signed certificates in an internal environment without installing the certificate into your OS CA trust store, configure the Satellite to bypass certificate verification:

- **In `satellite.json`**:
  ```json
  {
    "hub_url": "wss://hub.vhk.cluster/ws",
    "agent_id": "proxyD",
    "insecure_skip_verify": true
  }
  ```

- **Or via CLI flag**:
  ```bash
  ./bin/redborder-satellite -config satellite.json -insecure
  ```
