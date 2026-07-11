# MeowFRP Server

[中文说明](./README_CN.md)

MeowFRP Server is a self-contained FRP control platform that combines an embedded `frps` runtime, a Go control API, a MySQL-backed policy layer, an integrated DPI engine, and a Vue web administration panel.

Companion client project: [`MeowFRP_Client`](https://github.com/QWEOVO123/MeowFRP_Client)

## Features

- Embedded and policy-aware `frps`; no separate FRP server process is required
- First-run administrator and MySQL setup through the web panel
- Administrator sessions derived from a fixed admin token with configurable expiration
- Automatic HTTPS API token creation for regular users
- Per-user remote-port ranges, tunnel limits, and protocol permissions
- Short-lived FRP runtime tokens and server-generated client configurations
- Immediate enforcement when a user, token, client device, or inbound IP is banned
- Connected-client presence tracked by ten-second HTTPS heartbeats
- Remote client commands for stopping FRP, displaying a warning, and forcing reauthentication
- Active TCP/UDP connection inventory, TCP termination, and inbound-IP blocking
- Configurable UDP pseudo-connection timeout
- Historical client records with explicit deletion
- Static Vue 3 administration panel designed for Nginx deployment

## Integrated DPI

DPI is fully connected to the embedded FRP data path. It is not a placeholder interface.

The current composite engine inspects bounded samples from each flow and supports:

- HTTP request detection and `Host` extraction
- TLS ClientHello detection and SNI extraction
- QUIC Initial packet detection
- Heuristic detection of encrypted tunnel traffic, including SS-like traffic patterns

DPI policy is configured per user. Administrators can enable or disable the DPI gateway, select detectors, choose which detected traffic types are blocked, and inspect recorded events. Events contain the user, client, proxy, direction, addresses, matched detector, protocol metadata, decision, and timestamp.

The client resource-policy response also reports whether DPI is enabled and which traffic types are blocked, so MeowFRP Client can display the effective policy before starting a tunnel.

## Architecture

```text
cmd/server                  Application entry point
internal/config             Runtime and persisted configuration
internal/db                 MySQL schema and data access
internal/httpapi            Setup, admin, client, and FRP plugin APIs
internal/frpcore            Embedded frps and live connection control
internal/dpiengine          HTTP, TLS, QUIC, and encrypted-tunnel detectors
internal/dpi                Per-user DPI policy and enforcement service
internal/policy             Shared authorization decisions
internal/security           Password, token, and session security
front                       Vue 3 / Vite administration panel
third_party/frp             Bundled and adapted FRP source
```

The root module uses the bundled FRP source directly:

```text
replace github.com/fatedier/frp => ./third_party/frp
```

## Requirements

- Go 1.25 or later
- Node.js and npm for building the web panel
- MySQL 8.0 or a compatible MySQL server
- Nginx or another static web server for production deployment

Create a UTF-8 database before first-time setup:

```sql
CREATE DATABASE frp_control
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
```

## Build

Build the server:

```bash
go build -trimpath -o MeowFRP_server ./cmd/server
```

Build the web panel:

```bash
cd front
npm ci
npm run build
```

The generated static files are written to `front/dist`.

Run the test suite:

```bash
go test ./...
```

## First-Run Setup

Start the backend from a writable working directory:

```bash
./MeowFRP_server -port=8080
```

The API listener defaults to port `8080`; `-port` overrides it. On first launch, the server enters setup mode. Open the web panel and provide:

- the initial administrator username and password;
- the MySQL host, port, username, password, and database name.

The server verifies the database connection, creates or updates the schema, creates the administrator, generates security material, and writes `frp-control-server.cfg.json` in the working directory. This file contains sensitive database and authentication data and must not be committed.

After initialization, a database outage opens the repair workflow instead of returning to first-run registration. Only the original administrator credentials can change the stored database configuration.

## Deployment

Serve `front/dist` as a single-page application and reverse-proxy `/api/` to the backend. A minimal Nginx layout is:

```nginx
server {
    listen 443 ssl;
    server_name frp.example.com;

    root /opt/meowfrp/front;
    index index.html;

    location / {
        try_files $uri /index.html;
    }

    location ^~ /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_http_version 1.1;
        proxy_buffering off;
    }
}
```

Expose the configured FRP bind port and the remote-port ranges assigned to users. Keep the backend API behind HTTPS in production.

## Client Flow

1. MeowFRP Client authenticates with its long-lived HTTPS API token and device ID.
2. `POST /api/v1/client/resource-policy` returns the FRP endpoint, permitted protocols, remote-port range, tunnel limit, and DPI status.
3. The user selects tunnels within that policy.
4. `POST /api/v1/client/bootstrap` validates the request and returns a generated configuration containing a short-lived FRP token.
5. Embedded `frps` validates the runtime token and allows only proxies allocated to that lease.
6. The client sends `POST /api/v1/client/heartbeat` every ten seconds and receives queued control commands.
7. A normal exit or forced reauthentication calls `POST /api/v1/client/logout` to remove the client from the online list immediately.

Clients that stop sending heartbeats are removed from the connected-client view after the configured timeout, their queued commands are released, and active FRP access can be terminated.

## API Groups

- `/api/v1/system/*`: initialization, status, and database repair
- `/api/v1/auth/*`: administrator login, session state, and logout
- `/api/v1/admin/users*`: users and resource policies
- `/api/v1/admin/tokens*`: API tokens, rotation, bans, and grants
- `/api/v1/admin/clients*`: device history, bans, deletion, and commands
- `/api/v1/admin/dpi-*`: DPI policies and detection events
- `/api/v1/admin/connections*`: active connections and termination
- `/api/v1/admin/blocked-ips*`: inbound-IP block list
- `/api/v1/client/*`: policy, bootstrap, heartbeat, and logout
- `/api/v1/frp/plugin`: internal FRP authorization callback

Administrative endpoints require an authenticated administrator session. Regular user API tokens cannot access the web administration API and cannot be used directly for FRP authentication.

## Security Notes

- Always deploy the control API behind HTTPS.
- Protect `frp-control-server.cfg.json` and database backups.
- Use a dedicated MySQL account with only the required database privileges.
- Restrict direct access to the backend API listener and FRP control port where possible.
- DPI encrypted-tunnel detection is heuristic; review events and tune per-user blocking policies before broad enforcement.

## Third-Party Source

The adapted FRP source is stored under `third_party/frp` and retains its original Apache License 2.0 notice. MeowFRP-specific FRP integration changes include authorization hooks, connection tracking, live termination, and DPI data callbacks.

## License

MeowFRP Server is licensed under the [Apache License 2.0](./LICENSE).
