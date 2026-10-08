# MeowFRP Server

[中文说明](./README_CN.md) · [Windows client](https://github.com/QWEOVO123/MeowFRP_Client)

MeowFRP is a self-hosted control system around FRP. You manage users, nodes and resource limits in a web panel; users choose an authorized node in the desktop client and start their tunnels. The server handles configuration generation, authorization and runtime control.

Start with one server. When you need more locations, deploy the same binary as edge nodes. The controller owns accounts and policies, while the selected node carries tunnel traffic. Edge traffic does not have to pass through the controller.

The adapted `frps` runtime is embedded in the Go application. The Vue panel is **not** embedded: deploy its static build with Nginx or another web server.

## What is included

- Generated user tokens; per-user node, port, protocol and tunnel limits.
- Temporary FRP leases tied to allocated proxies.
- Controller/edge administration, client history, live connections and inbound-IP blocking.
- Active user, token, resource and DPI synchronization over bidirectional mTLS.
- On-demand edge telemetry through the panel's “Pull data” action.
- Remote client commands and separately authorized edge administration.
- Fault admission gates and proxy draining for control-plane failures.
- A blue web panel with separate page URLs, per-node settings and a dedicated advanced page.

The project is actively evolving. This README describes implemented behavior, not guaranteed compatibility with every older FRP release or network environment.

## Four paths, different responsibilities

| Path | Default port | Purpose |
| --- | --- | --- |
| Browser/client → HTTPS API | Public 443; backend 8080 | Administration, authentication, policy, leases and client heartbeats |
| FRPC → embedded FRPS | 7000 | FRP login, proxy registration and work connections |
| Edge → controller mTLS | 9443 | Node identity, keepalive, synchronization, commands and reports |
| Visitor → tunnel port | For example, 25565 | Access to the user's local service |

A successful HTTPS heartbeat is **not** proof of a working tunnel. Look for `login to server success` and `start proxy success`. Allocation and firewall rules do not create a listener; successful proxy registration does.

API HTTPS, FRP transport TLS and node mTLS are independent. Automatic configuration enables embedded FRPS and keeps **FRP TLS disabled**. It does not disable HTTPS/mTLS, nor implement the proposed HTTPS key exchange, certificate pinning or custom encryption.

## Architecture and authentication

```text
Desktop client ── HTTPS/token ── Controller: authenticate, return authorized nodes
       │
       ├── HTTPS ── Selected node: policy, bootstrap, heartbeat, command ACK
       └── FRP ──── Selected node: tunnels and forwarding

Controller: MySQL, accounts, policy, directory, cache ownership
       ⇅ bidirectional gRPC / HTTP2 over mTLS
Edge: embedded SQLite file, synchronized identity, leases, events, commands
```

Both `controller` and `edge` modes use `MeowFRP_server`. Only the controller needs MySQL. Edges use embedded SQLite, normally at `data/edge-state.db`; no separate database service is needed. This is not a custom database engine.

### Login and leases

1. The desktop client submits the generated user token and device ID to `POST /api/v1/client/login` on the controller.
2. The controller checks the account, token, device and node permissions before returning the authorized directory.
3. The selected node's `resource-policy` returns the FRP endpoint, resource limits and DPI status.
4. `bootstrap` validates requested proxies, reserves ports and returns a TOML configuration with a runtime lease, normally valid for 24 hours.
5. Internal FRP plugin callbacks validate the runtime token and allow only allocated proxies.
6. Client HTTPS heartbeats normally run every ten seconds, delivering commands and acknowledgements.

The long-lived API token is not the FRP runtime token. Node pools, user policy and token grants must all permit a resource. Reserved management ports and active-lease ports cannot be allocated again. Desktop users do not sign in with the web administrator password.

### Active identity and DPI synchronization

One `user_node_cache` many-to-many table tracks holders using `(user_id, node_id)` and a reverse `(node_id, user_id)` index.

- Business changes and desired sync revisions commit in the same MySQL transaction.
- `desired_revision` represents pending work; `applied_revision` represents a committed edge ACK.
- Updates contain complete affected-user records, not patches that assume an existing cache.
- Baselines use a `user_id` cursor, up to 64 users per page, then 512 KiB serialized-data fragments.
- Ownership is confirmed only after complete-batch persistence and acknowledgement.
- The timeout is 120 seconds without progress, not 30 seconds for the entire baseline.
- Startup/reconnection discards identity caches. A generation-bound `cache_cleared` ACK resets controller ownership before rebuilding the baseline. New sessions stay closed until final confirmation.

Node configuration, certificates, command deduplication, unacknowledged events and local bans are not disposable identity caches. Direct SQL business-table edits bypass the Web/API push notification path.

### Telemetry, bans and faults

Node heartbeats do not periodically upload complete client, connection or traffic inventories. The panel requests reports explicitly; offline-node views may show the last snapshot.

Global inbound-IP changes go to all edges as deltas. Enrollment/reconnection sends a full replacement, including an empty list. Global and local bans are separate: removing one does not override the other. New global bans also enforce restrictions on matching existing connections.

Disabled DPI reporting stops accumulating that event category. Queues have limits, durable events require persistence ACKs, and telemetry write errors do not automatically tear down the mTLS stream.

A controller database failure first pauses new authentication, leases and proxy registration. Ten seconds of continuous failure declares a node fault. Notifications use the existing control stream and an in-memory node directory, not the failed database queue.

Edges also close admission on control-channel failure, controller fault or local database failure. Clients with registered proxies receive a warning. Once their actual FRPS proxy count reaches zero, the next client heartbeat can require reauthentication. Process-alive flags and visitor counts are not proxy counts.

This preserves a still-running data plane during **control-plane failures**. Power loss, process restart and FRP transport failure still interrupt tunnels. Revocation, bans and ordinary logout remain enforced. Healthy control state and completed synchronization are required before new sessions resume.

## Build

Requirements:

- Go 1.25+ as declared by the module; this version was built with Go 1.26.2.
- Node.js 20.19+ or 22.12+ satisfying Vite's engine requirement; use a supported LTS environment.
- Controller: MySQL 5.7/8.0-compatible SQL, with native-password support enabled during setup. Validate your database distribution and privileges.
- Static hosting and an HTTPS reverse proxy, such as Nginx.

From the repository root, build Linux x86-64:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o build/MeowFRP_server ./cmd/server
```

Build the panel:

```bash
cd front
npm ci
npm run build
```

Deploy the binary and **all** of `front/dist`, including lazy-loaded assets. The Go application does not serve the Vue pages.

## First deployment

Create a controller database; edges skip this step:

```sql
CREATE DATABASE frp_control
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
```

Use a dedicated account with application read/write and schema-upgrade privileges.

Run from a writable deployment directory:

```bash
chmod +x MeowFRP_server
./MeowFRP_server -APIbind=127.0.0.1 -APIport=8080
```

The unmodified API normally binds to `0.0.0.0:8080`, without HTTPS. Keep it on loopback behind an HTTPS proxy in production. `-port` is a legacy alias for `-APIport`.

Serve the panel and preserve `/api/` when proxying:

```nginx
server {
    listen 443 ssl;
    server_name frp.example.com;
    ssl_certificate /etc/nginx/certs/frp.example.com.crt;
    ssl_certificate_key /etc/nginx/certs/frp.example.com.key;
    root /opt/meowfrp/front;
    index index.html;

    location ^~ /api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }
    location /assets/ {
        try_files $uri =404;
    }
    location = /index.html {
        add_header Cache-Control "no-cache" always;
    }
    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

Replace domain, certificate and filesystem paths. `proxy_pass` intentionally has no trailing slash. Administrator cookies are `Secure`. History-mode page routes need the index fallback; missing JS/CSS should still return 404. On BaoTa, update existing location blocks rather than duplicating them.

Open the HTTPS panel and choose controller or edge mode. Controller setup needs administrator/MySQL details; edge setup needs the controller address and enrollment token.

The setup form derives the API URL from the browser origin plus `/api`, with manual override. It attempts public IPv4 detection; ambiguous/inconclusive results leave `127.0.0.1` for you to correct. Restart after initialization as directed to load the mode and listeners.

Configuration normally lives in the working directory at `frp-control-server.cfg.json`. Preserve working directory, permissions and environment variables when using systemd or BaoTa supervision.

### Enroll edges and assign users

Enable multi-node access and create a short-lived, single-use enrollment token. The edge generates its private key locally, submits a CSR through HTTPS, then uses the dedicated mTLS channel.

Advertised node API URLs must be reachable by desktop clients, such as `https://edge.example.com/api`, not remote loopback. Assign allowed nodes and resource policies explicitly; possessing a token alone does not grant node or port access.

Allow the actual FRP and tunnel TCP/UDP ports in firewalls/security groups, plus the controller mTLS port when needed. Ports 7000/9443 are not ordinary HTTP `/api` routes.

## Settings and DPI

System Settings manages the current service's common configuration. Multi-node management contains enrollment, deletion and per-edge settings. Advanced options live at `/panel/settings/advanced`; `/panel/nodes/<nodeID>/settings/advanced` updates that edge through mTLS.

Advanced options include TCP mux, KeepAlive, pools, timeouts and mTLS handshake/session settings. Zero generally retains underlying defaults; some fields accept a special `-1`. Edge remote administration needs local approval, with separate reporting/action permissions. Follow restart notices for listener changes.

DPI hooks inspect bounded flow samples for HTTP Host, TLS ClientHello/SNI, QUIC Initial and heuristic encrypted-tunnel patterns. Enable the user's policy explicitly. An explicit empty detector list disables detectors; it does not restore all of them.

DPI does not decrypt HTTPS payloads or reliably identify every encrypted protocol. A synchronized policy does not imply all existing flows were inspected again. Review events before broad blocking.

## Troubleshooting and upgrades

```bash
curl -sS http://127.0.0.1:8080/api/v1/health
ss -lntp '( sport = :7000 or sport = :9443 or sport = :25565 )'
```

- Check `frps.running`, not just the saved enable flag.
- An edge's `database_ready:false` means the controller MySQL Store is not loaded; use mode, fault flags and sync state to judge health.
- `EOF` is not automatically an invalid token; compare both endpoints' logs and captures.
- `connect to local service ... refused` points to the client's local target.
- Investigate listeners, active leases and duplicate processes before releasing occupied ports. Do not delete databases as a repair shortcut.

Back up configuration, databases, edge state and certificates. Upgrade controller and all edges to the same version, preserving data and working directories. Older compatibility paths do not provide every new sync/draining guarantee. Node certificates do not renew automatically; plan reenrollment before expiry.

Never commit real configuration, certificates, runtime TOML, captures or database backups.

## Development map

| Directory | Responsibility |
| --- | --- |
| `cmd/server` | Entry point and listener lifecycle |
| `internal/httpapi` | Setup, admin/client APIs, FRP authorization and admission |
| `internal/cluster` | mTLS, paging/chunks, ACKs, events and commands |
| `internal/db` / `internal/edgestate` | Controller MySQL / edge SQLite |
| `internal/frpcore` | Embedded FRPS, proxy counts, connections and bans |
| `internal/dpi` / `internal/dpiengine` | Policy execution and detectors |
| `front` | Vue 3, TypeScript, Vite and Vue Router |
| `third_party/frp` | Adapted FRP source; current identifier 0.69.1 |

The root module uses `replace github.com/fatedier/frp => ./third_party/frp`. Lease authorization, data hooks, connection control and proxy counts make an unadapted external FRPS an unsuitable drop-in replacement.

Development checks:

```bash
go test ./...
go vet ./...
go test -race ./internal/cluster ./internal/edgestate ./internal/frpcore ./internal/httpapi
```

Race detection needs a C toolchain on a supported platform. Regression coverage does not establish real MySQL fault handling, Linux deployment or historical FRP compatibility on its own.

More notes: [identity sync](./docs/USER_CACHE_SYNC_CN.md), [fault draining](./docs/NODE_FAULT_DRAIN_CN.md), [panel/BaoTa routing](./docs/WEB_PANEL_ROUTING_CN.md). These Chinese notes retain historical context; current code takes precedence over older state names or validation records.

## License

Server: [Apache License 2.0](./LICENSE). Bundled FRP retains its [original license](./third_party/frp/LICENSE). The companion client has a separate license.
