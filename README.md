# MeowFRP_server

MeowFRP 的服务端、管理后端与 Web 控制面。

配套客户端项目：`MeowFRP_client`。

第一版目标是先把后端链路立起来：

- 第一次启动后创建管理员账户
- 管理用户、长期 access token、端口/域名授权
- 管理每个用户可开放的服务端端口范围和最大端口数量
- 客户端启动前通过 HTTPS API bootstrap 获取 frpc 配置
- 服务端签发短期 runtime token 和 lease
- frps 通过 HTTP plugin 二次校验 `Login/NewProxy/Ping/NewWorkConn/NewUserConn/CloseProxy`
- 用户/token/client 被封禁后，bootstrap 和 frps runtime 请求都会拒绝
- 预留 `policy.Engine`，后续 DPI、实时阻断、限速、封禁动作可以接这里

## 目录

```text
cmd/server                 # 程序入口
internal/config            # 环境变量配置
internal/db                # MySQL schema 和数据访问
internal/httpapi           # 管理 API、客户端 bootstrap、frps plugin
internal/policy            # DPI/阻断预留接口
internal/security          # 密码、token、session cookie
front                      # Vue 3 / Vite Web 管理面板
docs/frps-plugin-example.toml
```

## 启动前准备

创建 MySQL 数据库：

```sql
CREATE DATABASE frp_control CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

第一次启动时只初始化管理系统本身：管理员账号和数据库连接。后端会进入 setup 模式，前端会要求管理员填写数据库信息并验证连接，然后在运行目录写入：

```text
frp-control-server.cfg.json
```

运行：

```powershell
.\bin\frp-control-server.exe
```

也可以用命令行指定 API 监听端口：

```powershell
.\bin\frp-control-server.exe -port=18080
```

或者源码运行：

```powershell
go run .\cmd\server
```

## 第一次启动

前端打开时先请求：

```http
GET /api/v1/system/bootstrap-state
```

未初始化时调用：

```http
POST /api/v1/system/setup-admin
Content-Type: application/json

{
  "username": "admin",
  "password": "至少8位密码",
  "display_name": "Administrator",
  "database": {
    "host": "127.0.0.1",
    "port": 3306,
    "username": "root",
    "password": "root",
    "database": "frp_control"
  }
}
```

后端会验证数据库连接、执行迁移、创建管理员，并把数据库信息和管理员密码摘要写入 cfg。成功后会写入 HttpOnly Cookie，后续管理 API 用这个 Cookie 登录态。当前实现会热切换数据库连接，正常不需要重启；接口仍会返回 `restart_required` 字段，前端会按这个字段提示。

frps 地址、frps 端口、客户端配置注释等 frp 业务配置不在首次启动页里填写。初始化完成并登录管理后台后，在“系统”页面配置。

## 管理 API

登录：

```http
POST /api/v1/auth/login
```

用户：

```text
GET  /api/v1/admin/users
POST /api/v1/admin/users
POST /api/v1/admin/users/{id}/ban
POST /api/v1/admin/users/{id}/unban
GET  /api/v1/admin/user-policies
GET  /api/v1/admin/users/{id}/policy
PUT  /api/v1/admin/users/{id}/policy
```

长期 token：

```text
GET  /api/v1/admin/tokens
POST /api/v1/admin/tokens
POST /api/v1/admin/tokens/{id}/ban
POST /api/v1/admin/tokens/{id}/unban
GET  /api/v1/admin/tokens/{id}/grants
POST /api/v1/admin/tokens/{id}/grants
GET  /api/v1/admin/clients
POST /api/v1/admin/clients/{id}/ban
POST /api/v1/admin/clients/{id}/unban
GET  /api/v1/admin/system-settings
PUT  /api/v1/admin/system-settings
```

创建 token 的响应里会返回 `plain_token`，只返回这一次，数据库只保存 SHA256。

端口授权示例：

```json
{
  "protocol": "tcp",
  "remote_port_start": 6001,
  "remote_port_end": 6003,
  "max_count": 3
}
```

HTTP 域名授权示例：

```json
{
  "protocol": "http",
  "domain": "demo.example.com",
  "max_count": 1
}
```

用户资源策略示例：

```json
{
  "port_start": 6001,
  "port_end": 6020,
  "max_ports": 2,
  "enabled": true
}
```

这表示该用户只能在服务端 `6001-6020` 范围内选择端口，并且最多同时申请 2 个代理端口。

## 客户端 Bootstrap

普通用户 token 不能访问管理 API，只能先查询自己被分配的资源范围：

```http
POST /api/v1/client/resource-policy
Content-Type: application/json

{
  "access_token": "ak_xxx",
  "client_id": "device-001"
}
```

返回：

```json
{
  "ok": true,
  "policy": {
    "port_start": 6001,
    "port_end": 6020,
    "max_ports": 2,
    "enabled": true
  },
  "dpi": {
    "enabled": true,
    "mode": "block",
    "enabled_detectors": ["http", "tls", "quic", "encrypted_tunnel"],
    "blocked_traffic_types": ["quic", "encrypted_tunnel"],
    "allowed_traffic_types": ["http", "tls"],
    "block_on_any_finding": false
  }
}
```

然后客户端在范围内选择一个服务端端口，再请求配置：

```http
POST /api/v1/client/bootstrap
Content-Type: application/json

{
  "access_token": "ak_xxx",
  "client_id": "device-001",
  "client_version": "0.1.0",
  "proxies": [
    {
      "name": "ssh",
      "type": "tcp",
      "local_ip": "127.0.0.1",
      "local_port": 22,
      "remote_port": 6001
    }
  ]
}
```

如果用户/token/client 被封禁，返回：

```json
{
  "ok": false,
  "status": "banned",
  "reason": "封禁原因"
}
```

允许时返回：

```json
{
  "ok": true,
  "lease_id": "lease_xxx",
  "expires_in": 3600,
  "frpc_config": "serverAddr = ..."
}
```

生成的 frpc 配置会包含：

```toml
metadatas.token = "rt_xxx"
metadatas.lease_id = "lease_xxx"
```

frps 插件只接受这个 lease 已经分配过的代理，不接受客户端私自改出来的端口或代理。也就是说，客户端可以提交想开放的端口，但最终是否允许、允许哪一个端口，全部由服务端策略决定。

## frps 插件配置

参考：

```text
docs/frps-plugin-example.toml
```

核心配置：

```toml
[[httpPlugins]]
name = "frp-control-server"
addr = "127.0.0.1:8080"
path = "/api/v1/frp/plugin"
ops = ["Login", "NewProxy", "CloseProxy", "Ping", "NewWorkConn", "NewUserConn"]
```

## 编译

```powershell
go test ./...
go build -o .\bin\frp-control-server.exe .\cmd\server
```

## Web 前端

前端在 `front` 目录：

```powershell
cd .\front
npm install
npm run dev -- --host 127.0.0.1 --port 5173
npm run build
```

前端代码只请求当前域名下的 `/api`。生产部署时由 Nginx 反代 `/api/` 到 Go 后端即可。

开发模式默认把 `/api` 代理到 `http://127.0.0.1:8080`。如果后端用了 `-port=18080`，可以这样启动前端：

```powershell
$env:VITE_API_PROXY_TARGET='http://127.0.0.1:18080'
npm run dev -- --host 127.0.0.1 --port 5173
```

如果本机 `GOSUMDB` 配置异常，可以临时执行：

```powershell
$env:GOSUMDB='sum.golang.org'
```

## 后续要补的东西

- 管理 API 分页、搜索、审计日志查询
- 前端 Vue 3/Vite 管理面板
- Nginx 配置模板
- Redis 缓存 runtime token 和在线状态
- DPI/实时阻断实现接入 `internal/policy.Engine`
## Embedded frps

`frp-control-server` links the bundled frp source through:

```text
replace github.com/fatedier/frp => ./third_party/frp
```

By default, the server starts an embedded frps instance in the same process.
Useful config keys:

```json
{
  "embedded_frps_enabled": true,
  "frp_bind_addr": "0.0.0.0",
  "frp_proxy_bind_addr": "0.0.0.0",
  "frp_server_addr": "127.0.0.1",
  "frp_server_port": 7000,
  "frp_transport_tls": false
}
```

The embedded frps uses the existing HTTP plugin endpoint:

```text
/api/v1/frp/plugin
```

DPI is still only reserved as internal interfaces. Traffic inspection is not connected yet.
