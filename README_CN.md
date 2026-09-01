# MeowFRP 服务端

[English](./README.md)

MeowFRP 服务端是一个自包含的 FRP 控制平台，整合了内嵌 `frps`、Go 控制 API、基于 MySQL 的策略系统、已经接入数据链路的 DPI 引擎，以及 Vue Web 管理面板。

配套客户端项目：[`MeowFRP_Client`](https://github.com/QWEOVO123/MeowFRP_Client)

## 主要功能

- 内嵌支持策略控制的 `frps`，不需要单独部署 FRP 服务端进程
- 通过 Web 面板完成首次管理员和 MySQL 初始化
- 管理员会话由固定管理员令牌派生，并支持配置过期时间
- 创建普通用户时自动生成 HTTPS API 令牌
- 按用户配置远程端口范围、隧道数量和允许协议
- 生成客户端配置并签发默认 24 小时的 FRP 运行租约，退出或心跳超时后立即撤销
- 封禁用户、令牌、客户端设备或入站 IP 后立即执行限制
- 通过每十秒一次的 HTTPS 心跳维护在线客户端状态
- 远程停止客户端 FRP、显示违规提示或要求重新鉴权，并通过 HTTPS ACK 确认执行结果和处理重试
- 展示当前 TCP/UDP 连接、强制断开 TCP 连接和封禁入站 IP
- 支持配置 UDP 伪连接超时时间
- 保存历史客户端记录，并支持管理员主动删除
- 提供适合通过 Nginx 部署的 Vue 3 静态管理面板

## 已接入的 DPI

DPI 已经完整接入内嵌 FRP 的数据路径，不是预留接口。

当前组合检测引擎会对每条流量的有限长度样本进行检查，支持：

- 检测 HTTP 请求并提取 `Host`
- 检测 TLS ClientHello 并提取 SNI
- 检测 QUIC Initial 数据包
- 通过启发式规则检测加密隧道流量，包括类似 SS 的流量特征

DPI 策略按用户配置。管理员可以控制用户是否经过 DPI 网关、启用哪些检测器、阻断哪些命中的流量类型，并查看检测事件。事件中记录用户、客户端、代理、流量方向、通信地址、命中检测器、协议信息、处理结果和时间。

客户端查询资源策略时，服务端还会返回 DPI 是否启用以及当前阻断的流量类型，让 MeowFRP 客户端在启动隧道前展示实际生效的策略。

## 项目结构

```text
cmd/server                  程序入口
internal/config             运行配置和持久化配置
internal/db                 MySQL 表结构和数据访问
internal/httpapi            初始化、管理、客户端和 FRP 插件 API
internal/frpcore            内嵌 frps 和实时连接控制
internal/dpiengine          HTTP、TLS、QUIC 和加密隧道检测器
internal/dpi                按用户执行 DPI 策略和阻断
internal/policy             通用授权决策
internal/security           密码、令牌和管理员会话安全
front                       Vue 3 / Vite 管理面板
third_party/frp             内置并经过适配的 FRP 源码
```

根 Go 模块直接引用仓库中的 FRP 源码：

```text
replace github.com/fatedier/frp => ./third_party/frp
```

## 环境要求

- Go 1.25 或更高版本
- 用于构建 Web 面板的 Node.js 和 npm
- MySQL 8.0 或兼容的 MySQL 服务
- 正式部署时使用 Nginx 或其他静态 Web 服务器

首次初始化前创建 UTF-8 数据库：

```sql
CREATE DATABASE frp_control
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
```

## 编译

编译服务端：

```bash
go build -trimpath -o MeowFRP_server ./cmd/server
```

编译 Web 面板：

```bash
cd front
npm ci
npm run build
```

## 中心与边缘模式

同一个服务端程序和同一套 Web 面板支持两种部署模式。运行目录中没有配置文件或配置文件不合法时，API 默认在所有网卡的 `8080` 端口监听并进入初始化流程；如需仅允许本机初始化，可使用 `-APIbind=127.0.0.1`。

- `controller` 使用 MySQL，可以作为普通单机服务器运行，也可以在“系统设置”中开启边缘节点接入。
- `edge` 通过中心地址和短期、单次使用的注册凭证完成注册，使用内置 SQLite 保存本地状态，不要求安装 MySQL。

首次注册复用中心现有的 HTTPS API，可由 Nginx 在 443 端口反代。Edge 在本地生成私钥并提交 CSR，Controller 使用十分钟有效、单次使用且明文保存在 MySQL 的注册 Token 鉴权；注册成功后，Edge 自动切换到默认 9443 端口上的 gRPC/HTTP2 mTLS 双向流。Edge 节点证书有效期固定为一年，不会自动续期；到期后需在中心生成新的注册 Token，并从 Edge 面板手动重新连接，签发结果写入 cfg，重启后生效。Controller 的 CA、CA 私钥和服务端身份以及 Edge 的 CA、节点证书和节点私钥都以 Base64 写入各自 cfg，管理接口不会返回这些私钥字段。

这条 mTLS 双向流同时承载可配置的 2–60 秒心跳、客户端在线状态、连接快照、流量统计、可靠运行日志/DPI 事件和带幂等回执的中心命令。中心面板可以查看各 Edge 的在线客户端与连接、远程断开 TCP 连接、踢出指定客户端，也可以下发单节点或全局 IP 封禁。各类上报和远程命令均受 Edge 本地权限开关控制。

Edge 面板还提供一个默认关闭、只能在本机修改的“允许中心远程管理”总开关。开启后，中心面板可以修改该 Edge 的上报/远程命令权限，并可在节点在线时修改 Edge 本地管理员用户名和密码。新密码以明文仅经过中心 HTTPS 请求和 mTLS 内存消息，在 Edge 本地计算 bcrypt 哈希；它不会进入 MySQL、离线命令队列或审计详情。凭据修改成功后，Edge 上已有的管理会话立即失效。

生成的静态文件位于 `front/dist`。

运行测试：

```bash
go test ./...
```

## 首次初始化

在可写的工作目录中启动后端：

```bash
./MeowFRP_server -APIport=8080 -APIbind=127.0.0.1
```

API 默认在所有网卡监听 `8080`，可以通过 `-APIport` 指定其他端口，通过 `-APIbind=127.0.0.1` 限制为仅本机监听；旧的 `-port` 仍作为兼容别名。生产环境的管理登录 Cookie 始终带 `Secure`，因此应通过 HTTPS/Nginx 访问面板。

- 初始管理员用户名和密码；
- MySQL 地址、端口、用户名、密码和数据库名。

服务端会验证数据库连接、创建或更新表结构、创建管理员、生成安全密钥，并在运行目录写入 `frp-control-server.cfg.json`。该文件包含数据库和认证敏感信息，禁止提交到 Git 仓库。

完成初始化后，如果数据库连接失败，系统会进入数据库修复页面，而不会重新进入首次注册页面。只有首次创建的管理员账户和密码有权修改数据库配置。

## 部署

使用 Nginx 托管 `front/dist`，并把 `/api/` 反向代理到后端。最小配置示例：

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

每个 Controller/Edge 都有独立的节点标签、公开 API URL、FRP 对外地址、FRP 控制端口和可用端口池。节点端口池会与用户策略和 Token 授权取交集，并排除 API、FRP 控制面、中心 mTLS 等保留端口；已被活动租约占用的端口也不会再次分配。FRP 控制端口变化后需要重启进程，其余公开地址和端口池设置可直接保存。中心可以在 Edge 授权远程管理和“修改运行参数”后通过 mTLS 下发这些设置。

云厂商安全组和主机防火墙通常不会默认开放 `1024-65535`。部署时必须显式开放实际配置的 FRP 控制端口以及节点端口池所需的 TCP/UDP 范围。正式环境必须通过 HTTPS 提供控制 API。

## 客户端交互流程

1. MeowFRP 客户端先调用中心的免鉴权 `GET /api/v1/public/nodes`。目录包含中心节点自身以及管理员允许选择的 Edge，并返回标签、公开 API URL、节点类型和在线状态。
2. 用户选择节点后，客户端携带长期令牌和设备标识直接向 Edge 发起认证；中心不转发长期令牌。
3. Edge 的 `POST /api/v1/client/resource-policy` 返回 FRP 地址、允许协议、远程端口范围、隧道数量和 DPI 状态。
4. 用户在服务端规定的权限范围内选择隧道。
5. 客户端调用 Edge 的 `POST /api/v1/client/bootstrap`，Edge 使用经 mTLS 同步到 SQLite 的令牌哈希和策略校验请求，并返回包含短期 FRP 令牌的配置。
6. 内嵌 `frps` 验证运行令牌，并且只允许建立当前租约已经分配的代理。
7. 客户端每十秒调用 `POST /api/v1/client/heartbeat`，同时接收服务端排队下发的命令；命令执行或弹窗成功后，通过当前节点的 HTTPS API 回传 ACK，未确认命令会重试但不会在同一 Client 进程中重复弹窗。
8. 运行租约默认有效 24 小时；客户端心跳超时或调用 `POST /api/v1/client/logout` 后，租约立即撤销并关闭已跟踪连接。

客户端停止发送心跳并超过超时时间后，会从在线客户端列表清除，未执行命令队列会被释放，已经建立的 FRP 访问也可以被终止。

Edge 与中心失联时会拒绝新的资源查询和 bootstrap，并返回 `edge_controller_disconnected`。已有 FRP 租约继续由 Edge 本地验证；正在运行的客户端每次断线只会收到一次 `show_warning`。

## API 分类

- `/api/v1/system/*`：初始化、系统状态和数据库修复
- `/api/v1/auth/*`：管理员登录、会话状态和退出
- `/api/v1/admin/users*`：用户和资源策略
- `/api/v1/admin/tokens*`：API 令牌、轮换、封禁和授权
- `/api/v1/admin/clients*`：客户端历史、封禁、删除和远程命令
- `/api/v1/admin/dpi-*`：DPI 策略和检测事件
- `/api/v1/admin/connections*`：当前连接和强制断开
- `/api/v1/admin/blocked-ips*`：入站 IP 封禁列表
- `/api/v1/admin/edge-clients`、`/api/v1/admin/nodes/{id}/commands`：边缘客户端聚合和中心命令
- `/api/v1/client/*`：资源查询、配置下发、心跳和退出
- `/api/v1/frp/plugin`：内部 FRP 授权回调

管理接口必须使用管理员会话。普通用户的 API 令牌不能访问 Web 管理接口，也不会被直接用作 FRP 认证令牌。

## 安全说明

- 控制 API 必须通过 HTTPS 对外提供。
- 妥善保护 `frp-control-server.cfg.json` 和数据库备份。
- MySQL 应使用只拥有本项目数据库必要权限的独立账户。
- 尽可能限制后端 API 监听端口和 FRP 控制端口的直接访问。
- 加密隧道检测采用启发式判断，建议先观察事件并按用户调整策略，再进行大范围阻断。

## 第三方源码

经过适配的 FRP 源码位于 `third_party/frp`，并保留原始 Apache License 2.0 许可。MeowFRP 对 FRP 的集成修改包括授权钩子、连接追踪、实时终止以及向 DPI 提供流量数据。

## 许可证

MeowFRP 服务端采用 [Apache License 2.0](./LICENSE)。
