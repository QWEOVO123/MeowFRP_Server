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
- 签发短期 FRP 运行令牌并生成客户端配置
- 封禁用户、令牌、客户端设备或入站 IP 后立即执行限制
- 通过每十秒一次的 HTTPS 心跳维护在线客户端状态
- 远程停止客户端 FRP、显示违规提示或要求重新鉴权
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

生成的静态文件位于 `front/dist`。

运行测试：

```bash
go test ./...
```

## 首次初始化

在可写的工作目录中启动后端：

```bash
./MeowFRP_server -port=8080
```

API 默认监听 `8080`，可以通过 `-port` 指定其他端口。第一次启动时，服务端进入初始化模式。打开 Web 面板后填写：

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

同时开放配置的 FRP 监听端口，以及分配给用户的远程端口范围。正式环境必须通过 HTTPS 提供控制 API。

## 客户端交互流程

1. MeowFRP 客户端携带长期 HTTPS API 令牌和设备标识发起认证。
2. `POST /api/v1/client/resource-policy` 返回 FRP 地址、允许协议、远程端口范围、隧道数量和 DPI 状态。
3. 用户在服务端规定的权限范围内选择隧道。
4. 客户端调用 `POST /api/v1/client/bootstrap`，服务端校验后返回包含短期 FRP 令牌的配置。
5. 内嵌 `frps` 验证运行令牌，并且只允许建立当前租约已经分配的代理。
6. 客户端每十秒调用 `POST /api/v1/client/heartbeat`，同时接收服务端排队下发的命令。
7. 客户端正常退出或被要求重新鉴权时调用 `POST /api/v1/client/logout`，立即从在线列表移除。

客户端停止发送心跳并超过超时时间后，会从在线客户端列表清除，未执行命令队列会被释放，已经建立的 FRP 访问也可以被终止。

## API 分类

- `/api/v1/system/*`：初始化、系统状态和数据库修复
- `/api/v1/auth/*`：管理员登录、会话状态和退出
- `/api/v1/admin/users*`：用户和资源策略
- `/api/v1/admin/tokens*`：API 令牌、轮换、封禁和授权
- `/api/v1/admin/clients*`：客户端历史、封禁、删除和远程命令
- `/api/v1/admin/dpi-*`：DPI 策略和检测事件
- `/api/v1/admin/connections*`：当前连接和强制断开
- `/api/v1/admin/blocked-ips*`：入站 IP 封禁列表
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
