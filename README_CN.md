# MeowFRP 服务端

[English](./README.md) · [配套 Windows 客户端](https://github.com/QWEOVO123/MeowFRP_Client)

你可以把 MeowFRP 理解成一套围绕 FRP 做的自托管管理系统：管理员在网页里分配用户、节点和端口，用户在桌面客户端选择节点、建立隧道，剩下的配置生成、鉴权和运行管理交给程序处理。

只有一台服务器也能用。等到需要多个地区的入口时，再开启多节点，把同一个服务端程序部署成边缘节点。中心负责账号和策略，边缘负责实际转发；用户的数据流量不需要绕回中心。

`frps` 直接嵌入 Go 程序，不需要另外启动原版 FRPS。不过 Web 前端仍是独立静态文件，需要由 Nginx 等 Web 服务器托管。

## 现在能做什么

- 创建用户并自动生成登录 Token，限制可访问节点、远程端口范围、隧道数量和协议。
- 下发临时 FRP 租约，把资源分配和实际注册的代理关联起来。
- 管理中心及边缘节点、在线客户端、历史设备、TCP/UDP 连接和入站 IP 黑名单。
- 通过双向 mTLS 控制通道主动同步用户、Token、资源权限和 DPI 策略。
- 查看边缘状态时手动“拉取数据”，不用每隔几秒上传整份连接和流量快照。
- 下发客户端提示、停止、重新鉴权，以及得到授权的边缘远程管理命令。
- 控制面故障时关闭新接入，让已经注册的穿透端口进入排空。
- 蓝色系管理面板，独立栏目 URL、节点设置弹窗和单独的高级设置页。

当前代码仍在迭代。下面写的是已实现的行为，不是对所有网络环境、所有旧版 FRP 客户端的兼容承诺。

## 先看懂四条连接

| 连接 | 默认端口 | 用途 |
| --- | --- | --- |
| 浏览器 / 客户端 → HTTPS API | 对外通常 443，后端 8080 | 管理登录、用户鉴权、节点选择、租约、客户端心跳 |
| FRPC → 内嵌 FRPS | 7000 | FRP 登录、代理注册及工作连接 |
| 边缘 → 中心 mTLS | 9443 | 节点身份、保活、策略推送、命令和按需上报 |
| 外部访问者 → 穿透端口 | 管理员分配，例如 25565 | 访问用户本机服务 |

**HTTPS 心跳成功，不代表 FRP 隧道成功。** 客户端还需要出现 `login to server success` 和 `start proxy success`。代理成功注册后，服务器才会监听分配的远程端口；防火墙里“放行”不会让端口自动开始监听。

API HTTPS、客户端到 FRPS 的 TLS、节点管理通道 mTLS 是三件不同的事。自动配置开启内嵌 FRPS、保持 **FRP TLS 关闭**，不关闭 HTTPS 或节点 mTLS。这一版没有加入讨论中的 HTTPS 密钥交换、证书固定或自定义流量加密。

## 中心和边缘怎么分工

```text
桌面客户端 ── HTTPS / Token ── 中心：验证用户，返回授权节点
     │
     ├── HTTPS ── 选中的节点：资源策略、租约、心跳、命令 ACK
     └── FRP ──── 选中的节点：实际隧道与转发

中心：MySQL、账号、策略、节点目录、缓存持有关系
     ⇅ gRPC / HTTP2 双向 mTLS
边缘：本地 SQLite 文件、已同步策略、租约、事件及命令状态
```

中心模式为 `controller`，边缘模式为 `edge`，两者使用同一个 `MeowFRP_server` 二进制。

中心需要 MySQL。边缘不需要 MySQL，而是使用内嵌 SQLite，默认文件为 `data/edge-state.db`。这是文件型数据库，不需要另行部署数据库服务，也不是自研数据库引擎。

### 用户登录与租约

1. 用户填写中心 API 地址和系统生成的用户 Token，不使用 Web 管理员密码登录桌面客户端。
2. 客户端向中心发送 `POST /api/v1/client/login`；中心检查 Token、用户状态、设备和节点授权，只返回有权限的节点。
3. 用户选择节点后，客户端直接调用该节点的 `resource-policy`，获取有效端口范围、隧道限制、协议和 DPI 状态。
4. `bootstrap` 再次校验请求，分配端口并签发默认 24 小时的运行租约，返回 FRPC TOML。
5. 内嵌 FRPS 通过内部插件验证运行 Token、租约和代理分配，不允许添加未分配的代理。
6. 客户端通过当前节点的 HTTPS API 心跳，并执行、确认服务端命令。正常心跳间隔为 10 秒。

长期用户 Token 与临时 FRP 运行 Token 不同。节点端口池、用户策略和 Token 授权需要同时满足；API、FRP 控制端口、mTLS 等保留端口及活动租约占用的端口不会再次分配。

### 用户资料和 DPI 如何主动同步

中心使用 `user_node_cache` 多对多关联表，不给每个用户建一张物理表。主键 `(user_id, node_id)` 找到用户的缓存持有节点，反向索引 `(node_id, user_id)` 用于按节点清理缓存关系。

- `desired_revision` 记录待推送版本，`applied_revision` 记录边缘落盘并 ACK 的版本。
- 用户、Token、节点授权、资源和 DPI 修改，与待推送记录在同一 MySQL 事务中提交。
- 下发完整的单用户资料，避免对不存在的缓存只发局部补丁。
- 基线按 `user_id` 游标分页，每批最多 64 个用户，序列化后再拆成 512 KiB 原始数据片段。
- 每批完整落盘 ACK 后才确认“已缓存”；同步按连续 120 秒无进展超时，不限制整份基线必须在 30 秒内完成。
- 启动或控制流重连时，边缘废弃身份缓存并报告 `cache_cleared`；中心按新缓存世代清关联，再重建基线。最终确认前不开放新会话。

节点自己的配置、证书、命令去重、未确认事件和本地封禁不是用户缓存，不会跟着全部删除。直接用 SQL 改业务表不会触发 Web/API 主动通知，请通过管理接口修改策略。

### 心跳、拉取数据与黑名单

节点心跳负责保活和控制状态，不周期性携带完整客户端、连接和流量快照。网页点击“拉取数据”后，中心才通过 mTLS 请求边缘上报。离线节点展示的可能是上次快照，不应当作实时状态。

全局入站 IP 黑名单同步到所有边缘：正常修改发送增量，首次接入和重连发送全量，包括空列表。全局与节点本地封禁分开存储，所以全局解封不会覆盖独立的本地封禁。新全局封禁也会处理匹配的现有连接。

关闭 DPI 事件上报时不继续积压该类事件。相关事件队列和运行日志有数量限制，可靠事件以持久化 ACK 为准；遥测写库失败不会直接掐断整条 mTLS 流。

### 控制面故障时会怎样

中心检测到数据库不可用，先暂停新登录、租约和新代理；连续失败达到 10 秒后判定节点异常。节点目录保留内存副本，故障通知走现有控制流，不依赖故障 MySQL 入队。

边缘收到故障通知、控制通道断开或本地状态库不可用后，也会拒绝新登录和新穿透端口。已有注册代理的客户端收到警告；代理全部关闭后，再通过客户端命令要求重新鉴权。计数来自 FRPS 代理生命周期，不使用 `frpc_running` 或当前访客连接数冒充。

这个机制保护的是**控制面故障期间仍在运行的数据面**。服务器断电、进程重启、FRP 数据连接断开仍会中断隧道。权限撤销、封禁和正常退出也不是“故障保留”的例外通行证。恢复后完成缓存同步，才重新接纳新会话。

## 从源码构建

需要：

- Go：模块要求 1.25+；本版本构建使用 Go 1.26.2。
- 前端：Node.js 20.19+ 或 22.12+，并满足 Vite 的版本要求；建议使用受支持的 LTS 环境。
- 中心数据库：MySQL 5.7 / 8.0 兼容 SQL，初始化连接启用 `mysql_native_password` 支持；实际发行版和权限仍需部署验证。
- Nginx 或同类静态文件及 HTTPS 反向代理服务。

在仓库根目录构建 Linux x86-64：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o build/MeowFRP_server ./cmd/server
```

构建前端：

```bash
cd front
npm ci
npm run build
```

部署需要服务端二进制和完整 `front/dist`。Go 程序不会自动托管 Vue 页面；不要只复制 `index.html` 或某一个 JS 文件。

## 第一次部署

### 1. 准备中心数据库

```sql
CREATE DATABASE frp_control
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
```

使用独立账户，授予这个库所需的读写和建表/升级权限。边缘节点跳过这一步。

### 2. 启动 API

把二进制放到可写的部署目录，在该目录启动：

```bash
chmod +x MeowFRP_server
./MeowFRP_server -APIbind=127.0.0.1 -APIport=8080
```

生产环境建议 API 只监听回环地址，由 Nginx 提供 HTTPS。不带参数通常监听 `0.0.0.0:8080`，并不是已配置 HTTPS 的公网入口。`-port` 是旧版 `-APIport` 别名。

### 3. 配置 HTTPS 和页面路由

示例中 `/opt/meowfrp/front` 放的是 `front/dist` 的内容。域名和证书路径换成你自己的。

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

`proxy_pass` 没有末尾 `/`，目的是保留后端需要的 `/api/` 路径。管理 Cookie 使用 `Secure`，正式管理登录需要 HTTPS。

宝塔已有站点请修改原配置，不要重复添加 `location /`。Vue 使用 History 路由，没有首页回退时，直接打开或刷新高级设置会得到 Nginx 404；缺失 JS/CSS 则应保持 404。

### 4. 完成网页初始化

打开 HTTPS 站点，选择中心或边缘。中心填写管理员和 MySQL；边缘填写中心地址及新增接入时生成的 Token。

初始化页面以浏览器当前 origin 拼接 `/api`，例如 `https://frp.example.com/api`，仍可手动修改。FRP 对外 IPv4 尝试自动探测；结果不唯一或不可确认时保留 `127.0.0.1`，请填写客户端真正能访问的地址。

保存后按提示重启后端，加载对应模式和监听器。配置默认写入工作目录的 `frp-control-server.cfg.json`。使用 systemd 或宝塔进程守护时，保持正确工作目录、文件权限和原环境变量。

### 5. 接入边缘并分配用户

在中心“多节点”页开启接入，用“新增接入”生成短期、单次使用的注册 Token。边缘本地生成私钥，通过中心 HTTPS API 提交 CSR，注册后使用独立 mTLS 通道。

节点管理地址必须是客户端可访问的完整 API URL，例如 `https://edge.example.com/api`，不要填远程客户端无法访问的 `127.0.0.1`。在用户页勾选允许访问的节点并保存资源策略；拥有用户 Token 不代表已经获得节点和端口权限。

开放实际 FRP 控制端口及穿透 TCP/UDP 端口；中心开启边缘接入还需开放 mTLS 端口。7000、9443 不是普通 `/api` HTTP 路径，不要套用 API 的 HTTP 反代。

## 网页设置放在哪里

- **系统设置**：当前服务自身的鉴权、API、FRP 地址和端口池等常用配置。
- **多节点**：接入总开关、接入凭证、节点列表、删除和每个边缘的设置入口。
- **高级设置**：独立 `/panel/settings/advanced` 页面，配置 TCP 复用、KeepAlive、超时、连接池、mTLS 握手和会话恢复等。
- **边缘高级设置**：`/panel/nodes/<nodeID>/settings/advanced`，通过 mTLS 管理指定边缘，不用中心配置冒充边缘参数。

边缘远程管理需先得到边缘本地授权，上报和操作权限分别控制。`0` 通常表示沿用底层默认值，个别字段的 `-1` 有特殊语义，按表单说明填写。涉及监听器的设置按提示重启。

## DPI：能看到什么，也有哪些限制

DPI 钩子接入内嵌 FRP 数据路径，按用户配置启用状态、检测器和阻断规则。当前检测包括 HTTP Host、TLS ClientHello/SNI、QUIC Initial 和加密隧道的启发式特征。

请先检查策略“启用”开关，再看检测器和阻断规则。显式取消全部检测器表示不运行这些检测器，不会恢复成全部开启。

它检查有限样本，不解密 HTTPS 内容，也不能保证识别所有加密协议。“已同步”不等于所有旧连接已重新检查。先观察事件，再逐步启用阻断，更容易定位误报。

## 排查与升级

```bash
curl -sS http://127.0.0.1:8080/api/v1/health
ss -lntp '( sport = :7000 or sport = :9443 or sport = :25565 )'
```

- `frps.running` 才表示内嵌 FRPS 已运行，保存启用配置不等于监听器已启动。
- 边缘的 `database_ready:false` 表示未加载中心 MySQL Store，不单独代表故障；结合模式、`node_fault`、`database_fault` 和同步状态判断。
- `EOF` 不等于 Token 错误。对照两端日志和抓包，区分握手、注册和中间网络重置。
- `connect to local service ... refused` 表示客户端本机目标没有接受连接，不是远程端口没分配。
- 端口冲突先查监听、活动租约和重复实例，别直接删数据库释放端口。

升级前备份 cfg、中心数据库、边缘状态文件和证书。先升级中心，再升级全部边缘，使用同一版本，保留工作目录和数据。旧节点兼容格式不具备全部新版同步、故障排空保障，不能仅升级中心就宣称完成升级。

节点证书当前不会自动续期，到期前应准备重新接入并加载新身份。不要把证书、配置、TOML、抓包或数据库备份提交到 Git。

## 给开发者

| 目录 | 负责什么 |
| --- | --- |
| `cmd/server` | 入口、监听器与进程生命周期 |
| `internal/httpapi` | 初始化、管理、客户端 API、FRP 授权及准入 |
| `internal/cluster` | mTLS、分页/分片同步、ACK、事件和远程命令 |
| `internal/db` / `internal/edgestate` | 中心 MySQL / 边缘 SQLite |
| `internal/frpcore` | 内嵌 FRPS、代理计数、连接与封禁控制 |
| `internal/dpi` / `internal/dpiengine` | 用户策略执行与检测器 |
| `front` | Vue 3、TypeScript、Vite、Vue Router |
| `third_party/frp` | 适配后的 FRP 源码，当前版本标识 0.69.1 |

根模块通过 `replace github.com/fatedier/frp => ./third_party/frp` 使用本地源码。集成包含运行租约鉴权、数据钩子、连接控制和代理生命周期计数；未适配的原版 FRPS 不是等价替代品。

按需运行验证：

```bash
go test ./...
go vet ./...
go test -race ./internal/cluster ./internal/edgestate ./internal/frpcore ./internal/httpapi
```

Go race 检测需要支持的平台及 C 工具链。仓库包含同步、黑名单、故障准入、代理排空和 DPI 回归用例，但不等于真实 MySQL 故障、Linux 部署和全部历史 FRP 版本兼容性测试已经通过。

继续看：[用户缓存同步](./docs/USER_CACHE_SYNC_CN.md)、[故障排空](./docs/NODE_FAULT_DRAIN_CN.md)、[Web 路由与宝塔部署](./docs/WEB_PANEL_ROUTING_CN.md)。这些文档保留各次改动背景；旧状态名和历史验证记录以当前代码为准。

## 许可证

服务端采用 [Apache License 2.0](./LICENSE)，内置 FRP 保留其 [原始许可](./third_party/frp/LICENSE)。客户端使用独立许可证，请分别查看对应仓库。
