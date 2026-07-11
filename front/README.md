# frp control front

Vue 3 + TypeScript + Vite 管理面板。

## 功能

- 首次初始化管理员
- 首次初始化数据库连接并写入后端 cfg
- 登录后在系统设置中配置 frps
- 管理员登录/退出
- Dashboard 总览
- 用户创建、封禁、解封
- 管理每个用户可开放的服务端端口范围和最大端口数量
- Token 创建、封禁、解封
- Token 端口/域名授权
- Client 列表、封禁、解封
- 普通 token 查询资源范围
- 客户端 bootstrap 配置下发测试

## 开发

```powershell
cd D:\Qt_test\frp_control_server\front
npm install
npm run dev -- --host 127.0.0.1 --port 5173
```

开发服务器会把 `/api` 代理到：

```text
http://127.0.0.1:8080
```

如果后端用了其它端口，例如 `-port=18080`：

```powershell
$env:VITE_API_PROXY_TARGET='http://127.0.0.1:18080'
npm run dev -- --host 127.0.0.1 --port 5173
```

生产构建不会写死 API 地址，浏览器只请求当前域名下的 `/api`。

## 构建

```powershell
npm run build
```

构建产物在：

```text
D:\Qt_test\frp_control_server\front\dist
```

Nginx 可以直接托管 `dist`，并把 `/api/` 反代到 Go 后端。
