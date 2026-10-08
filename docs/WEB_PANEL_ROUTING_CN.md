# Web 管理面板独立路由

本面板使用 Vue Router 的 HTML5 History 路由。各栏目有独立 URL，支持书签、直接访问和浏览器前进/后退；不再仅在首页通过变量切换栏目。高级设置是独立页面组件并按需加载，不使用高级弹窗、body 滚动锁定或嵌套滚动容器。

| 栏目 | URL |
| --- | --- |
| 总览 | `/panel/overview` |
| 用户 | `/panel/users` |
| 已连接客户端 | `/panel/clients` |
| 历史客户端 | `/panel/client-history` |
| 连接列表 | `/panel/connections` |
| 封禁列表 | `/panel/bans` |
| 配置下发 | `/panel/bootstrap` |
| 多节点 | `/panel/nodes` |
| 系统设置 | `/panel/settings` |
| DPI | `/panel/dpi` |
| 本服务高级设置 | `/panel/settings/advanced` |
| 指定边缘节点高级设置 | `/panel/nodes/节点ID/settings/advanced` |

高级设置分类使用路径后缀：`/frp`、`/timeouts`、`/tcp`、`/mtls`、`/file`。例如中心 TCP 设置地址为 `/panel/settings/advanced/tcp`；边缘高级设置不展示中心启动文件信息分类。

分类切换保留当前草稿，保存提交全部分类。未保存时离开页面、重新读取或刷新会提醒；保存失败不丢弃草稿。表单发现其他分类的无效输入时会切到该分类，避免隐藏字段无法聚焦而导致保存无响应。

自动模式只锁定内置 FRP 开启与 FRP TLS 关闭，不禁用监听地址、超时或连接调优的编辑。中心高级页只修改本中心进程；边缘高级页从路径中的节点 ID 获取实际配置，并通过现有 mTLS 接口下发，不使用中心配置代替边缘参数。

初始化、登录和数据库修复分别使用 `/setup`、`/login`、`/database-repair`。未登录访问管理页面会进入登录页，登录后回到原管理地址；跳转目标只接受本面板已知的内部管理路由。边缘部署不能访问中心专用管理栏目；未知页面展示 404。前端守卫只负责导航，后端鉴权保持原样。

## 宝塔 / Nginx 配置

History 路由必须在静态站点上回退到 `index.html`，否则从浏览器直接打开高级设置或刷新栏目会得到服务器 404。当前应用默认部署在网站根目录，API 保持 `/api/`。

在现有站点 `server {}` 内修改已有的静态位置块，不要重复添加 `location /`。保留原域名、HTTPS 证书、网站根目录和 API 反代。若 API 使用宝塔独立反代规则，保持原规则，不要把 API 请求改写为 HTML。

```nginx
# 保留现有 location ^~ /api/ 及其后端地址。
location /assets/ {
    try_files $uri =404;
}
location = /index.html {
    expires -1;
    add_header Cache-Control "no-cache" always;
}
location / {
    try_files $uri $uri/ /index.html;
}
```

检查宝塔已生成的静态扩展名缓存规则或其他正则 location 是否覆盖资源访问。不要设置所有 API/404 都回退首页；缺失 JS/CSS 应返回 404。

更新完整前端构建目录，并保留高级设置的独立 JS 文件；不要只上传 `index.html` 或主 JS。保留用户 cfg、数据库、边缘状态库、CA 和证书，不重新初始化。程序本身仅提供 API，页面路由由 Nginx/Vite 提供，不需要给 Go 的 `/api` 注册页面地址。

架构参考：[3x-ui 路由源码](https://github.com/MHSanaei/3x-ui/blob/main/frontend/src/routes.tsx)、[设置页面源码](https://github.com/MHSanaei/3x-ui/blob/main/frontend/src/pages/settings/SettingsPage.tsx)。History 部署配置参考：[Vue Router 官方说明](https://router.vuejs.org/guide/essentials/history-mode.html)。本项目仍使用自己的 Vue UI、FRP 配置与 mTLS 业务接口，不引入 3x-ui 的隧道逻辑。
