# 自定义域名短链接与路由跳转系统（Docker 独立部署版）

零第三方依赖、极低内存占用（约 35MB），基于 **Docker + Node.js 24 原生 HTTP & SQLite (WAL)** 构建的域名路由跳转管理系统。完全脱离 Cloudflare，部署在你自己的任意服务器上。

绑定域名（如 `abc.com`）后即可实现：
- 访问 `http(s)://abc.com/abc` ➔ 跳转到自定义地址 A
- 访问 `http(s)://abc.com/efg` ➔ 跳转到自定义地址 B
- 访问 `http(s)://abc.com/`（路径填 `@`）➔ 自定义域名首页跳转
- 访问 `http(s)://abc.com/admin` ➔ 进入可视化后台管理所有链接与查看点击统计

---

## 一、服务器 Docker 快速部署

### 1. 克隆仓库并设置密码

在装有 Docker 的 Linux 服务器上直接执行：

```bash
git clone https://github.com/674542449/url-redirect.git
cd url-redirect

# 创建 .env 配置文件（请将 your-strong-password 替换为你自己的后台管理密码）
cat > .env << 'EOF'
HOST_PORT=8080
ADMIN_PATH=/admin
ADMIN_PASSWORD=your-strong-password
EOF

# 一键构建并后台启动（零外部依赖，约 2 秒完成）
docker compose up -d --build
```

- 启动后数据会自动持久化保存在当前目录的 `./data/links.db` 中，重启或升级容器均不会丢失任何短链接和点击统计。
- 先通过 `http://你的服务器IP:8080/admin` 即可测试登录后台。

---

## 二、绑定你的域名（如 `abc.com`）

先把域名 `abc.com` 的 DNS `A 记录` 解析到你的服务器公网 IP，然后任选以下方式：

### 方式 A：服务器装有 宝塔面板 / 1Panel / Nginx（推荐，自动支持 HTTPS）
1. 在面板中新建静态网站，域名填 `abc.com`，并一键申请 Let's Encrypt 免费 SSL 证书。
2. 进入该站点的 **反向代理** 设置，添加反向代理：
   - **目标 URL**：`http://127.0.0.1:8080`
   - **发送域名 (Host)**：`$host`
3. 若手动配置纯 Nginx，参考配置如下：

```nginx
server {
    listen 80;
    server_name abc.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
    }
}
```

### 方式 B：服务器没有装 Nginx，直接绑定 80 端口
将 `.env` 中的 `HOST_PORT=8080` 改为 `HOST_PORT=80`，然后重新运行 `docker compose up -d`，即可直接通过 `http://abc.com/abc` 访问跳转。

---

## 三、常用运维命令

```bash
# 查看运行状态与日志
docker compose logs -f

# 修改 .env 密码或端口后重启生效
docker compose up -d

# 停止服务
docker compose down
```
