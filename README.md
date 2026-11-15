# 自定义域名短链接与路由跳转系统（Docker 多架构版：支持 x86 & ARM）

零第三方依赖、极低内存占用（约 35MB），基于 **Docker + Node.js 24 原生 HTTP & SQLite (WAL)** 构建的域名路由跳转管理系统。

- **多架构原生支持**：通过 GitHub Actions 自动构建并发布 **`linux/amd64` (x86_64)** 与 **`linux/arm64` (aarch64，如甲骨文云 ARM、树莓派、华为鲲鹏、Apple Silicon)** 双架构镜像，Docker 会自动识别服务器 CPU 架构拉取对应镜像，零 C++ 编译依赖。

绑定域名（如 `abc.com`）后即可实现：
- 访问 `http(s)://abc.com/abc` ➔ 跳转到自定义地址 A
- 访问 `http(s)://abc.com/efg` ➔ 跳转到自定义地址 B
- 访问 `http(s)://abc.com/`（路径填 `@`）➔ 自定义域名首页跳转
- 访问 `http(s)://abc.com/admin` ➔ 进入可视化后台管理所有链接与查看点击统计

---

## 一、服务器快速部署（x86 / ARM 自动适配）

### 方式 1：无需克隆源码，单条命令直接拉取多架构镜像启动（推荐）

在任意 **x86_64** 或 **ARM64** 的 Linux 服务器上直接执行（请把 `your-strong-password` 替换为你自己的后台密码）：

```bash
docker run -d \
  --name url-redirect \
  --restart unless-stopped \
  -p 8080:8080 \
  -e ADMIN_PASSWORD=your-strong-password \
  -e ADMIN_PATH=/admin \
  -v $(pwd)/url-data:/app/data \
  ghcr.io/674542449/url-redirect:latest
```

### 方式 2：使用 Docker Compose 部署（或本地源码构建）

```bash
git clone https://github.com/674542449/url-redirect.git
cd url-redirect

# 创建 .env 配置文件（请将 your-strong-password 替换为你自己的后台管理密码）
cat > .env << 'EOF'
HOST_PORT=8080
ADMIN_PATH=/admin
ADMIN_PASSWORD=your-strong-password
EOF

# 直接拉取预构建好的多架构镜像启动（若想在本地自行编译镜像可加上 --build）
docker compose up -d
```

- 启动后数据会自动持久化保存在本地数据卷中，重启或升级容器均不会丢失任何短链接和点击统计。
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
将 `-p 8080:8080` 改为 `-p 80:8080`（或将 `.env` 中的 `HOST_PORT=8080` 改为 `HOST_PORT=80`），重启容器后即可直接通过 `http://abc.com/abc` 访问跳转。

---

## 三、常用运维命令

```bash
# 更新到最新镜像（Docker Compose 方式）
docker compose pull && docker compose up -d

# 查看运行状态与日志
docker logs -f url-redirect
```
