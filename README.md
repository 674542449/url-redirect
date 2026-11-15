# 自定义域名短链接与路由跳转系统（Docker 多架构安全加固版）

零第三方依赖、极低内存占用（约 35MB），基于 **Docker + Node.js 24 原生 HTTP & SQLite (WAL)** 构建的域名路由跳转管理系统。

### 核心与安全特性
- **多架构原生支持**：GitHub Actions 自动构建发布 **`linux/amd64` (x86_64)** 与 **`linux/arm64` (aarch64)** 双架构镜像，自动适配服务器架构。
- **零默认密码与弱口令熔断**：彻底取消默认密码，未设置 `ADMIN_PASSWORD`、密码少于 8 位或使用常见弱密码时，后台自动进入**安全锁定状态**，拒绝一切登录。
- **防暴力破解与 `scrypt` 慢哈希**：密码校验采用内存硬哈希 `scrypt` + 常量时间比对；单 IP 连续输错 5 次自动封禁 15 分钟（识别真实反代 IP，防伪造 `X-Forwarded-For` 绕过）。
- **服务端有状态会话**：256 位随机高熵令牌，数据库仅保存 SHA-256 哈希，退出登录或修改密码后旧 Cookie **立即在服务端销毁失效**，杜绝离线字典破解与重放。
- **支持隐蔽后台入口**：将 `ADMIN_PATH` 设为自定义路径（如 `/panel-9x8k`）后，前端页面与后端 API 同步迁移，扫描器访问 `/admin` 完全返回 `404` 且无任何路径泄露。
- **严格安全头**：内置动态随机 Nonce `Content-Security-Policy`、`SameSite=Strict`、`Origin` 同源校验与 `Referrer-Policy: no-referrer`。

---

## 一、服务器快速部署（x86 / ARM 自动适配）

### 方式 1：无需克隆源码，单条命令直接拉取多架构镜像启动（推荐）

> **安全建议**：如果服务器装有宝塔 / 1Panel / Nginx 做 HTTPS 反向代理，建议将端口映射写为 `-p 127.0.0.1:8080:8080`（仅本机 Nginx 可访问容器，公网无法直接扫描 8080 端口），并将 `ADMIN_PATH` 改为您专属的隐蔽路径！

```bash
docker run -d \
  --name url-redirect \
  --restart unless-stopped \
  -p 127.0.0.1:8080:8080 \
  -e ADMIN_PASSWORD=请替换为8位以上复杂强密码 \
  -e ADMIN_PATH=/admin \
  -v $(pwd)/url-data:/app/data \
  ghcr.io/674542449/url-redirect:latest
```
*(若需先通过 `http://服务器IP:8080` 直接调试，可将 `-p 127.0.0.1:8080:8080` 改为 `-p 8080:8080`)*

### 方式 2：使用 Docker Compose 部署

```bash
git clone https://github.com/674542449/url-redirect.git
cd url-redirect

# 创建 .env 配置文件（密码必须至少 8 位且不能为弱口令）
cat > .env << 'EOF'
HOST_PORT=8080
ADMIN_PATH=/admin
ADMIN_PASSWORD=请替换为8位以上复杂强密码
EOF

docker compose up -d
```

---

## 二、绑定你的域名（如 `abc.com`，强烈建议开启 HTTPS）

先把域名 `abc.com` 的 DNS `A 记录` 解析到你的服务器公网 IP：

### 方式 A：宝塔面板 / 1Panel / Nginx 反向代理（推荐，全程 HTTPS 加密登录）
1. 在面板中新建网站 `abc.com`，并一键开启 Let's Encrypt 免费 SSL 证书（开启强制 HTTPS）。
2. 添加 **反向代理**，目标 URL 填写 `http://127.0.0.1:8080`。
3. 纯 Nginx 配置参考：

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

---

## 三、常用运维命令

```bash
# 拉取最新安全镜像并无缝重启更新
docker compose pull && docker compose up -d

# 查看运行状态与日志
docker logs -f url-redirect
```
