# 官方多架构基础镜像，原生支持 linux/amd64 (x86_64) 与 linux/arm64 (aarch64)
FROM node:24-alpine

LABEL org.opencontainers.image.source="https://github.com/674542449/url-redirect" \
      org.opencontainers.image.description="轻量零依赖自定义域名短链接与路由跳转系统 (amd64 / arm64)"

WORKDIR /app

ENV NODE_ENV=production \
    TZ=Asia/Shanghai \
    PORT=8080 \
    DB_PATH=/app/data/links.db \
    ADMIN_PATH=/admin

# 零第三方依赖、零编译步骤，x86 与 ARM 架构通用
COPY package.json server.mjs ./
COPY src ./src

VOLUME ["/app/data"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "server.mjs"]
