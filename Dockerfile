FROM node:24-alpine

WORKDIR /app

ENV NODE_ENV=production \
    TZ=Asia/Shanghai \
    PORT=8080 \
    DB_PATH=/app/data/links.db \
    ADMIN_PATH=/admin

# 零第三方依赖，直接复制源码即可运行，构建仅需 2 秒且无需联网 npm install
COPY package.json server.mjs ./
COPY src ./src

RUN mkdir -p /app/data

VOLUME ["/app/data"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/healthz').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "server.mjs"]
