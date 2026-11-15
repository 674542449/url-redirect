import fs from 'node:fs';
import http from 'node:http';
import { createApp } from './src/app.mjs';

if (fs.existsSync('.env') && typeof process.loadEnvFile === 'function') {
  process.loadEnvFile('.env');
}

const PORT = Number(process.env.PORT || process.env.HOST_PORT) || 8080;
const HOST = process.env.HOST || '0.0.0.0';
const DB_PATH = process.env.DB_PATH || './data/links.db';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const ADMIN_PATH = process.env.ADMIN_PATH || '/admin';

const app = createApp({
  dbPath: DB_PATH,
  adminPassword: ADMIN_PASSWORD,
  adminPath: ADMIN_PATH,
});

const server = http.createServer(app.handler);

server.on('clientError', (err, socket) => {
  if (err.code === 'ECONNRESET' || !socket.writable) return;
  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

server.listen(PORT, HOST, () => {
  console.log('====================================================');
  console.log(' 短链接路由跳转服务已启动 (Node.js + SQLite WAL)');
  console.log(` 监听地址: http://${HOST}:${PORT}`);
  console.log(` 管理后台: http://localhost:${PORT}${app.adminPath}`);
  console.log(` 数据文件: ${DB_PATH}`);
  console.log('====================================================');
});

function shutdown(signal) {
  console.log(`\n收到 ${signal} 信号，正在安全关闭服务与数据库...`);
  server.close(() => {
    try {
      app.close();
    } catch {}
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 5000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
