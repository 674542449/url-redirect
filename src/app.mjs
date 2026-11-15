/**
 * 独立部署版（Docker / Node.js + SQLite）自定义域名短链接与路由跳转系统（安全加固版）
 *
 * 安全机制：
 * 1. 强密码强制策略：拒绝空密码、少于 8 位密码及常见弱口令（未合规时自动锁定后台拒绝一切登录）
 * 2. 内存硬哈希鉴权：使用异步 scrypt + timingSafeEqual 常量时间比对
 * 3. 有状态服务端会话：256 位随机 CSPRNG 令牌，数据库仅存 SHA-256 哈希，支持服务端真注销与改密即刻踢出所有旧会话
 * 4. 防暴力破解限流：基于真实客户端 IP（防伪造 X-Forwarded-For）连续失败锁定保护 + 内存上限淘汰防 OOM
 * 5. 路径隐匿支持：管理页面与所有后台 API 均挂载于 ADMIN_PATH 下，无任何未授权信息泄露
 * 6. 严格安全头与防跨站：动态 Nonce CSP、SameSite=Strict、Path 隔离、X-Requested-With + Origin 双重防 CSRF
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const MAX_JSON_BODY_BYTES = 1024 * 1024; // 批量导入等管理接口最大 1 MB
const MAX_LOGIN_BODY_BYTES = 4 * 1024;   // 登录接口最大 4 KB，防止超大请求体消耗内存
const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 会话有效期 24 小时
const MAX_ACTIVE_SESSIONS = 20;
const MAX_RATE_LIMIT_ENTRIES = 5000;

const WEAK_PASSWORD_BLOCKLIST = new Set([
  'admin',
  'admin123',
  'admin888',
  'administrator',
  'root1234',
  '12345678',
  '123456789',
  '1234567890',
  '88888888',
  '00000000',
  'password',
  'password123',
  'qwerty123',
  'qwertyuiop',
  'change-me-please',
  'your-strong-password',
]);

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function isStrongAdminPassword(pw) {
  if (typeof pw !== 'string') return false;
  const trimmed = pw.trim();
  if (trimmed.length < 8 || trimmed.length > 256) return false;
  if (WEAK_PASSWORD_BLOCKLIST.has(trimmed.toLowerCase())) return false;
  return true;
}

function normalizeIp(ip) {
  const raw = String(ip || '').trim();
  if (raw.startsWith('::ffff:')) return raw.slice(7);
  return raw;
}

function isTrustedProxyIp(ip) {
  const clean = normalizeIp(ip).toLowerCase();
  if (!clean) return false;
  if (clean === '127.0.0.1' || clean === '::1' || clean.startsWith('127.')) return true;
  if (clean.startsWith('10.') || clean.startsWith('192.168.')) return true;
  if (clean.startsWith('fc') || clean.startsWith('fd') || clean.startsWith('fe80:')) return true;
  const m172 = clean.match(/^172\.(\d+)\./);
  if (m172) {
    const second = Number(m172[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

function scryptAsync(password, salt) {
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 32, { N: 16384, r: 8, p: 1 }, (err, derivedKey) => {
      if (err) reject(err);
      else resolve(derivedKey);
    });
  });
}

export function createApp(options = {}) {
  const dbPath = options.dbPath || process.env.DB_PATH || './data/links.db';
  const rawPassword = String(options.adminPassword ?? process.env.ADMIN_PASSWORD ?? '').trim();
  const passwordConfigured = isStrongAdminPassword(rawPassword);

  const rawAdminPath = String(options.adminPath ?? process.env.ADMIN_PATH ?? '/admin').trim();
  const cleanAdmin = '/' + rawAdminPath.replace(/^\/+|\/+$/g, '');
  const adminPath = cleanAdmin === '/' ? '/admin' : cleanAdmin;
  const apiPrefix = `${adminPath}/api/`;

  const maxLoginAttempts = Number(options.maxLoginAttempts) || 5;
  const loginLockoutMs = Number(options.loginLockoutMs) || 15 * 60 * 1000; // 默认锁定 15 分钟
  const failDelayMs = options.failDelayMs !== undefined ? Number(options.failDelayMs) : 120;
  const trustProxy = options.trustProxy !== undefined ? Boolean(options.trustProxy) : true;

  // 预派生管理员密码 scrypt 摘要（避免明文常驻比对，同时防御时序攻击）
  const pwSalt = crypto.randomBytes(16);
  const expectedPwHash = passwordConfigured
    ? crypto.scryptSync(rawPassword, pwSalt, 32, { N: 16384, r: 8, p: 1 })
    : null;
  const pwFingerprint = passwordConfigured
    ? crypto.createHash('sha256').update('shortlink-pw-fp-v1::' + rawPassword).digest('hex').slice(0, 32)
    : '';

  if (dbPath !== ':memory:') {
    fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
  }

  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA synchronous = NORMAL;
    PRAGMA busy_timeout = 5000;

    CREATE TABLE IF NOT EXISTS links (
      slug TEXT PRIMARY KEY,
      url TEXT NOT NULL,
      status_code INTEGER NOT NULL DEFAULT 302,
      clicks INTEGER NOT NULL DEFAULT 0,
      note TEXT NOT NULL DEFAULT '',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      last_accessed_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_links_created_at ON links(created_at DESC);

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      pw_fingerprint TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    );
  `);

  const stmts = {
    getBySlug: db.prepare(
      'SELECT slug, url, status_code, clicks, note, enabled, created_at, updated_at, last_accessed_at FROM links WHERE slug = ?'
    ),
    recordClick: db.prepare(
      'UPDATE links SET clicks = clicks + 1, last_accessed_at = ? WHERE slug = ?'
    ),
    listAll: db.prepare(
      'SELECT slug, url, status_code, clicks, note, enabled, created_at, updated_at, last_accessed_at FROM links ORDER BY created_at DESC'
    ),
    insert: db.prepare(`
      INSERT INTO links (slug, url, status_code, clicks, note, enabled, created_at, updated_at, last_accessed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `),
    updateSameSlug: db.prepare(`
      UPDATE links
      SET url = ?, status_code = ?, clicks = ?, note = ?, enabled = ?, updated_at = ?, last_accessed_at = ?
      WHERE slug = ?
    `),
    toggle: db.prepare('UPDATE links SET enabled = ?, updated_at = ? WHERE slug = ?'),
    remove: db.prepare('DELETE FROM links WHERE slug = ?'),
    upsertImport: db.prepare(`
      INSERT INTO links (slug, url, status_code, clicks, note, enabled, created_at, updated_at, last_accessed_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(slug) DO UPDATE SET
        url = excluded.url,
        status_code = excluded.status_code,
        note = excluded.note,
        enabled = excluded.enabled,
        updated_at = excluded.updated_at
    `),
    // 会话管理 SQL
    insertSession: db.prepare(
      'INSERT INTO sessions (token_hash, pw_fingerprint, created_at, expires_at) VALUES (?, ?, ?, ?)'
    ),
    getSession: db.prepare(
      'SELECT token_hash, pw_fingerprint, expires_at FROM sessions WHERE token_hash = ?'
    ),
    deleteSession: db.prepare('DELETE FROM sessions WHERE token_hash = ?'),
    purgeInvalidSessions: db.prepare(
      'DELETE FROM sessions WHERE expires_at <= ? OR pw_fingerprint != ?'
    ),
    trimOldSessions: db.prepare(`
      DELETE FROM sessions WHERE token_hash NOT IN (
        SELECT token_hash FROM sessions ORDER BY created_at DESC LIMIT ?
      )
    `),
  };

  // 启动时立即清理过期或旧密码签发的会话
  stmts.purgeInvalidSessions.run(Date.now(), pwFingerprint);

  // 登录防爆破内存表: ip -> { count, firstAt, lockedUntil }
  const loginRateMap = new Map();

  function pruneRateMap(now) {
    if (loginRateMap.size <= MAX_RATE_LIMIT_ENTRIES) return;
    for (const [k, v] of loginRateMap.entries()) {
      if (v.lockedUntil <= now && now - v.firstAt > loginLockoutMs) {
        loginRateMap.delete(k);
      }
      if (loginRateMap.size <= MAX_RATE_LIMIT_ENTRIES * 0.8) break;
    }
    while (loginRateMap.size > MAX_RATE_LIMIT_ENTRIES) {
      const oldestKey = loginRateMap.keys().next().value;
      loginRateMap.delete(oldestKey);
    }
  }

  function checkLoginRateLimit(ip) {
    const now = Date.now();
    const record = loginRateMap.get(ip);
    if (!record) return { allowed: true };

    if (record.lockedUntil > now) {
      const remainMin = Math.max(1, Math.ceil((record.lockedUntil - now) / 60000));
      return {
        allowed: false,
        retryAfterSec: Math.ceil((record.lockedUntil - now) / 1000),
        message: `密码连续错误次数过多，当前 IP 已锁定，请 ${remainMin} 分钟后再试`,
      };
    }

    if (now - record.firstAt > loginLockoutMs) {
      loginRateMap.delete(ip);
    }
    return { allowed: true };
  }

  function recordLoginFailure(ip) {
    const now = Date.now();
    pruneRateMap(now);
    const prev = loginRateMap.get(ip);
    if (!prev || now - prev.firstAt > loginLockoutMs) {
      loginRateMap.set(ip, { count: 1, firstAt: now, lockedUntil: 0 });
      return maxLoginAttempts - 1;
    }
    prev.count += 1;
    if (prev.count >= maxLoginAttempts) {
      prev.lockedUntil = now + loginLockoutMs;
      return 0;
    }
    return maxLoginAttempts - prev.count;
  }

  function clearLoginFailures(ip) {
    loginRateMap.delete(ip);
  }

  function normalizeRow(row) {
    if (!row) return null;
    return {
      slug: String(row.slug),
      url: String(row.url),
      status_code: Number(row.status_code) === 301 ? 301 : 302,
      clicks: Number(row.clicks) || 0,
      note: row.note ? String(row.note) : '',
      enabled: Number(row.enabled) === 0 ? 0 : 1,
      created_at: String(row.created_at || ''),
      updated_at: String(row.updated_at || ''),
      last_accessed_at: row.last_accessed_at ? String(row.last_accessed_at) : null,
    };
  }

  // ==========================================================================
  // 安全鉴权与会话管理
  // ==========================================================================

  async function verifyPassword(input) {
    if (!passwordConfigured || !expectedPwHash || typeof input !== 'string') return false;
    if (input.length === 0 || input.length > 256) return false;
    const derived = await scryptAsync(input, pwSalt);
    return crypto.timingSafeEqual(derived, expectedPwHash);
  }

  function hashToken(rawToken) {
    return crypto.createHash('sha256').update(rawToken).digest('hex');
  }

  function extractRawSessionToken(cookieHeader) {
    if (!cookieHeader) return null;
    const match = String(cookieHeader).match(/(?:^|;\s*)sl_session=([A-Za-z0-9_-]{32,128})/);
    return match ? match[1] : null;
  }

  function createSession() {
    const now = Date.now();
    const rawToken = crypto.randomBytes(32).toString('base64url');
    const tokenHash = hashToken(rawToken);
    stmts.purgeInvalidSessions.run(now, pwFingerprint);
    stmts.insertSession.run(tokenHash, pwFingerprint, now, now + SESSION_TTL_MS);
    stmts.trimOldSessions.run(MAX_ACTIVE_SESSIONS);
    return rawToken;
  }

  function verifySessionCookie(cookieHeader) {
    if (!passwordConfigured) return false;
    const rawToken = extractRawSessionToken(cookieHeader);
    if (!rawToken) return false;

    const tokenHash = hashToken(rawToken);
    const row = stmts.getSession.get(tokenHash);
    if (!row) return false;

    if (Number(row.expires_at) <= Date.now() || String(row.pw_fingerprint) !== pwFingerprint) {
      stmts.deleteSession.run(tokenHash);
      return false;
    }
    return true;
  }

  function destroySessionCookie(cookieHeader) {
    const rawToken = extractRawSessionToken(cookieHeader);
    if (!rawToken) return;
    stmts.deleteSession.run(hashToken(rawToken));
  }

  function normalizeAndValidateSlug(rawSlug) {
    if (typeof rawSlug !== 'string') {
      return { ok: false, error: '请输入自定义短路径' };
    }
    const trimmed = rawSlug.trim();
    if (!trimmed) {
      return { ok: false, error: '自定义短路径不能为空（如需设置域名首页跳转，请填写 @）' };
    }
    if (trimmed === '@' || trimmed === '/') {
      return { ok: true, slug: '@' };
    }

    let clean = trimmed.replace(/^\/+|\/+$/g, '');
    try {
      clean = decodeURIComponent(clean).replace(/^\/+|\/+$/g, '');
    } catch {
      return { ok: false, error: '自定义路径包含无效的 URL 编码字符 (%)' };
    }
    if (!clean) {
      return { ok: true, slug: '@' };
    }
    if (clean.length > 200) {
      return { ok: false, error: '自定义路径长度不能超过 200 个字符' };
    }
    if (/[\s?#\x00-\x1f\x7f\\]/.test(clean)) {
      return { ok: false, error: '自定义路径不能包含空格、问号(?)、井号(#)或反斜杠(\\)' };
    }
    if (clean.includes('//')) {
      return { ok: false, error: '自定义路径不能包含连续斜杠 //' };
    }

    const lower = clean.toLowerCase();
    const adminClean = adminPath.replace(/^\/+|\/+$/g, '').toLowerCase();
    if (
      lower === adminClean ||
      lower.startsWith(adminClean + '/') ||
      lower === 'healthz' ||
      lower === 'favicon.ico' ||
      lower === 'robots.txt'
    ) {
      return { ok: false, error: `"/${clean}" 为系统保留路径，请更换其他路径名称` };
    }

    return { ok: true, slug: clean };
  }

  function validateTargetUrl(rawUrl, requestOrigin, slug) {
    if (typeof rawUrl !== 'string' || !rawUrl.trim()) {
      return { ok: false, error: '目标跳转地址不能为空' };
    }
    const trimmed = rawUrl.trim();
    if (trimmed.length > 2048) {
      return { ok: false, error: '目标地址长度不能超过 2048 个字符' };
    }

    let parsed;
    try {
      parsed = new URL(trimmed);
    } catch {
      return { ok: false, error: '请输入合法的完整网址（需以 https:// 或 http:// 开头）' };
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { ok: false, error: '仅支持 http:// 或 https:// 协议的目标网址' };
    }

    if (requestOrigin && parsed.origin.toLowerCase() === requestOrigin.toLowerCase()) {
      let targetSlug = '@';
      try {
        const decoded = decodeURIComponent(parsed.pathname).replace(/^\/+|\/+$/g, '');
        targetSlug = decoded || '@';
      } catch {
        targetSlug = parsed.pathname.replace(/^\/+|\/+$/g, '') || '@';
      }
      if (targetSlug === slug) {
        return { ok: false, error: '目标地址不能指向当前短链接自身，否则会造成无限循环跳转' };
      }
    }

    return { ok: true, url: parsed.toString() };
  }

  function getRequestContext(req) {
    const socketIp = normalizeIp(req.socket && req.socket.remoteAddress) || '0.0.0.0';
    const fromTrustedProxy = trustProxy && isTrustedProxyIp(socketIp);

    let proto = 'http';
    let rawHost = String(req.headers.host || '').trim() || 'localhost';
    let clientIp = socketIp;

    if (fromTrustedProxy) {
      const forwardedProto = String(req.headers['x-forwarded-proto'] || '')
        .split(',')[0]
        .trim()
        .toLowerCase();
      if (forwardedProto === 'https') proto = 'https';

      const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
      if (forwardedHost) rawHost = forwardedHost;

      const xRealIp = normalizeIp(req.headers['x-real-ip']);
      if (xRealIp) {
        clientIp = xRealIp;
      } else if (req.headers['x-forwarded-for']) {
        const xffList = String(req.headers['x-forwarded-for'])
          .split(',')
          .map((s) => normalizeIp(s))
          .filter(Boolean);
        // 取最右侧由反向代理追加的客户端 IP，防止客户端伪造左侧 X-Forwarded-For 绕过限流
        if (xffList.length > 0) {
          clientIp = xffList[xffList.length - 1];
        }
      }
    }

    let host = 'localhost';
    let origin = `${proto}://localhost`;
    try {
      const parsedOrigin = new URL(`${proto}://${rawHost}`);
      host = parsedOrigin.host;
      origin = parsedOrigin.origin;
    } catch {}

    const rawReqUrl = String(req.url || '/');
    const safeRelUrl = rawReqUrl.startsWith('/') ? '/' + rawReqUrl.replace(/^\/+/, '') : '/';
    let parsedUrl;
    try {
      parsedUrl = new URL(safeRelUrl, origin);
    } catch {
      parsedUrl = new URL('/', origin);
    }

    return { proto, isHttps: proto === 'https', host, origin, clientIp, parsedUrl };
  }

  async function readJsonBody(req, maxBytes = MAX_JSON_BODY_BYTES) {
    const chunks = [];
    let total = 0;
    for await (const chunk of req) {
      total += chunk.length;
      if (total > maxBytes) {
        throw new HttpError(413, '请求体过大');
      }
      chunks.push(chunk);
    }
    if (total === 0) return {};
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch {
      throw new HttpError(400, 'JSON 请求格式不正确');
    }
  }

  function sendJson(res, status, data, extraHeaders = {}) {
    const payload = JSON.stringify(data);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      ...extraHeaders,
    });
    res.end(payload);
  }

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ==========================================================================
  // 后台管理 API 控制器 (${adminPath}/api/*)
  // ==========================================================================

  async function handleAdminApi(req, res, ctx) {
    const subPath = '/' + ctx.parsedUrl.pathname.slice(apiPrefix.length);
    const method = (req.method || 'GET').toUpperCase();

    // 1. 会话状态检查（不泄露 adminPath 等任何内部配置）
    if (subPath === '/session' && method === 'GET') {
      return sendJson(res, 200, {
        configured: passwordConfigured,
        authenticated: verifySessionCookie(req.headers.cookie),
      });
    }

    // 2. 双重防跨站请求伪造 (CSRF)：校验自定义头 + Origin 同源校验
    if (method !== 'GET' && method !== 'HEAD') {
      if (req.headers['x-requested-with'] !== 'ShortLinkAdmin') {
        return sendJson(res, 403, { error: '非法请求来源 (CSRF 校验未通过)' });
      }
      if (req.headers.origin && String(req.headers.origin).toLowerCase() !== ctx.origin.toLowerCase()) {
        return sendJson(res, 403, { error: '非法跨源请求 (Origin 不匹配)' });
      }
    }

    // 3. 若未配置满足强度要求的密码，彻底锁定后台所有写/登录接口
    if (!passwordConfigured) {
      return sendJson(
        res,
        503,
        { error: '安全锁定：未配置有效的 ADMIN_PASSWORD（要求至少 8 位且不能使用常见弱密码），后台已禁止登录' }
      );
    }

    try {
      // 4. 登录接口（带 IP 防爆破锁定与 scrypt 校验）
      if (subPath === '/login' && method === 'POST') {
        const rateCheck = checkLoginRateLimit(ctx.clientIp);
        if (!rateCheck.allowed) {
          return sendJson(
            res,
            429,
            { error: rateCheck.message },
            { 'Retry-After': String(rateCheck.retryAfterSec) }
          );
        }

        const body = await readJsonBody(req, MAX_LOGIN_BODY_BYTES);
        const ok = await verifyPassword(String(body.password || ''));
        if (!ok) {
          const remaining = recordLoginFailure(ctx.clientIp);
          if (failDelayMs > 0) {
            await new Promise((r) => setTimeout(r, failDelayMs));
          }
          const msg =
            remaining > 0
              ? `管理密码不正确（还剩 ${remaining} 次尝试机会）`
              : '密码连续错误次数过多，当前 IP 已被锁定 15 分钟';
          return sendJson(res, remaining > 0 ? 401 : 429, { error: msg });
        }

        clearLoginFailures(ctx.clientIp);
        const rawToken = createSession();
        const cookie = `sl_session=${rawToken}; Path=${adminPath}; Max-Age=86400; HttpOnly; SameSite=Strict${ctx.isHttps ? '; Secure' : ''}`;
        return sendJson(res, 200, { ok: true }, { 'Set-Cookie': cookie });
      }

      // 5. 退出登录（立即从数据库销毁服务端会话）
      if (subPath === '/logout' && method === 'POST') {
        destroySessionCookie(req.headers.cookie);
        const cookie = `sl_session=; Path=${adminPath}; Max-Age=0; HttpOnly; SameSite=Strict${ctx.isHttps ? '; Secure' : ''}`;
        return sendJson(res, 200, { ok: true }, { 'Set-Cookie': cookie });
      }

      // 以下接口均需已登录的有效会话
      if (!verifySessionCookie(req.headers.cookie)) {
        return sendJson(res, 401, { error: '登录已过期或未授权，请重新登录' });
      }

      // 查询全部短链接
      if (subPath === '/links' && method === 'GET') {
        const links = stmts.listAll.all().map(normalizeRow);
        let totalClicks = 0;
        let activeCount = 0;
        for (const item of links) {
          totalClicks += item.clicks;
          if (item.enabled) activeCount += 1;
        }
        return sendJson(res, 200, {
          links,
          stats: {
            totalLinks: links.length,
            activeLinks: activeCount,
            totalClicks,
          },
        });
      }

      // 新建短链接
      if (subPath === '/links' && method === 'POST') {
        const body = await readJsonBody(req);
        const slugCheck = normalizeAndValidateSlug(body.slug);
        if (!slugCheck.ok) return sendJson(res, 400, { error: slugCheck.error });

        const urlCheck = validateTargetUrl(body.url, ctx.origin, slugCheck.slug);
        if (!urlCheck.ok) return sendJson(res, 400, { error: urlCheck.error });

        const existing = normalizeRow(stmts.getBySlug.get(slugCheck.slug));
        if (existing) {
          return sendJson(res, 409, {
            error: `路径 "${slugCheck.slug === '@' ? '/' : '/' + slugCheck.slug}" 已存在，请直接编辑该记录或更换路径`,
          });
        }

        const now = new Date().toISOString();
        const item = {
          slug: slugCheck.slug,
          url: urlCheck.url,
          status_code: Number(body.status_code) === 301 ? 301 : 302,
          clicks: 0,
          note: String(body.note || '').trim().slice(0, 200),
          enabled: body.enabled === false || body.enabled === 0 ? 0 : 1,
          created_at: now,
          updated_at: now,
          last_accessed_at: null,
        };

        stmts.insert.run(
          item.slug,
          item.url,
          item.status_code,
          item.clicks,
          item.note,
          item.enabled,
          item.created_at,
          item.updated_at,
          item.last_accessed_at
        );

        return sendJson(res, 201, { link: item });
      }

      // 更新短链接
      if (subPath === '/links' && method === 'PUT') {
        const body = await readJsonBody(req);
        const oldCheck = normalizeAndValidateSlug(body.old_slug ?? body.slug);
        if (!oldCheck.ok) return sendJson(res, 400, { error: oldCheck.error });

        const newCheck = normalizeAndValidateSlug(body.slug);
        if (!newCheck.ok) return sendJson(res, 400, { error: newCheck.error });

        const urlCheck = validateTargetUrl(body.url, ctx.origin, newCheck.slug);
        if (!urlCheck.ok) return sendJson(res, 400, { error: urlCheck.error });

        const existing = normalizeRow(stmts.getBySlug.get(oldCheck.slug));
        if (!existing) {
          return sendJson(res, 404, { error: '未找到要修改的短链接记录' });
        }

        const now = new Date().toISOString();
        const resetClicks = Boolean(body.reset_clicks);
        const nextClicks = resetClicks ? 0 : existing.clicks;
        const nextLastAccessed = resetClicks ? null : existing.last_accessed_at;
        const nextCode = Number(body.status_code) === 301 ? 301 : 302;
        const nextEnabled =
          body.enabled === undefined
            ? existing.enabled
            : body.enabled === false || body.enabled === 0
              ? 0
              : 1;
        const nextNote = String(body.note || '').trim().slice(0, 200);

        if (newCheck.slug !== oldCheck.slug) {
          const conflict = normalizeRow(stmts.getBySlug.get(newCheck.slug));
          if (conflict) {
            return sendJson(res, 409, {
              error: `目标路径 "${newCheck.slug === '@' ? '/' : '/' + newCheck.slug}" 已被其他规则占用`,
            });
          }
          db.exec('BEGIN');
          try {
            stmts.insert.run(
              newCheck.slug,
              urlCheck.url,
              nextCode,
              nextClicks,
              nextNote,
              nextEnabled,
              existing.created_at,
              now,
              nextLastAccessed
            );
            stmts.remove.run(oldCheck.slug);
            db.exec('COMMIT');
          } catch (txErr) {
            db.exec('ROLLBACK');
            throw txErr;
          }
        } else {
          stmts.updateSameSlug.run(
            urlCheck.url,
            nextCode,
            nextClicks,
            nextNote,
            nextEnabled,
            now,
            nextLastAccessed,
            newCheck.slug
          );
        }

        return sendJson(res, 200, {
          link: {
            slug: newCheck.slug,
            url: urlCheck.url,
            status_code: nextCode,
            clicks: nextClicks,
            note: nextNote,
            enabled: nextEnabled,
            created_at: existing.created_at,
            updated_at: now,
            last_accessed_at: nextLastAccessed,
          },
        });
      }

      // 快捷启停
      if (subPath === '/links/toggle' && method === 'PATCH') {
        const body = await readJsonBody(req);
        const slugCheck = normalizeAndValidateSlug(body.slug);
        if (!slugCheck.ok) return sendJson(res, 400, { error: slugCheck.error });

        const existing = normalizeRow(stmts.getBySlug.get(slugCheck.slug));
        if (!existing) {
          return sendJson(res, 404, { error: '未找到对应的短链接记录' });
        }

        const nextEnabled = body.enabled ? 1 : 0;
        const now = new Date().toISOString();
        stmts.toggle.run(nextEnabled, now, slugCheck.slug);
        return sendJson(res, 200, { link: { ...existing, enabled: nextEnabled, updated_at: now } });
      }

      // 删除短链接
      if (subPath === '/links' && method === 'DELETE') {
        const body = await readJsonBody(req);
        const slugCheck = normalizeAndValidateSlug(body.slug);
        if (!slugCheck.ok) return sendJson(res, 400, { error: slugCheck.error });

        stmts.remove.run(slugCheck.slug);
        return sendJson(res, 200, { ok: true });
      }

      // 批量导入 JSON
      if (subPath === '/import' && method === 'POST') {
        const body = await readJsonBody(req);
        const list = Array.isArray(body.links) ? body.links : [];
        if (list.length === 0) {
          return sendJson(res, 400, { error: '导入列表为空' });
        }
        if (list.length > 2000) {
          return sendJson(res, 400, { error: '单次最多支持导入 2000 条记录' });
        }

        let imported = 0;
        let skipped = 0;
        const now = new Date().toISOString();

        db.exec('BEGIN');
        try {
          for (const raw of list) {
            if (!raw || typeof raw !== 'object') {
              skipped += 1;
              continue;
            }
            const sc = normalizeAndValidateSlug(String(raw.slug || ''));
            const uc = validateTargetUrl(String(raw.url || ''), ctx.origin, sc.ok ? sc.slug : '');
            if (!sc.ok || !uc.ok) {
              skipped += 1;
              continue;
            }
            stmts.upsertImport.run(
              sc.slug,
              uc.url,
              Number(raw.status_code) === 301 ? 301 : 302,
              Number(raw.clicks) || 0,
              String(raw.note || '').trim().slice(0, 200),
              raw.enabled === 0 || raw.enabled === false ? 0 : 1,
              raw.created_at || now,
              now,
              raw.last_accessed_at || null
            );
            imported += 1;
          }
          db.exec('COMMIT');
        } catch (txErr) {
          db.exec('ROLLBACK');
          throw txErr;
        }

        return sendJson(res, 200, { ok: true, imported, skipped });
      }

      return sendJson(res, 404, { error: '未知的 API 接口' });
    } catch (err) {
      if (err instanceof HttpError) {
        return sendJson(res, err.status, { error: err.message });
      }
      console.error('Admin API Error:', err);
      return sendJson(res, 500, { error: '服务器内部错误' });
    }
  }

  // ==========================================================================
  // 页面渲染（前台 404 / 首页状态页 & 可视化后台）
  // ==========================================================================

  function sendLandingOr404(res, { host, isRoot, slug }) {
    const status = isRoot ? 200 : 404;
    const title = isRoot ? host : '未找到该链接 (404)';
    const heading = isRoot ? host : '链接不存在或已停用';
    const desc = isRoot
      ? '域名跳转服务运行正常。'
      : `未找到路径 "/${escapeHtml(slug)}" 对应的跳转规则，请检查链接拼写是否正确。`;

    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="robots" content="noindex, nofollow" />
  <title>${escapeHtml(title)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #f8fafc;
      color: #0f172a;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
      padding: 24px;
    }
    .card {
      max-width: 440px;
      width: 100%;
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      padding: 36px 32px;
      text-align: center;
      box-shadow: 0 4px 20px rgba(15, 23, 42, 0.04);
    }
    .badge {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 48px;
      height: 48px;
      border-radius: 12px;
      background: ${isRoot ? '#eff6ff' : '#fef2f2'};
      color: ${isRoot ? '#2563eb' : '#dc2626'};
      font-weight: 700;
      font-size: 18px;
      margin-bottom: 16px;
    }
    h1 { font-size: 20px; font-weight: 600; margin-bottom: 10px; word-break: break-all; }
    p { font-size: 14px; color: #64748b; line-height: 1.6; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">${isRoot ? 'OK' : '404'}</div>
    <h1>${escapeHtml(heading)}</h1>
    <p>${desc}</p>
  </div>
</body>
</html>`;

    res.writeHead(status, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(html);
  }

  function sendAdminHtml(res) {
    const nonce = crypto.randomBytes(16).toString('base64');
    const safeApiBaseJson = JSON.stringify(adminPath + '/api').replace(/</g, '\\u003c');

    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <meta name="robots" content="noindex, nofollow" />
  <title>短链接路由管理后台</title>
  <style>
    :root {
      --bg: #f1f5f9;
      --surface: #ffffff;
      --border: #e2e8f0;
      --text: #0f172a;
      --muted: #64748b;
      --primary: #2563eb;
      --primary-hover: #1d4ed8;
      --danger: #dc2626;
      --danger-bg: #fef2f2;
      --success: #16a34a;
      --warn-bg: #fef9c3;
      --warn-text: #854d0e;
      --radius: 12px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
      font-size: 14px;
      line-height: 1.5;
      min-height: 100vh;
    }
    .hidden { display: none !important; }
    button, input, select { font-family: inherit; font-size: 14px; }

    .navbar {
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 0 24px;
      height: 60px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 20;
    }
    .brand { display: flex; align-items: center; gap: 10px; font-weight: 700; font-size: 16px; }
    .brand-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      background: var(--primary);
      color: #fff;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      font-size: 15px;
    }
    .domain-pill {
      font-weight: 500;
      font-size: 12px;
      background: #eff6ff;
      color: var(--primary);
      padding: 3px 10px;
      border-radius: 999px;
      border: 1px solid #bfdbfe;
    }
    .nav-actions { display: flex; align-items: center; gap: 10px; }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 8px 14px;
      border-radius: 8px;
      font-weight: 500;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.15s ease;
      white-space: nowrap;
    }
    .btn:disabled { opacity: 0.6; cursor: not-allowed; }
    .btn-primary { background: var(--primary); color: #fff; }
    .btn-primary:hover:not(:disabled) { background: var(--primary-hover); }
    .btn-outline { background: #fff; border-color: var(--border); color: var(--text); }
    .btn-outline:hover:not(:disabled) { background: #f8fafc; border-color: #cbd5e1; }
    .btn-danger-ghost { background: transparent; color: var(--danger); padding: 5px 8px; }
    .btn-danger-ghost:hover { background: var(--danger-bg); }
    .btn-sm { padding: 5px 10px; font-size: 13px; border-radius: 6px; }
    .link-btn {
      background: none;
      border: none;
      padding: 0;
      font-size: 12px;
      color: var(--primary);
      cursor: pointer;
    }
    .link-btn:hover { text-decoration: underline; }

    .container { max-width: 1160px; margin: 24px auto; padding: 0 20px 48px; }

    .center-wrap {
      min-height: calc(100vh - 80px);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px;
    }
    .auth-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 32px;
      width: 100%;
      max-width: 440px;
      box-shadow: 0 8px 28px rgba(15, 23, 42, 0.05);
    }
    .auth-card h2 { font-size: 20px; margin-bottom: 6px; }
    .auth-sub { color: var(--muted); font-size: 13px; margin-bottom: 22px; line-height: 1.6; }
    .lock-alert {
      background: var(--danger-bg);
      border: 1px solid #fecaca;
      color: #991b1b;
      padding: 14px 16px;
      border-radius: 10px;
      font-size: 13px;
      line-height: 1.6;
    }
    code {
      background: #f1f5f9;
      padding: 2px 6px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 12px;
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 20px;
    }
    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 18px 20px;
    }
    .stat-label { color: var(--muted); font-size: 13px; margin-bottom: 6px; }
    .stat-value { font-size: 26px; font-weight: 700; letter-spacing: -0.02em; }
    .stat-extra { font-size: 12px; color: var(--muted); margin-top: 4px; }

    .toolbar {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 16px;
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 16px;
    }
    .search-box { flex: 1; min-width: 220px; max-width: 400px; }
    .input, .select {
      width: 100%;
      padding: 9px 12px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #fff;
      color: var(--text);
      outline: none;
      transition: border-color 0.15s;
    }
    .input:focus, .select:focus {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
    }

    .table-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      overflow: hidden;
    }
    .table-scroll { overflow-x: auto; }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th {
      background: #f8fafc;
      color: var(--muted);
      font-weight: 600;
      font-size: 12px;
      padding: 12px 16px;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }
    td {
      padding: 14px 16px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #fcfdff; }
    tr.row-disabled td { opacity: 0.6; }

    .slug-cell { display: flex; align-items: center; gap: 8px; font-weight: 600; }
    .slug-link {
      color: var(--primary);
      text-decoration: none;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 14px;
      word-break: break-all;
    }
    .slug-link:hover { text-decoration: underline; }
    .url-text {
      max-width: 340px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: #334155;
      font-size: 13px;
    }
    .note-text { font-size: 12px; color: var(--muted); margin-top: 3px; }
    .tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
    }
    .tag-302 { background: #eff6ff; color: #1d4ed8; }
    .tag-301 { background: var(--warn-bg); color: var(--warn-text); }
    .clicks-num { font-weight: 700; font-size: 14px; }
    .time-sub { font-size: 12px; color: var(--muted); margin-top: 2px; white-space: nowrap; }

    .switch { position: relative; display: inline-block; width: 38px; height: 22px; }
    .switch input { opacity: 0; width: 0; height: 0; }
    .slider {
      position: absolute;
      cursor: pointer;
      inset: 0;
      background: #cbd5e1;
      border-radius: 999px;
      transition: 0.2s;
    }
    .slider:before {
      content: "";
      position: absolute;
      height: 16px;
      width: 16px;
      left: 3px;
      bottom: 3px;
      background: #fff;
      border-radius: 50%;
      transition: 0.2s;
    }
    .switch input:checked + .slider { background: var(--success); }
    .switch input:checked + .slider:before { transform: translateX(16px); }

    .empty-state { padding: 56px 24px; text-align: center; color: var(--muted); }

    .modal-backdrop {
      position: fixed;
      inset: 0;
      background: rgba(15, 23, 42, 0.45);
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
      z-index: 50;
    }
    .modal {
      background: var(--surface);
      border-radius: 16px;
      width: 100%;
      max-width: 520px;
      padding: 24px;
      box-shadow: 0 20px 45px rgba(15, 23, 42, 0.18);
    }
    .modal-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 18px;
    }
    .modal-header h3 { font-size: 18px; }
    .form-group { margin-bottom: 16px; }
    .form-label {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-weight: 500;
      font-size: 13px;
      margin-bottom: 6px;
    }
    .slug-input-group {
      display: flex;
      align-items: stretch;
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
      background: #fff;
    }
    .slug-input-group:focus-within {
      border-color: var(--primary);
      box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.12);
    }
    .slug-prefix {
      background: #f8fafc;
      color: var(--muted);
      padding: 9px 10px;
      border-right: 1px solid var(--border);
      font-size: 13px;
      white-space: nowrap;
      user-select: none;
    }
    .slug-input-group input {
      border: none;
      outline: none;
      padding: 9px 12px;
      flex: 1;
      min-width: 0;
    }
    .form-hint { font-size: 12px; color: var(--muted); margin-top: 5px; }
    .checkbox-row { display: flex; align-items: center; gap: 8px; }
    .modal-footer { display: flex; justify-content: flex-end; gap: 10px; margin-top: 22px; }

    .toast {
      position: fixed;
      bottom: 24px;
      right: 24px;
      background: #0f172a;
      color: #fff;
      padding: 10px 16px;
      border-radius: 8px;
      font-size: 13px;
      box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
      z-index: 100;
    }
    .toast.error { background: var(--danger); }

    @media (max-width: 640px) {
      .navbar { padding: 0 14px; }
      .domain-pill { display: none; }
      .container { padding: 0 12px 36px; margin-top: 16px; }
    }
  </style>
</head>
<body>
  <header class="navbar">
    <div class="brand">
      <span class="brand-icon">↗</span>
      <span>域名跳转管理后台</span>
      <span id="domainBadge" class="domain-pill"></span>
    </div>
    <div id="navActions" class="nav-actions hidden">
      <button id="exportBtn" class="btn btn-outline btn-sm" type="button">导出备份</button>
      <button id="importBtn" class="btn btn-outline btn-sm" type="button">导入</button>
      <input id="importFileInput" type="file" accept=".json,application/json" class="hidden" />
      <button id="logoutBtn" class="btn btn-outline btn-sm" type="button">退出</button>
    </div>
  </header>

  <section id="lockedView" class="center-wrap hidden">
    <div class="auth-card">
      <h2>后台已安全锁定</h2>
      <p class="auth-sub">为防止默认密码或弱口令导致后台被入侵，系统已自动阻断所有登录请求。</p>
      <div class="lock-alert">
        请在服务器的 <code>.env</code> 文件或 Docker 环境变量中配置至少 <strong>8 位</strong>的强密码 <code>ADMIN_PASSWORD</code>（禁止使用 <code>admin123</code>、<code>12345678</code> 等常见弱口令），然后重启容器生效。
      </div>
    </div>
  </section>

  <section id="loginView" class="center-wrap hidden">
    <div class="auth-card">
      <h2>管理员登录</h2>
      <p class="auth-sub">请输入后台管理密码（连续输错 5 次将自动锁定当前 IP）</p>
      <form id="loginForm">
        <div class="form-group">
          <label class="form-label" for="passwordInput">后台管理密码</label>
          <input id="passwordInput" type="password" class="input" placeholder="请输入管理密码" required autocomplete="current-password" />
        </div>
        <button id="loginSubmitBtn" type="submit" class="btn btn-primary" style="width: 100%; padding: 10px;">登 录</button>
      </form>
    </div>
  </section>

  <main id="dashboardView" class="container hidden">
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">自定义链接总数</div>
        <div id="statTotalLinks" class="stat-value">0</div>
        <div id="statActiveLinks" class="stat-extra">启用中 0 条</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">累计总点击访问量</div>
        <div id="statTotalClicks" class="stat-value">0</div>
        <div class="stat-extra">实时记录点击与最后访问时间</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">本地持久化引擎</div>
        <div class="stat-value" style="font-size: 20px; padding-top: 4px;">SQLite (WAL)</div>
        <div class="stat-extra">服务端有状态安全会话保护</div>
      </div>
    </div>

    <div class="toolbar">
      <div class="search-box">
        <input id="searchInput" type="search" class="input" placeholder="搜索路径 (如 abc)、目标网址或备注..." />
      </div>
      <div style="display: flex; gap: 10px;">
        <button id="refreshBtn" class="btn btn-outline" type="button">刷新</button>
        <button id="createBtn" class="btn btn-primary" type="button">+ 新建自定义跳转</button>
      </div>
    </div>

    <div class="table-card">
      <div class="table-scroll">
        <table>
          <thead>
            <tr>
              <th>自定义路径</th>
              <th>目标跳转地址 / 备注</th>
              <th>跳转方式</th>
              <th>访问统计 (点击 / 最近访问)</th>
              <th>启用</th>
              <th style="text-align: right;">操作</th>
            </tr>
          </thead>
          <tbody id="linksTableBody"></tbody>
        </table>
      </div>
      <div id="emptyState" class="empty-state hidden">
        暂无跳转规则，点击右上角「+ 新建自定义跳转」添加第一条短链接吧！
      </div>
    </div>
  </main>

  <div id="linkModal" class="modal-backdrop hidden">
    <div class="modal">
      <div class="modal-header">
        <h3 id="modalTitle">新建自定义跳转</h3>
        <button id="closeModalBtn" class="btn btn-outline btn-sm" type="button">✕</button>
      </div>
      <form id="linkForm">
        <input id="editOldSlug" type="hidden" />

        <div class="form-group">
          <div class="form-label">
            <label for="slugInput">自定义路径后缀 *</label>
            <button id="randomSlugBtn" type="button" class="link-btn">随机生成短码</button>
          </div>
          <div class="slug-input-group">
            <span id="slugOriginPrefix" class="slug-prefix"></span>
            <input id="slugInput" type="text" placeholder="例如 abc 或 promo/2026（填 @ 代表域名首页）" required />
          </div>
          <div class="form-hint">访问该路径时将自动跳转到下方目标网址；支持字母、数字、连字符、多级路径。</div>
        </div>

        <div class="form-group">
          <label class="form-label" for="urlInput">目标跳转网址 (URL) *</label>
          <input id="urlInput" type="text" class="input" placeholder="https://example.com/your-target-page" required />
        </div>

        <div class="form-group">
          <label class="form-label" for="statusCodeSelect">跳转类型</label>
          <select id="statusCodeSelect" class="select">
            <option value="302">302 临时跳转（推荐：后台修改地址立即生效，不漏统计）</option>
            <option value="301">301 永久跳转（适合固定不变的 SEO 权重传递，浏览器会缓存）</option>
          </select>
        </div>

        <div class="form-group">
          <label class="form-label" for="noteInput">备注说明（选填）</label>
          <input id="noteInput" type="text" class="input" placeholder="例如：公众号菜单活动页 / 备用下载链接" maxlength="200" />
        </div>

        <div id="editExtraOptions" class="form-group checkbox-row hidden">
          <input id="resetClicksCheckbox" type="checkbox" style="width: 16px; height: 16px;" />
          <label for="resetClicksCheckbox" style="font-size: 13px; color: #475569; cursor: pointer;">同时清零该链接的历史点击统计</label>
        </div>

        <div class="modal-footer">
          <button id="cancelModalBtn" class="btn btn-outline" type="button">取消</button>
          <button id="saveLinkBtn" class="btn btn-primary" type="submit">保存设置</button>
        </div>
      </form>
    </div>
  </div>

  <div id="toastEl" class="toast hidden"></div>

  <script nonce="${nonce}">
    (function () {
      var API_BASE = ${safeApiBaseJson};
      var origin = window.location.origin;
      var allLinks = [];
      var toastTimer = null;

      document.getElementById('domainBadge').textContent = window.location.host;
      document.getElementById('slugOriginPrefix').textContent = origin + '/';

      function showToast(msg, isError) {
        var el = document.getElementById('toastEl');
        el.textContent = msg;
        el.className = isError ? 'toast error' : 'toast';
        clearTimeout(toastTimer);
        toastTimer = setTimeout(function () {
          el.className = 'toast hidden';
        }, 2800);
      }

      async function apiFetch(subPath, options) {
        var opts = options || {};
        var headers = Object.assign({ 'X-Requested-With': 'ShortLinkAdmin' }, opts.headers || {});
        if (opts.body && typeof opts.body === 'object') {
          headers['Content-Type'] = 'application/json';
          opts.body = JSON.stringify(opts.body);
        }
        opts.headers = headers;
        var res = await fetch(API_BASE + subPath, opts);
        var data = {};
        try {
          data = await res.json();
        } catch (e) {}
        if (!res.ok) {
          var err = new Error(data.error || ('请求失败 (' + res.status + ')'));
          err.status = res.status;
          throw err;
        }
        return data;
      }

      function formatTime(iso) {
        if (!iso) return '暂无访问记录';
        var d = new Date(iso);
        if (isNaN(d.getTime())) return iso;
        var diffSec = Math.floor((Date.now() - d.getTime()) / 1000);
        var rel = '';
        if (diffSec < 60) rel = '刚刚';
        else if (diffSec < 3600) rel = Math.floor(diffSec / 60) + ' 分钟前';
        else if (diffSec < 86400) rel = Math.floor(diffSec / 3600) + ' 小时前';
        else if (diffSec < 86400 * 30) rel = Math.floor(diffSec / 86400) + ' 天前';

        var pad = function (n) { return String(n).padStart(2, '0'); };
        var full = d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) +
          ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
        return rel ? (rel + ' (' + full + ')') : full;
      }

      function getFullShortUrl(slug) {
        return slug === '@' ? (origin + '/') : (origin + '/' + slug);
      }

      function renderTable() {
        var keyword = document.getElementById('searchInput').value.trim().toLowerCase();
        var filtered = allLinks.filter(function (item) {
          if (!keyword) return true;
          return (
            item.slug.toLowerCase().indexOf(keyword) !== -1 ||
            item.url.toLowerCase().indexOf(keyword) !== -1 ||
            (item.note || '').toLowerCase().indexOf(keyword) !== -1
          );
        });

        var tbody = document.getElementById('linksTableBody');
        var emptyEl = document.getElementById('emptyState');
        tbody.innerHTML = '';

        if (filtered.length === 0) {
          emptyEl.classList.remove('hidden');
          emptyEl.textContent = allLinks.length === 0
            ? '暂无跳转规则，点击右上角「+ 新建自定义跳转」添加第一条短链接吧！'
            : '没有找到匹配搜索条件的短链接';
          return;
        }
        emptyEl.classList.add('hidden');

        filtered.forEach(function (item) {
          var tr = document.createElement('tr');
          if (!item.enabled) tr.className = 'row-disabled';

          var tdSlug = document.createElement('td');
          var slugWrap = document.createElement('div');
          slugWrap.className = 'slug-cell';
          var a = document.createElement('a');
          a.className = 'slug-link';
          a.href = getFullShortUrl(item.slug);
          a.target = '_blank';
          a.rel = 'noopener noreferrer';
          a.textContent = item.slug === '@' ? '/ (域名首页)' : ('/' + item.slug);
          var copyBtn = document.createElement('button');
          copyBtn.type = 'button';
          copyBtn.className = 'btn btn-outline btn-sm';
          copyBtn.style.padding = '2px 7px';
          copyBtn.style.fontSize = '12px';
          copyBtn.textContent = '复制';
          copyBtn.onclick = function () {
            var fullUrl = getFullShortUrl(item.slug);
            if (navigator.clipboard && navigator.clipboard.writeText) {
              navigator.clipboard.writeText(fullUrl).then(function () {
                showToast('已复制: ' + fullUrl);
              }).catch(function () {
                window.prompt('请手动复制短链接:', fullUrl);
              });
            } else {
              window.prompt('请手动复制短链接:', fullUrl);
            }
          };
          slugWrap.appendChild(a);
          slugWrap.appendChild(copyBtn);
          tdSlug.appendChild(slugWrap);

          var tdUrl = document.createElement('td');
          var urlDiv = document.createElement('div');
          urlDiv.className = 'url-text';
          urlDiv.title = item.url;
          urlDiv.textContent = item.url;
          tdUrl.appendChild(urlDiv);
          if (item.note) {
            var noteDiv = document.createElement('div');
            noteDiv.className = 'note-text';
            noteDiv.textContent = item.note;
            tdUrl.appendChild(noteDiv);
          }

          var tdCode = document.createElement('td');
          var codeSpan = document.createElement('span');
          codeSpan.className = 'tag ' + (item.status_code === 301 ? 'tag-301' : 'tag-302');
          codeSpan.textContent = item.status_code === 301 ? '301 永久' : '302 临时';
          tdCode.appendChild(codeSpan);

          var tdStats = document.createElement('td');
          var clicksDiv = document.createElement('div');
          clicksDiv.className = 'clicks-num';
          clicksDiv.textContent = (Number(item.clicks) || 0).toLocaleString() + ' 次点击';
          var timeDiv = document.createElement('div');
          timeDiv.className = 'time-sub';
          timeDiv.textContent = '最近: ' + formatTime(item.last_accessed_at);
          tdStats.appendChild(clicksDiv);
          tdStats.appendChild(timeDiv);

          var tdToggle = document.createElement('td');
          var labelSwitch = document.createElement('label');
          labelSwitch.className = 'switch';
          var chk = document.createElement('input');
          chk.type = 'checkbox';
          chk.checked = Boolean(item.enabled);
          chk.onchange = async function () {
            try {
              await apiFetch('/links/toggle', {
                method: 'PATCH',
                body: { slug: item.slug, enabled: chk.checked }
              });
              showToast(chk.checked ? '已启用跳转' : '已暂停该跳转');
              await loadLinks();
            } catch (err) {
              chk.checked = !chk.checked;
              showToast(err.message, true);
            }
          };
          var slider = document.createElement('span');
          slider.className = 'slider';
          labelSwitch.appendChild(chk);
          labelSwitch.appendChild(slider);
          tdToggle.appendChild(labelSwitch);

          var tdOps = document.createElement('td');
          tdOps.style.textAlign = 'right';
          tdOps.style.whiteSpace = 'nowrap';
          var editBtn = document.createElement('button');
          editBtn.type = 'button';
          editBtn.className = 'btn btn-outline btn-sm';
          editBtn.style.marginRight = '6px';
          editBtn.textContent = '编辑';
          editBtn.onclick = function () { openModal(item); };

          var delBtn = document.createElement('button');
          delBtn.type = 'button';
          delBtn.className = 'btn btn-danger-ghost btn-sm';
          delBtn.textContent = '删除';
          delBtn.onclick = async function () {
            var label = item.slug === '@' ? '域名首页 (/)' : ('/' + item.slug);
            if (!window.confirm('确定要删除跳转规则 "' + label + '" 吗？')) return;
            try {
              await apiFetch('/links', {
                method: 'DELETE',
                body: { slug: item.slug }
              });
              showToast('已删除规则 ' + label);
              await loadLinks();
            } catch (err) {
              showToast(err.message, true);
            }
          };

          tdOps.appendChild(editBtn);
          tdOps.appendChild(delBtn);

          tr.appendChild(tdSlug);
          tr.appendChild(tdUrl);
          tr.appendChild(tdCode);
          tr.appendChild(tdStats);
          tr.appendChild(tdToggle);
          tr.appendChild(tdOps);
          tbody.appendChild(tr);
        });
      }

      async function loadLinks() {
        try {
          var data = await apiFetch('/links');
          allLinks = data.links || [];
          document.getElementById('statTotalLinks').textContent = data.stats.totalLinks.toLocaleString();
          document.getElementById('statActiveLinks').textContent = '启用中 ' + data.stats.activeLinks + ' 条';
          document.getElementById('statTotalClicks').textContent = data.stats.totalClicks.toLocaleString();
          renderTable();
        } catch (err) {
          if (err.status === 401) {
            showView('login');
          } else {
            showToast(err.message, true);
          }
        }
      }

      function showView(name) {
        document.getElementById('lockedView').classList.toggle('hidden', name !== 'locked');
        document.getElementById('loginView').classList.toggle('hidden', name !== 'login');
        document.getElementById('dashboardView').classList.toggle('hidden', name !== 'dashboard');
        document.getElementById('navActions').classList.toggle('hidden', name !== 'dashboard');
      }

      function openModal(editItem) {
        var modal = document.getElementById('linkModal');
        var isEdit = Boolean(editItem);
        document.getElementById('modalTitle').textContent = isEdit ? '编辑跳转规则' : '新建自定义跳转';
        document.getElementById('editOldSlug').value = isEdit ? editItem.slug : '';
        document.getElementById('slugInput').value = isEdit ? editItem.slug : '';
        document.getElementById('urlInput').value = isEdit ? editItem.url : '';
        document.getElementById('statusCodeSelect').value = isEdit ? String(editItem.status_code) : '302';
        document.getElementById('noteInput').value = isEdit ? (editItem.note || '') : '';
        document.getElementById('resetClicksCheckbox').checked = false;
        document.getElementById('editExtraOptions').classList.toggle('hidden', !isEdit);
        modal.classList.remove('hidden');
        setTimeout(function () {
          document.getElementById(isEdit ? 'urlInput' : 'slugInput').focus();
        }, 30);
      }

      function closeModal() {
        document.getElementById('linkModal').classList.add('hidden');
      }

      document.getElementById('loginForm').onsubmit = async function (e) {
        e.preventDefault();
        var btn = document.getElementById('loginSubmitBtn');
        var pw = document.getElementById('passwordInput').value;
        btn.disabled = true;
        try {
          await apiFetch('/login', { method: 'POST', body: { password: pw } });
          document.getElementById('passwordInput').value = '';
          showView('dashboard');
          await loadLinks();
        } catch (err) {
          showToast(err.message, true);
        } finally {
          btn.disabled = false;
        }
      };

      document.getElementById('logoutBtn').onclick = async function () {
        await apiFetch('/logout', { method: 'POST' });
        showView('login');
      };

      document.getElementById('createBtn').onclick = function () { openModal(null); };
      document.getElementById('closeModalBtn').onclick = closeModal;
      document.getElementById('cancelModalBtn').onclick = closeModal;
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') closeModal();
      });
      document.getElementById('refreshBtn').onclick = function () { loadLinks(); };
      document.getElementById('searchInput').oninput = renderTable;

      document.getElementById('randomSlugBtn').onclick = function () {
        var chars = 'abcdefghijkmnpqrstuvwxyz23456789';
        var code = '';
        for (var i = 0; i < 5; i++) {
          code += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        document.getElementById('slugInput').value = code;
      };

      document.getElementById('linkForm').onsubmit = async function (e) {
        e.preventDefault();
        var oldSlug = document.getElementById('editOldSlug').value;
        var slug = document.getElementById('slugInput').value.trim();
        var rawUrl = document.getElementById('urlInput').value.trim();
        var lowerUrl = rawUrl.toLowerCase();
        if (rawUrl && lowerUrl.indexOf('http://') !== 0 && lowerUrl.indexOf('https://') !== 0 && rawUrl.indexOf('.') !== -1) {
          rawUrl = 'https://' + rawUrl;
        }
        var payload = {
          slug: slug,
          url: rawUrl,
          status_code: Number(document.getElementById('statusCodeSelect').value),
          note: document.getElementById('noteInput').value.trim()
        };
        var saveBtn = document.getElementById('saveLinkBtn');
        saveBtn.disabled = true;
        try {
          if (oldSlug) {
            payload.old_slug = oldSlug;
            payload.reset_clicks = document.getElementById('resetClicksCheckbox').checked;
            await apiFetch('/links', { method: 'PUT', body: payload });
            showToast('跳转规则已更新');
          } else {
            await apiFetch('/links', { method: 'POST', body: payload });
            showToast('新建跳转成功');
          }
          closeModal();
          await loadLinks();
        } catch (err) {
          showToast(err.message, true);
        } finally {
          saveBtn.disabled = false;
        }
      };

      document.getElementById('exportBtn').onclick = function () {
        var blob = new Blob([JSON.stringify({ exported_at: new Date().toISOString(), links: allLinks }, null, 2)], {
          type: 'application/json'
        });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'shortlinks-backup-' + new Date().toISOString().slice(0, 10) + '.json';
        a.click();
        URL.revokeObjectURL(url);
      };

      document.getElementById('importBtn').onclick = function () {
        document.getElementById('importFileInput').click();
      };

      document.getElementById('importFileInput').onchange = async function (e) {
        var file = e.target.files && e.target.files[0];
        if (!file) return;
        try {
          var text = await file.text();
          var parsed = JSON.parse(text);
          var list = Array.isArray(parsed) ? parsed : (parsed.links || []);
          var res = await apiFetch('/import', {
            method: 'POST',
            body: { links: list }
          });
          showToast('导入完成：成功 ' + res.imported + ' 条' + (res.skipped ? ('，跳过 ' + res.skipped + ' 条') : ''));
          await loadLinks();
        } catch (err) {
          showToast('导入失败: ' + err.message, true);
        } finally {
          e.target.value = '';
        }
      };

      (async function init() {
        try {
          var session = await apiFetch('/session');
          if (!session.configured) {
            showView('locked');
            return;
          }
          if (session.authenticated) {
            showView('dashboard');
            await loadLinks();
          } else {
            showView('login');
          }
        } catch (err) {
          showToast('初始化加载失败: ' + err.message, true);
        }
      })();
    })();
  </script>
</body>
</html>`;

    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'X-Robots-Tag': 'noindex, nofollow',
      'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
    });
    res.end(html);
  }

  // ==========================================================================
  // 主 HTTP 请求分发器
  // ==========================================================================

  async function handler(req, res) {
    try {
      const ctx = getRequestContext(req);
      const pathname = ctx.parsedUrl.pathname;
      const method = (req.method || 'GET').toUpperCase();

      // 1. Docker 容器健康检查接口
      if (pathname === '/healthz') {
        return sendJson(res, 200, { status: 'ok' });
      }

      // 2. 后台管理 API（挂载于 ${adminPath}/api/*，支持自定义路径完全隐匿）
      if (pathname.startsWith(apiPrefix)) {
        return await handleAdminApi(req, res, ctx);
      }

      // 前台页面与短链仅允许 GET 与 HEAD 请求
      if (method !== 'GET' && method !== 'HEAD') {
        res.writeHead(405, { Allow: 'GET, HEAD', 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('Method Not Allowed');
      }

      // 3. 可视化管理后台入口
      if (pathname === adminPath || pathname === adminPath + '/') {
        return sendAdminHtml(res);
      }

      // 4. 静态爬虫与图标路径（绝不在 robots.txt 中回显 adminPath，防止暴露自定义后台入口）
      if (pathname === '/favicon.ico') {
        res.writeHead(204, { 'Cache-Control': 'public, max-age=86400' });
        return res.end();
      }
      if (pathname === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        return res.end('User-agent: *\nDisallow:\n');
      }

      // 5. 短路径查询与重定向
      let slug = '@';
      if (pathname !== '/') {
        try {
          slug = decodeURIComponent(pathname).replace(/^\/+|\/+$/g, '') || '@';
        } catch {
          slug = pathname.replace(/^\/+|\/+$/g, '') || '@';
        }
      }

      const link = normalizeRow(stmts.getBySlug.get(slug));
      if (!link || !link.enabled) {
        return sendLandingOr404(res, {
          host: ctx.host,
          isRoot: slug === '@',
          slug,
        });
      }

      let safeLocation = link.url;
      try {
        safeLocation = new URL(link.url).toString();
      } catch {
        safeLocation = encodeURI(link.url);
      }

      const statusCode = link.status_code === 301 ? 301 : 302;
      const cacheControl =
        statusCode === 302
          ? 'no-store, no-cache, must-revalidate, max-age=0'
          : 'private, max-age=0, must-revalidate';

      res.writeHead(statusCode, {
        Location: safeLocation,
        'Cache-Control': cacheControl,
        'X-Robots-Tag': 'noindex',
        'Referrer-Policy': 'no-referrer',
      });
      res.end();

      if (method === 'GET') {
        try {
          stmts.recordClick.run(new Date().toISOString(), link.slug);
        } catch (err) {
          console.error('Failed to record click:', err);
        }
      }
    } catch (err) {
      console.error('Unhandled HTTP request error:', err);
      if (!res.headersSent) {
        sendJson(res, 500, { error: 'Internal Server Error' });
      } else {
        res.destroy();
      }
    }
  }

  return {
    handler,
    adminPath,
    passwordConfigured,
    close() {
      db.close();
    },
  };
}
