import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import vm from 'node:vm';
import { createApp } from '../src/app.mjs';

async function startTestServer(opts = {}) {
  const app = createApp({
    dbPath: ':memory:',
    adminPassword: 'StrongPassword#2026!',
    adminPath: '/admin',
    failDelayMs: 0,
    ...opts,
  });
  const server = http.createServer(app.handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    app,
    port,
    baseUrl,
    async close() {
      await new Promise((resolve) => server.close(resolve));
      app.close();
    },
  };
}

test('Docker 健康检查、CSP 安全响应头与前端脚本语法校验', async () => {
  const srv = await startTestServer();
  try {
    const health = await fetch(`${srv.baseUrl}/healthz`);
    assert.equal(health.status, 200);

    const adminRes = await fetch(`${srv.baseUrl}/admin`);
    assert.equal(adminRes.status, 200);
    const csp = adminRes.headers.get('content-security-policy') || '';
    assert.match(csp, /script-src 'nonce-/);
    assert.equal(adminRes.headers.get('x-frame-options'), 'DENY');
    assert.equal(adminRes.headers.get('referrer-policy'), 'no-referrer');

    const html = await adminRes.text();
    const match = html.match(/<script nonce="[^"]+">([\s\S]*?)<\/script>/);
    assert.ok(match, '管理后台应包含带 Nonce 的内嵌脚本');
    assert.doesNotThrow(() => {
      new vm.Script(match[1]);
    });
  } finally {
    await srv.close();
  }
});

test('安全防御 1：空密码、短密码与常见弱口令一律触发后台锁定 (503)', async () => {
  for (const weakPw of ['', '1234567', 'admin123', 'password123', 'your-strong-password']) {
    const srv = await startTestServer({ adminPassword: weakPw });
    try {
      assert.equal(srv.app.passwordConfigured, false);
      const sessionRes = await fetch(`${srv.baseUrl}/admin/api/session`);
      const sessionData = await sessionRes.json();
      assert.equal(sessionData.configured, false);

      const loginAttempt = await fetch(`${srv.baseUrl}/admin/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'ShortLinkAdmin',
        },
        body: JSON.stringify({ password: weakPw }),
      });
      assert.equal(loginAttempt.status, 503);
    } finally {
      await srv.close();
    }
  }
});

test('安全防御 2：防暴力破解限流与防伪造左侧 X-Forwarded-For 绕过', async () => {
  const srv = await startTestServer({ maxLoginAttempts: 3, loginLockoutMs: 60_000 });
  try {
    // 模拟攻击者每次伪造不同的左侧 IP，但反向代理在最右侧追加真实 IP 203.0.113.50
    for (let i = 1; i <= 3; i++) {
      const res = await fetch(`${srv.baseUrl}/admin/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Requested-With': 'ShortLinkAdmin',
          'X-Forwarded-For': `1.2.3.${i}, 203.0.113.50`,
        },
        body: JSON.stringify({ password: `wrong-guess-${i}` }),
      });
      assert.equal(res.status, i < 3 ? 401 : 429);
    }

    // 锁定期间即便输入正确密码也必须被拦截 (429)
    const blockedEvenWithRightPw = await fetch(`${srv.baseUrl}/admin/api/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Requested-With': 'ShortLinkAdmin',
        'X-Forwarded-For': '9.9.9.9, 203.0.113.50',
      },
      body: JSON.stringify({ password: 'StrongPassword#2026!' }),
    });
    assert.equal(blockedEvenWithRightPw.status, 429);
  } finally {
    await srv.close();
  }
});

test('安全防御 3：自定义隐蔽后台路径不泄露，且退出登录后旧 Cookie 立即在服务端失效', async () => {
  const srv = await startTestServer({ adminPath: '/secret-panel-9x8k' });
  const headers = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'ShortLinkAdmin',
  };

  try {
    // 默认 /admin 及 /admin/api/session 完全返回 404
    const probeAdmin = await fetch(`${srv.baseUrl}/admin`);
    assert.equal(probeAdmin.status, 404);
    const probeApi = await fetch(`${srv.baseUrl}/admin/api/session`);
    assert.equal(probeApi.status, 404);

    // robots.txt 绝不泄露自定义后台路径
    const robotsTxt = await (await fetch(`${srv.baseUrl}/robots.txt`)).text();
    assert.equal(robotsTxt.includes('secret-panel-9x8k'), false);

    // 正常登录隐蔽路径
    const loginRes = await fetch(`${srv.baseUrl}/secret-panel-9x8k/api/login`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ password: 'StrongPassword#2026!' }),
    });
    assert.equal(loginRes.status, 200);
    const setCookie = loginRes.headers.get('set-cookie') || '';
    assert.match(setCookie, /Path=\/secret-panel-9x8k/);
    const cookie = setCookie.split(';')[0];

    // 跨站 Origin 伪造请求拦截 (403)
    const evilOriginRes = await fetch(`${srv.baseUrl}/secret-panel-9x8k/api/links`, {
      method: 'POST',
      headers: { ...headers, Cookie: cookie, Origin: 'https://evil-attacker.com' },
      body: JSON.stringify({ slug: 'hack', url: 'https://evil-attacker.com' }),
    });
    assert.equal(evilOriginRes.status, 403);

    // 退出登录后，重放刚才的旧 Cookie 必须返回 401（服务端真销毁）
    const logoutRes = await fetch(`${srv.baseUrl}/secret-panel-9x8k/api/logout`, {
      method: 'POST',
      headers: { ...headers, Cookie: cookie },
    });
    assert.equal(logoutRes.status, 200);

    const replayRes = await fetch(`${srv.baseUrl}/secret-panel-9x8k/api/links`, {
      headers: { Cookie: cookie },
    });
    assert.equal(replayRes.status, 401);
  } finally {
    await srv.close();
  }
});

test('核心业务回归：自定义跳转、301/302、点击统计、中文链接与防死循环验证', async () => {
  const srv = await startTestServer();
  const csrfHeaders = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'ShortLinkAdmin',
    'X-Forwarded-Proto': 'https',
    'X-Forwarded-Host': 'abc.com',
    Origin: 'https://abc.com',
  };

  try {
    const loginRes = await fetch(`${srv.baseUrl}/admin/api/login`, {
      method: 'POST',
      headers: csrfHeaders,
      body: JSON.stringify({ password: 'StrongPassword#2026!' }),
    });
    assert.equal(loginRes.status, 200);
    const setCookie = loginRes.headers.get('set-cookie') || '';
    assert.match(setCookie, /Secure/);
    const cookie = setCookie.split(';')[0];
    const authedHeaders = { ...csrfHeaders, Cookie: cookie };

    await fetch(`${srv.baseUrl}/admin/api/links`, {
      method: 'POST',
      headers: authedHeaders,
      body: JSON.stringify({ slug: 'abc', url: 'https://target1.com/a', note: '渠道A' }),
    });
    await fetch(`${srv.baseUrl}/admin/api/links`, {
      method: 'POST',
      headers: authedHeaders,
      body: JSON.stringify({ slug: 'efg', url: 'https://target2.com/b', status_code: 301 }),
    });

    const v1 = await fetch(`${srv.baseUrl}/abc`, { redirect: 'manual' });
    assert.equal(v1.status, 302);
    assert.equal(v1.headers.get('location'), 'https://target1.com/a');

    const vHead = await fetch(`${srv.baseUrl}/abc`, { method: 'HEAD', redirect: 'manual' });
    assert.equal(vHead.status, 302);

    const v3 = await fetch(`${srv.baseUrl}/efg`, { redirect: 'manual' });
    assert.equal(v3.status, 301);
    assert.equal(v3.headers.get('location'), 'https://target2.com/b');

    const listRes = await fetch(`${srv.baseUrl}/admin/api/links`, {
      headers: { Cookie: cookie },
    });
    const listData = await listRes.json();
    assert.equal(listData.stats.totalLinks, 2);
    assert.equal(listData.stats.totalClicks, 2);

    // 中文链接与中文路径
    const cnCreate = await fetch(`${srv.baseUrl}/admin/api/links`, {
      method: 'POST',
      headers: authedHeaders,
      body: JSON.stringify({
        slug: '/活动/',
        url: 'https://baike.baidu.com/item/人工智能?from=短链',
      }),
    });
    assert.equal(cnCreate.status, 201);

    const cnVisit = await fetch(`${srv.baseUrl}/${encodeURIComponent('活动')}`, {
      redirect: 'manual',
    });
    assert.equal(cnVisit.status, 302);
    assert.equal(
      cnVisit.headers.get('location'),
      'https://baike.baidu.com/item/%E4%BA%BA%E5%B7%A5%E6%99%BA%E8%83%BD?from=%E7%9F%AD%E9%93%BE'
    );

    // 畸形请求行 "//evil.com" 防崩溃
    const weirdRes = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port: srv.port,
          method: 'GET',
          path: '//evil.com',
          headers: { 'X-Forwarded-Host': 'bad host:::123' },
        },
        (res) => resolve(res.statusCode)
      );
      req.on('error', reject);
      req.end();
    });
    assert.equal(weirdRes, 404);
  } finally {
    await srv.close();
  }
});
