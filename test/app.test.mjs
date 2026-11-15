import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import vm from 'node:vm';
import { createApp } from '../src/app.mjs';

async function startTestServer(opts = {}) {
  const app = createApp({
    dbPath: ':memory:',
    adminPassword: 'test-password-123',
    adminPath: '/admin',
    ...opts,
  });
  const server = http.createServer(app.handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  return {
    port,
    baseUrl,
    async close() {
      await new Promise((resolve) => server.close(resolve));
      app.close();
    },
  };
}

test('Docker 健康检查接口 /healthz 与前端脚本语法校验', async () => {
  const srv = await startTestServer();
  try {
    const health = await fetch(`${srv.baseUrl}/healthz`);
    assert.equal(health.status, 200);
    const hJson = await health.json();
    assert.equal(hJson.status, 'ok');

    const adminRes = await fetch(`${srv.baseUrl}/admin`);
    assert.equal(adminRes.status, 200);
    const html = await adminRes.text();
    const match = html.match(/<script>([\s\S]*?)<\/script>/);
    assert.ok(match, '管理后台应包含内嵌脚本');
    assert.doesNotThrow(() => {
      new vm.Script(match[1]);
    });
  } finally {
    await srv.close();
  }
});

test('端到端跳转、301/302 切换、点击统计、反向代理头及安全防护验证', async () => {
  const srv = await startTestServer();
  const csrfHeaders = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'ShortLinkAdmin',
    'X-Forwarded-Proto': 'https',
    'X-Forwarded-Host': 'abc.com',
  };

  try {
    // 1. 登录并验证反向代理 HTTPS 下生成 Secure Cookie
    const loginRes = await fetch(`${srv.baseUrl}/__admin_api/login`, {
      method: 'POST',
      headers: csrfHeaders,
      body: JSON.stringify({ password: 'test-password-123' }),
    });
    assert.equal(loginRes.status, 200);
    const setCookie = loginRes.headers.get('set-cookie') || '';
    assert.match(setCookie, /sl_session=/);
    assert.match(setCookie, /Secure/);
    const cookie = setCookie.split(';')[0];

    const authedHeaders = { ...csrfHeaders, Cookie: cookie };

    // 2. 新建 abc.com/abc -> URL 1 (默认 302) 与 abc.com/efg -> URL 2 (301)
    const r1 = await fetch(`${srv.baseUrl}/__admin_api/links`, {
      method: 'POST',
      headers: authedHeaders,
      body: JSON.stringify({ slug: 'abc', url: 'https://target1.com/a', note: '渠道A' }),
    });
    assert.equal(r1.status, 201);

    const r2 = await fetch(`${srv.baseUrl}/__admin_api/links`, {
      method: 'POST',
      headers: authedHeaders,
      body: JSON.stringify({ slug: 'efg', url: 'https://target2.com/b', status_code: 301 }),
    });
    assert.equal(r2.status, 201);

    // 3. 访问 /abc 与 /efg
    const v1 = await fetch(`${srv.baseUrl}/abc`, { redirect: 'manual' });
    assert.equal(v1.status, 302);
    assert.equal(v1.headers.get('location'), 'https://target1.com/a');

    // HEAD 探测不计入点击量，但正常返回跳转头；POST 返回 405
    const vHead = await fetch(`${srv.baseUrl}/abc`, { method: 'HEAD', redirect: 'manual' });
    assert.equal(vHead.status, 302);
    assert.equal(vHead.headers.get('location'), 'https://target1.com/a');

    const vPost = await fetch(`${srv.baseUrl}/abc`, { method: 'POST', redirect: 'manual' });
    assert.equal(vPost.status, 405);

    const v3 = await fetch(`${srv.baseUrl}/efg`, { redirect: 'manual' });
    assert.equal(v3.status, 301);
    assert.equal(v3.headers.get('location'), 'https://target2.com/b');

    // 4. 查询统计数据验证点击量（HEAD 不增加次数，因此总点击为 2）
    const listRes = await fetch(`${srv.baseUrl}/__admin_api/links`, {
      headers: { Cookie: cookie },
    });
    const listData = await listRes.json();
    assert.equal(listData.stats.totalLinks, 2);
    assert.equal(listData.stats.totalClicks, 2);
    const abcRow = listData.links.find((x) => x.slug === 'abc');
    assert.equal(abcRow.clicks, 1);
    assert.ok(abcRow.last_accessed_at);

    // 5. 中文目标地址 & 中文路径跳转不崩溃（防 ERR_INVALID_CHAR）
    const cnCreate = await fetch(`${srv.baseUrl}/__admin_api/links`, {
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

    // 6. 畸形请求行 "//evil.com" 与畸形转发头防崩溃校验
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

    // 7. 批量导入容错测试（包含 null 与非法项时不崩溃）
    const impRes = await fetch(`${srv.baseUrl}/__admin_api/import`, {
      method: 'POST',
      headers: authedHeaders,
      body: JSON.stringify({
        links: [null, 123, { slug: 'ok-import', url: 'https://example.com/ok' }],
      }),
    });
    assert.equal(impRes.status, 200);
    const impJson = await impRes.json();
    assert.equal(impJson.imported, 1);
    assert.equal(impJson.skipped, 2);

    // 8. 防死循环跳转（结合 X-Forwarded-Host: abc.com）
    const loopRes = await fetch(`${srv.baseUrl}/__admin_api/links`, {
      method: 'POST',
      headers: authedHeaders,
      body: JSON.stringify({ slug: 'self', url: 'https://abc.com/self' }),
    });
    assert.equal(loopRes.status, 400);
  } finally {
    await srv.close();
  }
});
