#!/usr/bin/env node
/**
 * MT论坛 (bbs.binmt.cc) 自动签到脚本 (Node.js)
 * 部署到 GitHub Actions 每天自动运行
 *
 * 功能：
 *  1. 自动过阿里云 WAF (acw_sc__v2 JS 挑战)
 *  2. 动态获取 formhash
 *  3. 调用 k_misign 插件签到接口
 *
 * 容错：
 *  - 单次请求超时 120s + 连接超时 30s
 *  - 单次请求自动重试 4 次
 *  - 整个签到流程整体重试最多 4 轮（应对海外 runner 到国内站网络波动）
 *
 * 配置（环境变量）：
 *  BBS_COOKIE  - 论坛登录后的 Cookie（含 auth/saltkey），必填
 */

const https = require('https');
const vm = require('vm');
const zlib = require('zlib');

const BASE = 'https://bbs.binmt.cc';
const UA = 'Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36';

const REQ_TIMEOUT = 120000;
const CONNECT_TIMEOUT = 30000;
const REQ_RETRIES = 4;
const FLOW_ATTEMPTS = 4;
const FLOW_DELAYS = [30000, 60000, 120000];

const sleep = ms => new Promise(r => setTimeout(r, ms));

function request(url, cookieStr, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url, BASE);
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? https : require('http');
    const headers = Object.assign({
      'User-Agent': UA,
      'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept-Language': 'zh-CN,zh;q=0.9',
      'Referer': BASE + '/',
      'Connection': 'close',
    }, opts.headers || {});
    if (cookieStr) headers['Cookie'] = cookieStr;
    const t0 = Date.now();
    // family:4 强制走 IPv4 —— bbs.binmt.cc 的 IPv6 链路不通（会挂起到超时），
    // GitHub runner 有 IPv6 地址，若不强制 IPv4 会偶发连接被丢弃导致快速 timeout
    const reqObj = mod.get(u, { headers, family: 4 }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        let buf = Buffer.concat(chunks);
        const enc = (res.headers['content-encoding'] || '').toLowerCase();
        try {
          if (enc.includes('gzip')) buf = zlib.gunzipSync(buf);
          else if (enc.includes('deflate')) buf = zlib.inflateSync(buf);
          else if (enc.includes('br')) buf = zlib.brotliDecompressSync(buf);
        } catch (e) { /* 保留原文 */ }
        const setCookie = (res.headers['set-cookie'] || []).join('; ');
        resolve({
          status: res.statusCode,
          body: buf.toString(),
          setCookie,
          headers: res.headers,
          ms: Date.now() - t0,
        });
      });
    });
    reqObj.setTimeout(REQ_TIMEOUT, () => reqObj.destroy(new Error('timeout')));
    reqObj.on('socket', s => { s.setTimeout(CONNECT_TIMEOUT, () => reqObj.destroy(new Error('connect_timeout'))); });
    reqObj.on('error', err => { err.reqMs = Date.now() - t0; reject(err); });
  });
}

async function requestWithRetry(url, cookieStr, opts = {}, retries = REQ_RETRIES) {
  for (let i = 0; i < retries; i++) {
    try {
      return await request(url, cookieStr, opts);
    } catch (e) {
      if (i === retries - 1) throw e;
      console.log(`⚠️ 请求失败(${e.message} code=${e.code || '-'} ${e.reqMs || '?'}ms)，第 ${i + 1} 次重试...`);
      await sleep(5000);
    }
  }
}

function mergeCookies(...cookStrs) {
  const map = new Map();
  for (const cs of cookStrs) {
    if (!cs) continue;
    for (let part of cs.split(';')) {
      part = part.trim();
      if (!part) continue;
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      const k = part.slice(0, eq).trim();
      const v = part.slice(eq + 1);
      map.set(k, v);
    }
  }
  const out = [];
  for (const [k, v] of map) out.push(k + '=' + v);
  return out.join('; ');
}

function solveAcwChallenge(html) {
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  if (!m) return null;
  const js = m[1];
  const arg1m = js.match(/arg1\s*=\s*'([0-9A-Fa-f]+)'/);
  if (!arg1m) return null;
  const arg1 = arg1m[1];
  let cookieVal = '';
  const sandbox = {
    document: {},
    location: { reload() {} },
    navigator: { userAgent: UA, platform: 'Linux x86_64' },
    localStorage: { getItem: () => null, setItem: () => {} },
    Date, Math, RegExp, String, Array, parseInt, parseFloat,
    decodeURIComponent, encodeURIComponent, console,
  };
  Object.defineProperty(sandbox.document, 'cookie', {
    get() { return cookieVal; },
    set(v) { cookieVal = v; },
  });
  try {
    vm.createContext(sandbox);
    vm.runInContext(js, sandbox, { timeout: 5000 });
  } catch (e) { /* 忽略 */ }
  if (cookieVal.includes('acw_sc__v2')) return cookieVal;
  return null;
}

async function getWithWaf(url, cookie) {
  let c = cookie;
  for (let i = 0; i < 3; i++) {
    const r = await requestWithRetry(url, c);
    if (r.body.includes('acw_sc__v2') && /<script>[\s\S]*arg1\s*=/.test(r.body)) {
      const acw = solveAcwChallenge(r.body);
      if (acw) {
        c = mergeCookies(c, acw, r.setCookie);
        continue;
      }
    }
    return { res: r, cookie: mergeCookies(c, r.setCookie) };
  }
  return null;
}

function parseResult(respBody) {
  const clean = respBody
    .replace(/^<\?xml[\s\S]*?<root><!\[CDATA\[/, '')
    .replace(/\]\]><\/root>[\s\S]*$/, '')
    .replace(/^<\/?root>/, '')
    .trim();
  const text = clean || respBody.replace(/<[^>]+>/g, '').trim();
  if (/已签到|今日已签|今日已签到/.test(respBody)) return { kind: 'already', text };
  if (/签到成功|成功.*获取|签到.*成功/.test(respBody)) return { kind: 'success', text };
  if (respBody.includes('登录') && !respBody.includes('今日')) return { kind: 'expired', text };
  return { kind: 'unknown', text };
}

async function attemptSign(cookie) {
  const signUrl = BASE + '/k_misign-sign.html';
  const sf = await getWithWaf(signUrl, cookie);
  if (!sf) return { ok: false, msg: '多次请求仍被 WAF 拦截' };
  const html = sf.res.body;
  const cookieWithWaf = sf.cookie;
  console.log(`签到页: HTTP ${sf.res.status} ${sf.res.ms}ms, ${html.length}B`);

  const fh = html.match(/formhash=([a-f0-9]{8})/);
  if (!fh) return { ok: false, msg: '未能获取 formhash（cookie 可能已失效）' };
  const formhash = fh[1];
  console.log('✅ formhash =', formhash);

  const qdUrl = `${BASE}/plugin.php?id=k_misign:sign&operation=qiandao&format=text&formhash=${formhash}`;
  const qd = await getWithWaf(qdUrl, cookieWithWaf);
  if (!qd) return { ok: false, msg: '签到请求被 WAF 拦截' };
  console.log(`签到接口: HTTP ${qd.res.status} ${qd.res.ms}ms`);

  const respBody = qd.res.body;
  const result = parseResult(respBody);

  if (result.kind === 'already') {
    console.log('📅 今日已签到过: ' + result.text);
    return { ok: true, text: result.text };
  }
  if (result.kind === 'success') {
    console.log('✅ ' + result.text);
    return { ok: true, text: result.text };
  }
  if (result.kind === 'expired') {
    console.log('❌ Cookie 已失效，请更新 BBS_COOKIE');
    return { ok: false, fatal: true, msg: 'Cookie 已失效', text: result.text };
  }
  console.log('ℹ️ 签到返回: ' + result.text);
  return { ok: true, text: result.text };
}

async function main() {
  let cookie = process.env.BBS_COOKIE;
  if (!cookie) {
    console.log('❌ 缺少环境变量 BBS_COOKIE');
    process.exit(1);
  }
  cookie = cookie.replace(/[;%\s]+$/, '').trim();

  // 随机延迟：仅 schedule 触发时生效，workflow_dispatch（手动）跳过
  // GitHub Actions 的 GITHUB_EVENT_NAME 区分触发来源
  const eventName = process.env.GITHUB_EVENT_NAME || '';
  if (eventName === 'schedule') {
    const MAX_DELAY = 4 * 60 * 60 * 1000; // 4 小时
    const delay = Math.floor(Math.random() * MAX_DELAY);
    const delayMin = Math.round(delay / 60000);
    console.log(`🎲 随机延迟 ${delayMin} 分钟（${(delay / 1000).toFixed(0)}s）后开始签到...`);
    console.log(`   预计签到时间：约 ${new Date(Date.now() + delay).toISOString()}`);

    // 分段 sleep，每 10 分钟输出一次心跳（GitHub Actions 6h 超时，4h 安全）
    const HEARTBEAT = 10 * 60 * 1000;
    let remaining = delay;
    while (remaining > 0) {
      const step = Math.min(remaining, HEARTBEAT);
      await sleep(step);
      remaining -= step;
      if (remaining > 0) {
        const leftMin = Math.round(remaining / 60000);
        console.log(`⏳ 剩余 ${leftMin} 分钟...`);
      }
    }
    console.log('⏰ 延迟结束，开始签到！');
  } else {
    console.log('🚀 手动触发，跳过随机延迟');
  }

  for (let attempt = 1; attempt <= FLOW_ATTEMPTS; attempt++) {
    if (attempt > 1) {
      const delay = FLOW_DELAYS[attempt - 2] || 120000;
      console.log(`\n🔄 整体第 ${attempt} 轮尝试（等待 ${delay / 1000}s 后开始）...`);
      await sleep(delay);
    }
    try {
      const r = await attemptSign(cookie);
      if (r.ok) {
        console.log('✅ 签到流程成功.');
        console.log('RESULT_BODY=' + JSON.stringify(r.text));
        process.exit(0);
      }
      if (r.fatal) {
        console.log('❌ ' + r.msg);
        process.exit(1);
      }
      console.log('⚠️ 本轮未完成: ' + r.msg);
    } catch (e) {
      console.log(`⚠️ 本轮异常: ${e.message} code=${e.code || '-'}`);
    }
  }
  console.log('❌ 多次尝试均失败，签到未完成');
  process.exit(1);
}

main().catch(e => { console.error('❌ 出错:', e.message); process.exit(1); });