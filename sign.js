#!/usr/bin/env node
/**
 * MT论坛 (bbs.binmt.cc) 自动签到脚本 (Node.js)
 *
 * 修复记录 (2026-11-22):
 *  - 11-17 run#63 失败根因: 签到页 HTTP 403 + 0B 响应体 = 边缘 WAF 直接拦截,
 *    旧版误判为 "cookie 失效", 且用同一出口 IP 死等 30/60/120s 重试无意义。
 *  - 针对性修复:
 *    1) 补全真实 Chrome 请求指纹 (Sec-Fetch-* / Sec-Ch-Ua/Upgrade-Insecure-Requests),
 *       Connection 从 close 改为 keep-alive —— close 是典型机器人特征。
 *    2) UA 升级到 Chrome 132/133 并在单次运行内固定一套指纹（避免每请求换 UA 更可疑）。
 *    3) 403/429/空响应单独分类为 WAF 拦截，诊断日志给出状态码和 body 大小。
 *    4) 新增可选 BBS_PROXY 备用出口 (HTTP CONNECT 隧道, 零依赖)；
 *       命中 403 时立即切到备用出口重试，不再傻等。
 *    5) 整体重试等待从 30/60/120s 缩到 10/20/30/60s，轮数 4→5。
 *    6) 随机延迟上限 4h→2h（默认），降低晚高峰暴露面与 6h job 超时风险。
 *
 * 环境变量:
 *  BBS_COOKIE  必填, 论坛登录 Cookie
 *  BBS_PROXY   可选, 备用出口 http://[user:pass@]host:port
 *  BBS_MAX_DELAY_H  可选, 随机延迟上限小时数, 默认 2
 */

const https = require('https');
const http = require('http');
const tls = require('tls');
const vm = require('vm');
const zlib = require('zlib');

const BASE = 'https://bbs.binmt.cc';
const PROXY = (process.env.BBS_PROXY || '').trim();
const MAX_DELAY_H = Math.max(0, Math.min(6, Number(process.env.BBS_MAX_DELAY_H) || 2));
let activeProxy = ''; // 第一轮先直连，命中 403 再切备用出口

// 单次运行内固定一套浏览器指纹
const FP = pickFingerprint();
function pickFingerprint() {
  const pool = [
    { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
      sec: '"Chromium";v="133", "Not_A Brand";v="24"', platform: '"Windows"', mobile: '?0' },
    { ua: 'Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Mobile Safari/537.36',
      sec: '"Chromium";v="133", "Not_A Brand";v="24"', platform: '"Android"', mobile: '?1' },
    { ua: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36',
      sec: '"Chromium";v="132", "Not_A Brand";v="24"', platform: '"macOS"', mobile: '?0' },
  ];
  return pool[Math.floor(Math.random() * pool.length)];
}

const REQ_TIMEOUT = 120000;
const REQ_RETRIES = 3;
const FLOW_ATTEMPTS = 5;
const FLOW_DELAYS = [10000, 20000, 30000, 60000];
const sleep = ms => new Promise(r => setTimeout(r, ms));

function buildHeaders(cookieStr, extra = {}, isDoc = true) {
  const h = {
    'User-Agent': FP.ua,
    'Accept': isDoc
      ? 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'
      : 'text/plain, */*; q=0.8',
    'Accept-Language': 'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Sec-Ch-Ua': FP.sec,
    'Sec-Ch-Ua-Mobile': FP.mobile,
    'Sec-Ch-Ua-Platform': FP.platform,
    'Sec-Fetch-Dest': isDoc ? 'document' : 'empty',
    'Sec-Fetch-Mode': isDoc ? 'navigate' : 'cors',
    'Sec-Fetch-Site': isDoc ? 'none' : 'same-origin',
    'Upgrade-Insecure-Requests': '1',
    'Connection': 'keep-alive',
    'Referer': BASE + '/',
  };
  if (isDoc) h['Sec-Fetch-User'] = '?1';
  if (cookieStr) h['Cookie'] = cookieStr;
  Object.assign(h, extra);
  return h;
}

// HTTP CONNECT 隧道：让 https 请求走备用出口（零第三方依赖）
function connectViaProxy(u) {
  return new Promise((resolve, reject) => {
    let p;
    try { p = new URL(activeProxy); } catch (e) { return reject(new Error('BAD_PROXY')); }
    const target = `${u.hostname}:${u.port || 443}`;
    const pHeaders = { Host: target };
    if (p.username || p.password) {
      pHeaders['Proxy-Authorization'] = 'Basic ' + Buffer.from(
        decodeURIComponent(p.username) + ':' + decodeURIComponent(p.password)
      ).toString('base64');
    }
    const c = http.request({
      host: p.hostname,
      port: Number(p.port) || 80,
      method: 'CONNECT',
      path: target,
      headers: pHeaders,
    });
    c.setTimeout(20000, () => c.destroy(new Error('PROXY_CONNECT_TIMEOUT')));
    c.once('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        return reject(new Error('PROXY_CONNECT_' + res.statusCode));
      }
      const s = tls.connect({ socket, servername: u.hostname, ALPNProtocols: ['http/1.1'] });
      s.once('secureConnect', () => resolve(s));
      s.once('error', reject);
    });
    c.once('error', reject);
    c.end();
  });
}

function request(url, cookieStr, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url, BASE);
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? https : http;
    const headers = buildHeaders(cookieStr, opts.headers || {}, opts.isDoc !== false);
    const t0 = Date.now();
    const reqOpts = { headers, family: 4, agent: false };
    if (activeProxy && isHttps) {
      const agent = new https.Agent({ keepAlive: false });
      agent.createConnection = (o, cb) => connectViaProxy(u).then(s => cb(null, s), cb);
      reqOpts.agent = agent;
    }
    const reqObj = mod.request(u, reqOpts, res => {
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
        resolve({
          status: res.statusCode,
          body: buf.toString(),
          setCookie: (res.headers['set-cookie'] || []).join('; '),
          headers: res.headers,
          ms: Date.now() - t0,
        });
      });
    });
    reqObj.setTimeout(REQ_TIMEOUT, () => reqObj.destroy(new Error('timeout')));
    reqObj.on('error', err => { err.reqMs = Date.now() - t0; reject(err); });
    reqObj.end();
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
      map.set(part.slice(0, eq).trim(), part.slice(eq + 1));
    }
  }
  return [...map].map(([k, v]) => k + '=' + v).join('; ');
}

function solveAcwChallenge(html) {
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  if (!m) return null;
  const js = m[1];
  const arg1m = js.match(/arg1\s*=\s*'([0-9A-Fa-f]+)'/);
  if (!arg1m) return null;
  let cookieVal = '';
  const sandbox = {
    document: {}, location: { reload() {} },
    navigator: { userAgent: FP.ua, platform: 'Linux x86_64' },
    localStorage: { getItem: () => null, setItem: () => {} },
    Date, Math, RegExp, String, Array, parseInt, parseFloat,
    decodeURIComponent, encodeURIComponent, console,
  };
  Object.defineProperty(sandbox.document, 'cookie', { get() { return cookieVal; }, set(v) { cookieVal = v; } });
  try { vm.createContext(sandbox); vm.runInContext(js, sandbox, { timeout: 5000 }); } catch (e) {}
  return cookieVal.includes('acw_sc__v2') ? cookieVal : null;
}

async function getWithWaf(url, cookie, isDoc = true) {
  let c = cookie;
  for (let i = 0; i < 3; i++) {
    const r = await requestWithRetry(url, c, { isDoc });
    // 403/429/空响应 = 边缘 WAF 直接拦截，没有 JS 挑战页可解
    if (r.status === 403 || r.status === 429 || r.body.length === 0) {
      return { res: r, cookie: mergeCookies(c, r.setCookie), blocked: true };
    }
    if (r.body.includes('acw_sc__v2') && /<script>[\s\S]*arg1\s*=/.test(r.body)) {
      const acw = solveAcwChallenge(r.body);
      if (acw) { c = mergeCookies(c, acw, r.setCookie); continue; }
    }
    return { res: r, cookie: mergeCookies(c, r.setCookie), blocked: false };
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
  const sf = await getWithWaf(signUrl, cookie, true);
  if (!sf) return { ok: false, msg: '多次请求仍被 WAF 拦截' };
  const html = sf.res.body;
  const via = activeProxy ? 'PROXY' : 'DIRECT';
  console.log(`签到页: HTTP ${sf.res.status} ${sf.res.ms}ms, ${html.length}B [${via}]`);

  if (sf.blocked) {
    return { ok: false, waf: true, msg: `HTTP ${sf.res.status} 边缘 WAF 拦截 (${html.length}B)` };
  }
  const fh = html.match(/formhash=([a-f0-9]{8})/);
  if (!fh) return { ok: false, msg: '未能获取 formhash（cookie 可能已失效）' };
  const formhash = fh[1];
  console.log('✅ formhash =', formhash);

  const qdUrl = `${BASE}/plugin.php?id=k_misign:sign&operation=qiandao&format=text&formhash=${formhash}`;
  const qd = await getWithWaf(qdUrl, sf.cookie, false);
  if (!qd) return { ok: false, msg: '签到请求被 WAF 拦截' };
  console.log(`签到接口: HTTP ${qd.res.status} ${qd.res.ms}ms`);
  if (qd.blocked) return { ok: false, waf: true, msg: `签到接口 HTTP ${qd.res.status} 被拦截` };

  const result = parseResult(qd.res.body);
  if (result.kind === 'already') { console.log('📅 今日已签到过: ' + result.text); return { ok: true, text: result.text }; }
  if (result.kind === 'success') { console.log('✅ ' + result.text); return { ok: true, text: result.text }; }
  if (result.kind === 'expired') { console.log('❌ Cookie 已失效，请更新 BBS_COOKIE'); return { ok: false, fatal: true, msg: 'Cookie 已失效', text: result.text }; }
  console.log('ℹ️ 签到返回: ' + result.text);
  return { ok: true, text: result.text };
}

async function main() {
  let cookie = process.env.BBS_COOKIE;
  if (!cookie) { console.log('❌ 缺少环境变量 BBS_COOKIE'); process.exit(1); }
  cookie = cookie.replace(/[;%\s]+$/, '').trim();
  console.log(`🔖 指纹: ${FP.ua}`);
  if (PROXY) console.log(`🌐 备用出口已配置: ${PROXY.replace(/\/\/[^@]*@/, '//***@')}（403 时自动切换）`);

  const eventName = process.env.GITHUB_EVENT_NAME || '';
  if (eventName === 'schedule') {
    const delay = Math.floor(Math.random() * MAX_DELAY_H * 3600 * 1000);
    console.log(`🎲 随机延迟 ${Math.round(delay / 60000)} 分钟（${(delay / 1000).toFixed(0)}s）后开始签到...`);
    console.log(`   预计签到时间：约 ${new Date(Date.now() + delay).toISOString()}`);
    const HEARTBEAT = 10 * 60 * 1000;
    let remaining = delay;
    while (remaining > 0) {
      const step = Math.min(remaining, HEARTBEAT);
      await sleep(step);
      remaining -= step;
      if (remaining > 0) console.log(`⏳ 剩余 ${Math.round(remaining / 60000)} 分钟...`);
    }
    console.log('⏰ 延迟结束，开始签到！');
  } else {
    console.log('🚀 手动触发，跳过随机延迟');
  }

  let lastWaf = false, lastUsedProxy = false;
  for (let attempt = 1; attempt <= FLOW_ATTEMPTS; attempt++) {
    if (attempt > 1) {
      if (lastWaf && !lastUsedProxy && PROXY) {
        activeProxy = PROXY;
        console.log('\n🔁 命中 403：立即切换备用出口重试（不等待）');
      } else {
        const d = FLOW_DELAYS[attempt - 2] || 60000;
        console.log(`\n🔄 整体第 ${attempt} 轮尝试（等待 ${d / 1000}s 后开始）...`);
        await sleep(d);
      }
    }
    const usedProxy = !!activeProxy;
    try {
      const r = await attemptSign(cookie);
      lastWaf = !!r.waf; lastUsedProxy = usedProxy;
      if (r.ok) {
        console.log('✅ 签到流程成功.');
        console.log('RESULT_BODY=' + JSON.stringify(r.text));
        process.exit(0);
      }
      if (r.fatal) { console.log('❌ ' + r.msg); process.exit(1); }
      console.log('⚠️ 本轮未完成: ' + r.msg);
    } catch (e) {
      lastWaf = false; lastUsedProxy = usedProxy;
      console.log(`⚠️ 本轮异常: ${e.message} code=${e.code || '-'}`);
    }
  }
  console.log('❌ 多次尝试均失败，签到未完成');
  process.exit(1);
}

main().catch(e => { console.error('❌ 出错:', e.message); process.exit(1); });
