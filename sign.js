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
 * 配置（环境变量）：
 *  BBS_COOKIE  - 论坛登录后的 Cookie（含 auth/saltkey），必填
 *
 * 用法：
 *  直接运行: BBS_COOKIE="..." node sign.js
 */

const https = require('https');
const vm = require('vm');
const zlib = require('zlib');

const BASE = 'https://bbs.binmt.cc';
const UA = 'Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36';

// ---------- HTTP 请求封装（自动处理 gzip） ----------
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
    }, opts.headers || {});
    if (cookieStr) headers['Cookie'] = cookieStr;
    const reqObj = mod.get(u, { headers }, res => {
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
        resolve({ status: res.statusCode, body: buf.toString(), setCookie, headers: res.headers });
      });
    });
    reqObj.setTimeout(30000, () => reqObj.destroy(new Error('timeout')));
    reqObj.on('error', reject);
  });
}

// ---------- 合并 cookie ----------
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

// ---------- 解决阿里云 WAF acw_sc__v2 JS 挑战 ----------
function solveAcwChallenge(html) {
  // 提取 <script>...</script> 中的 JS
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  if (!m) return null;
  const js = m[1];
  // 提取 arg1 值（WAF 把关键数据放在 var arg1='...'）
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
  } catch (e) { /* 忽略运行时对 reload 等报错 */ }
  if (cookieVal.includes('acw_sc__v2')) return cookieVal;
  return null;
}

// ---------- 获取页面（自动处理 WAF 挑战） ----------
async function getWithWaf(url, cookie) {
  let c = cookie;
  for (let i = 0; i < 3; i++) {
    const r = await request(url, c);
    if (r.body.includes('acw_sc__v2') && /<script>[\s\S]*arg1\s*=/.test(r.body)) {
      const acw = solveAcwChallenge(r.body);
      if (acw) {
        c = mergeCookies(c, acw, r.setCookie);
        continue; // 重试
      }
    }
    return { res: r, cookie: mergeCookies(c, r.setCookie) };
  }
  return null;
}

// ---------- 主流程 ----------
async function main() {
  let cookie = process.env.BBS_COOKIE;
  if (!cookie) {
    console.log('❌ 缺少环境变量 BBS_COOKIE');
    process.exit(1);
  }
  // 清理：去除尾部残留的 %09/%20/分号/空白，避免干扰 Cookie 解析
  cookie = cookie.replace(/[;%\s]+$/, '').trim();

  // 1. 获取签到页，动态解析 formhash
  const signUrl = BASE + '/k_misign-sign.html';
  const sf = await getWithWaf(signUrl, cookie);
  if (!sf) { console.log('❌ 多次请求仍被 WAF 拦截'); process.exit(1); }
  const html = sf.res.body;
  const cookieWithWaf = sf.cookie;

  // 判断登录态
  if (html.includes('member.php?mod=logging') && !html.includes('qmtd')) {
    // 检查是否登录（签到页未登录会跳转登录）
  }

  const fh = html.match(/formhash=([a-f0-9]{8})/);
  if (!fh) {
    console.log('❌ 未能获取 formhash，cookie 可能已失效，请更新 BBS_COOKIE');
    process.exit(1);
  }
  const formhash = fh[1];
  console.log('✅ formhash =', formhash);

  // 2. 调用签到接口
  const qdUrl = `${BASE}/plugin.php?id=k_misign:sign&operation=qiandao&format=text&formhash=${formhash}`;
  const qd = await getWithWaf(qdUrl, cookieWithWaf);
  if (!qd) { console.log('❌ 签到请求失败（被 WAF 拦截）'); process.exit(1); }
  const respBody = qd.res.body;
  // 从 XML/CDATA 中提取纯文本
  const clean = respBody
    .replace(/^<\?xml[\s\S]*?<root><!\[CDATA\[/, '')
    .replace(/\]\]><\/root>[\s\S]*$/, '')
    .replace(/^<\/?root>/, '')
    .trim();
  const text = clean || respBody.replace(/<[^>]+>/g, '').trim();

  if (/已签到|今日已签|今日已签到/.test(respBody)) {
    console.log('📅 今日已签到过: ' + text);
  } else if (/签到成功|成功.*获取|签到.*成功/.test(respBody)) {
    console.log('✅ ' + text);
  } else if (respBody.includes('登录') && !respBody.includes('今日')) {
    console.log('❌ Cookie 已失效，请更新 BBS_COOKIE');
    process.exit(1);
  } else {
    console.log('ℹ️ 签到返回: ' + text);
  }

  // 3. 输出关键信息（供 GitHub Actions 通知）
  console.log('RESULT_BODY=' + JSON.stringify(text));
}

main().catch(e => { console.error('❌ 出错:', e.message); process.exit(1); });