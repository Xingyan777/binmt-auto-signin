# MT论坛自动签到 - GitHub Actions 部署说明

本仓库用于每天自动在 [MT论坛 (bbs.binmt.cc)](https://bbs.binmt.cc/) 签到。

## 原理

MT论坛使用 Discuz + `k_misign` 签到插件，并部署了**阿里云 WAF**（`acw_sc__v2` JS 挑战）。签到脚本自动完成：

1. **过 WAF**：在 Node.js 沙箱中执行 WAF 下发的混淆 JS，计算出 `acw_sc__v2` cookie
2. **取 formhash**：访问签到页 `k_misign-sign.html`，动态解析 `formhash`
3. **签到**：调用 `plugin.php?id=k_misign:sign&operation=qiandao&format=text&formhash=xxx`

## 使用方法

### 1. 配置 GitHub Secrets

在仓库 `Settings → Secrets and variables → Actions → New repository secret` 添加：

| 名称 | 值 |
|------|-----|
| `BBS_COOKIE` | 论坛登录后的完整 Cookie 字符串（必须包含 `auth` 和 `saltkey`） |

> ⚠️ **重要**：Cookie 是登录凭证，请**只作为 Secret** 保存，绝不要提交到代码/公开内容中。

### 2. 获取你的 Cookie

1. 在浏览器登录 [MT论坛](https://bbs.binmt.cc/)，F12 打开开发者工具
2. 切到 **Network（网络）** 标签，刷新页面
3. 任选一个请求，查看 **Request Headers → Cookie**
4. 复制完整 Cookie 字符串，粘贴到 `BBS_COOKIE` Secret

### 3. 部署

1. 把本仓库推送到你的 GitHub 仓库
2. 配置好 `BBS_COOKIE` Secret
3. 添加 `.github/workflows/sign.yml` 工作流（仓库已包含）
4. GitHub Actions 会自动每天定时执行签到

## 文件结构

```
.
├── sign.js                  # 签到主脚本 (Node.js)
├── .github/workflows/
│   └── sign.yml            # GitHub Actions 定时工作流
├── .gitignore               # 忽略敏感文件
└── README.md               # 本说明
```

## 定时说明

工作流默认每天 **早上 8:00 (UTC)** 即 **北京时间 16:00** 触发（`cron: '0 0 16 * * *'` 更贴近你的作息可自行调整）。可自行修改 `sign.yml` 中的 cron 表达式。

> GitHub Actions 的 cron 使用 **UTC 时区**，北京时间 = UTC + 8 小时。

## 注意事项

- 若连续多天签到失败，多为 `BBS_COOKIE` 过期（auth/saltkey 有有效期），需重新登录获取新 Cookie 并更新 Secret。
- 脚本有 WAF 重试机制，通常一次通过。
- 建议开启 GitHub 邮件通知，可在 `Settings → Notifications` 中设置 Actions 失败提醒。