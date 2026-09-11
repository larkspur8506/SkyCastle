# CastleKeep · SkyCastle 自动续期

完整 GitHub Actions 工作流：登录 [SkyCastle 面板](https://panel.skycastle.us)（FeatherPanel）、AFK 挂机赚 Credits、手机 Credits、用 Credits 保住套餐并拉起服务器。

面板真实接口（2026-09 对 `panel.skycastle.us` + FeatherPanel / BillingAFK / BillingPlans 源码核对）：

| 步骤 | 方法 | 路径 |
| --- | --- | --- |
| 登录 | `PUT` | `/api/user/auth/login` `{username_or_email, password, turnstile_token?}` |
| 2FA | `POST` | `/api/user/auth/two-factor` `{email, code}` |
| 会话 | Cookie | `remember_token`（30 天）也可 `Authorization: Bearer <API key>` |
| AFK 状态 | `GET` | `/api/user/billingafk/status` |
| AFK 心跳 | `POST` | `/api/user/billingafk/work` 最少间隔 **60 秒** |
| Credits | `GET` | `/api/user/billingcore/credits` |
| 套餐 | `GET` | `/api/user/billingplans/subscriptions` |
| 订阅 | `POST` | `/api/user/billingplans/plans/{id}/subscribe` |
| 服务器 | `GET` | `/api/user/servers` |
| 开机 | `POST` | `/api/user/servers/{uuidShort}/power/start` |

BillingPlans **没有「立刻续期」按钮**。面板 cron 到期时用账户 Credits 自动续。本仓库的工作是：**挂机把 Credits 堆够 + 过期则重新 subscribe + 离线服务器开机**。

BillingAFK 的 `last_seen_afk` 按用户锁 60 秒，所以 **桌面 AFK 和手机 Credits 不要同时跑**。三个 workflow 的 cron 已经错开。

## 1. 上传到 GitHub

1. 新建一个 **private** 仓库（里面有密码/Token）。
2. 把本目录全部文件推上去（不要漏 `.github/workflows/`）。
3. **Settings → Secrets and variables → Actions** 添加密钥。
4. **Actions** 页允许 workflows，然后 **Run workflow** 先跑一次 `login` 或 `status`。

## 2. Secrets

最少只要下面一组：

| Secret | 必填 | 说明 |
| --- | --- | --- |
| `SKYCASTLE_EMAIL` | 是* | 邮箱或用户名 |
| `SKYCASTLE_PASSWORD` | 是* | 至少 8 位 |
| `SKYCASTLE_TOKEN` | 推荐 | 浏览器 Cookie `remember_token`，可跳过验证码 |
| `SKYCASTLE_TOTP` | 开了 2FA 时 | 验证器 base32 密钥 |
| `SKYCASTLE_ACCOUNTS` | 多账号 | JSON 数组，见 `accounts.example.json` |
| `SKYCASTLE_PLAN_ID` | 可选 | 套餐过期时重新订阅的 plan id |
| `SKYCASTLE_PANEL` | 可选 | 默认 `https://panel.skycastle.us` |
| `SKYCASTLE_START_SERVERS` | 可选 | `0` 关闭自动开机，默认开机 |
| `CAPSOLVER_KEY` | 可选 | 登录遇到 Turnstile 时自动过码 |
| `SKYCASTLE_TURNSTILE_SITEKEY` | 可选 | Turnstile site key |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | 可选 | 跑完推送 |
| `DISCORD_WEBHOOK` | 可选 | 跑完推送 |

\* 若提供了有效的 `SKYCASTLE_TOKEN`，邮箱密码可以不填。

### 拿 `remember_token`（最稳，推荐）

1. 浏览器登录 https://panel.skycastle.us
2. F12 → Application / 存储 → Cookies → `panel.skycastle.us`
3. 复制 `remember_token` 的值到 Secret `SKYCASTLE_TOKEN`

## 3. 工作流

| 文件 | 默认节奏 | 做什么 |
| --- | --- | --- |
| `.github/workflows/skycastle.yml` | 每 6 小时 | 续期 + 桌面 AFK + 手机 Credits |
| `.github/workflows/afk.yml` | 01/07/13/19 UTC | 只跑桌面 AFK，默认 300 分钟 |
| `.github/workflows/mobile.yml` | 04/10/16/22 UTC | 只跑手机 UA 挂机 |

GitHub 单 job 上限 6 小时，脚本把挂机封顶在 330 分钟。

手动运行：Actions → SkyCastle Renew + AFK → Run workflow → 选 `status` 先确认登录。

## 4. 本地跑

```bash
export SKYCASTLE_EMAIL='you@example.com'
export SKYCASTLE_PASSWORD='********'
# 可选
export SKYCASTLE_TOKEN='remember_token...'
export SKYCASTLE_TOTP='BASE32SECRET'

python3 skycastle.py status
python3 skycastle.py renew
python3 skycastle.py afk --minutes 30
python3 skycastle.py mobile --minutes 30
python3 skycastle.py all --minutes 20
```

无第三方依赖（Python 3.10+）。

## 5. 登录模式 / 续期模式（探测结果）

**登录模式**

1. 邮箱或用户名 + 密码，`PUT /api/user/auth/login`
2. 若开启 Cloudflare Turnstile：请求体带 `turnstile_token`（可用 Capsolver，或改用 cookie）
3. 若开启 2FA：返回 `TWO_FACTOR_REQUIRED`，再 `POST /api/user/auth/two-factor`
4. 成功后 `Set-Cookie: remember_token`，后续所有鉴权接口只带这个 Cookie
5. Discord / OIDC / Passkey / LDAP / 邮箱验证码登录面板也支持，本脚本走密码 + TOTP + cookie，覆盖 99% 自动续期场景

**续期模式**

1. 读 Credits 与订阅，`next_renewal_at` 由面板 cron 扣 Credits 自动延
2. 订阅不是 `active/grace/trial` 时，用原 `plan_id` 或 `SKYCASTLE_PLAN_ID` 再 subscribe
3. Credits 不够会失败 → 先靠 AFK / 手机 Credits 攒
4. 服务器状态 offline/stopped/suspended 时 `POST .../power/start`

**AFK + 手机 Credits**

对应页面 https://panel.skycastle.us/dashboard/earn/afk  
前端每 60 秒打一次 `/api/user/billingafk/work`。手机模式换 Android + `FeatherPanel-Mobile` UA 和 `Sec-CH-UA-Mobile: ?1`，走同一条 BillingAFK 心跳（部分面板按设备分流 credits）。

## 6. 注意

- 仓库务必 **private**。
- 遵守 SkyCastle / FeatherPanel 服务条款。频繁打接口可能触发限流或封号。
- Fork 后 GitHub 默认关掉 Actions，需要手动 Enable。
- 第一次建议 `mode=status`，看日志里有没有 `remember_token captured`。
