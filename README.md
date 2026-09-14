# CastleKeep · SkyCastle 自动续期

完整 GitHub Actions 工作流：登录 [SkyCastle 面板](https://panel.skycastle.us)（FeatherPanel）、桌面 AFK 挂机赚 Credits（默认只跑 10 次）、用 Credits 保住套餐并拉起服务器。

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
| **服务器续期** | `POST` | `/api/user/servers/{id}/renew`（多路径探测） |
| 关机/重启/开机 | `POST` | `/api/user/servers/{id}/power/{stop,restart,start}` |

服务器卡片上的 **RENEWAL**（如 `1 credits · in 36h`）是**手动续期按钮**，脚本会模拟点击。
工作流：**AFK 养 Credits → 点服务器续期 → 关机重启 → TG 准确反馈**。

BillingAFK 的 `last_seen_afk` 按用户锁 60 秒。已移除独立的 mobile workflow，避免与桌面 AFK 抢锁导致 `RATE_LIMIT_EXCEEDED`。

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
| `SKYCASTLE_PLAN_ID` | 可选 | 无订阅或过期时重新订阅的 plan id（日志会打印可用套餐 id） |
| `SKYCASTLE_PANEL` | 可选 | 默认 `https://panel.skycastle.us` |
| `SKYCASTLE_SERVER_RENEW` | 可选 | 默认 `1`，点击服务器卡片续期；`0` 关闭 |
| `SKYCASTLE_RESTART_SERVERS` | 可选 | 默认 `1`，续期后重启服务器；`0` 关闭 |
| `SKYCASTLE_START_SERVERS` | 可选 | 默认 `1`，仅离线时开机 |
| `CAPSOLVER_KEY` | 可选 | 登录遇到 Turnstile 时自动过码 |
| `SKYCASTLE_TURNSTILE_SITEKEY` | 可选 | Turnstile site key |
| `TELEGRAM_BOT_TOKEN` | 可选 | Telegram Bot Token（@BotFather） |
| `TELEGRAM_CHAT_ID` | 可选 | 接收通知的 chat id |
| `DISCORD_WEBHOOK` | 可选 | Discord webhook |
| `SKYCASTLE_TG_SCREENSHOT` | 可选 | 默认 `1`，向 TG 发送状态截图卡片；设 `0` 关闭 |
| `SKYCASTLE_TG_DOCUMENT` | 可选 | 设 `1` 时额外发送 last-report.json 文件 |

\* 若提供了有效的 `SKYCASTLE_TOKEN`，邮箱密码可以不填。

### Telegram 通知（推荐）

1. 找 [@BotFather](https://t.me/BotFather) 创建 bot，拿到 `TELEGRAM_BOT_TOKEN`
2. 把 bot 拉进你的私聊或群，发任意消息
3. 打开 `https://api.telegram.org/bot<TOKEN>/getUpdates` 查 `chat.id`，填到 `TELEGRAM_CHAT_ID`
4. 跑完后会收到：
   - HTML 格式状态卡片（Credits / 套餐 / 服务器 / AFK）
   - 状态截图 PNG（可用 `SKYCASTLE_TG_SCREENSHOT=0` 关闭）

### 续期流程说明（服务器卡片 RENEWAL）

面板服务器卡片：

```
RENEWAL · Due 9月17日 · 1 credits · in 36h
```

这是**需要点击的手动续期**，不是 BillingPlans 自动 cron。

脚本会：

1. 列出服务器，记录 Due / cost / 状态
2. **点击续期** `POST .../servers/{id}/renew`（多路径探测）
3. **关机 + 重启** `power/restart`（失败则 stop→start）
4. 再拉一次服务器与 Credits，生成准确反馈：
   - 日志：`due 旧→新`、`state 旧→新`、`credits 旧→新`
   - Telegram HTML 卡片：续期成功/失败、重启成功/失败
   - 状态截图 PNG caption 含续期/重启计数

### 拿 `remember_token`（最稳，推荐）

1. 浏览器登录 https://panel.skycastle.us
2. F12 → Application / 存储 → Cookies → `panel.skycastle.us`
3. 复制 `remember_token` 的值到 Secret `SKYCASTLE_TOKEN`

## 3. 工作流

| 文件 | 默认节奏 | 做什么 |
| --- | --- | --- |
| `.github/workflows/skycastle.yml` | 每 6 小时 | 续期 + 桌面 AFK（默认 10 次） |
| `.github/workflows/afk.yml` | 01/07/13/19 UTC | 只跑桌面 AFK，默认 10 分钟 |

GitHub 单 job 上限 6 小时，脚本把挂机封顶在 330 分钟。默认 AFK 已压缩为 10 次，避免长时间占用和 rate limit。

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
python3 skycastle.py afk --minutes 10
python3 skycastle.py all --minutes 10
```

无第三方依赖（Python 3.10+）。默认 `--minutes 10`。

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
