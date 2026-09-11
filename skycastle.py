#!/usr/bin/env python3
"""SkyCastle (FeatherPanel) auto-renew + AFK / mobile credits farmer.

Designed to run on GitHub Actions. Stdlib only.

Login:
  PUT  /api/user/auth/login          {username_or_email, password, turnstile_token?}
  POST /api/user/auth/two-factor     {email, code}   if 2FA
  Cookie remember_token (30 days)    also accepted as SKYCASTLE_TOKEN

AFK credits (BillingAFK):
  GET  /api/user/billingafk/status
  POST /api/user/billingafk/work     every >= 60s  {minutes_afk: 1}

Renewal (BillingPlans + servers):
  GET  /api/user/billingcore/credits
  GET  /api/user/billingplans/subscriptions
  GET  /api/user/billingplans/plans
  POST /api/user/billingplans/plans/{id}/subscribe
  GET  /api/user/servers
  POST /api/user/servers/{uuidShort}/power/start
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar, MozillaCookieJar
from typing import Any

PANEL_DEFAULT = "https://panel.skycastle.us"
UA_DESKTOP = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
UA_MOBILE = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.6613.146 Mobile Safari/537.36 "
    "FeatherPanel-Mobile/1.0"
)
WORK_MIN_INTERVAL = 61  # BillingAFK rate-limits at 60s


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def log(msg: str, level: str = "info") -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    prefix = {"info": "·", "ok": "✓", "warn": "!", "err": "✗", "afk": "△"}.get(level, "·")
    line = f"[{ts}] {prefix} {msg}"
    print(line, flush=True)


def totp(secret: str, for_time: float | None = None) -> str:
    cleaned = secret.upper().replace(" ", "").replace("-", "")
    pad = "=" * ((8 - len(cleaned) % 8) % 8)
    key = base64.b32decode(cleaned + pad, casefold=True)
    counter = int((for_time if for_time is not None else time.time()) // 30)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def parse_accounts() -> list[dict[str, str]]:
    raw = env("SKYCASTLE_ACCOUNTS")
    if raw:
        data = json.loads(raw)
        if isinstance(data, dict):
            data = [data]
        out = []
        for item in data:
            out.append(
                {
                    "email": str(item.get("email") or item.get("username") or "").strip(),
                    "password": str(item.get("password") or "").strip(),
                    "totp": str(item.get("totp") or item.get("totp_secret") or "").strip(),
                    "token": str(item.get("token") or item.get("remember_token") or "").strip(),
                    "plan_id": str(item.get("plan_id") or "").strip(),
                }
            )
        return [a for a in out if a["email"] or a["token"]]

    email = env("SKYCASTLE_EMAIL") or env("SKYCASTLE_USERNAME")
    password = env("SKYCASTLE_PASSWORD")
    totp_secret = env("SKYCASTLE_TOTP")
    token = env("SKYCASTLE_TOKEN") or env("SKYCASTLE_REMEMBER_TOKEN")
    plan_id = env("SKYCASTLE_PLAN_ID")
    if not email and not token:
        return []
    return [
        {
            "email": email,
            "password": password,
            "totp": totp_secret,
            "token": token,
            "plan_id": plan_id,
        }
    ]


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------

class ApiError(RuntimeError):
    def __init__(self, message: str, code: str = "", status: int = 0, payload: Any = None):
        super().__init__(message)
        self.code = code
        self.status = status
        self.payload = payload or {}


class PanelClient:
    def __init__(self, base: str, profile: str = "desktop", cache_dir: str = ".skycastle-cache"):
        self.base = base.rstrip("/")
        self.profile = profile
        self.cache_dir = cache_dir
        self.jar = CookieJar()
        ctx = ssl.create_default_context()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
        )
        self.last_user: dict[str, Any] = {}
        os.makedirs(cache_dir, exist_ok=True)

    @property
    def ua(self) -> str:
        return UA_MOBILE if self.profile == "mobile" else UA_DESKTOP

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {
            "User-Agent": self.ua,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": self.base,
            "Referer": f"{self.base}/dashboard",
            "X-Requested-With": "XMLHttpRequest",
        }
        if self.profile == "mobile":
            headers["Sec-CH-UA-Mobile"] = "?1"
            headers["Sec-CH-UA-Platform"] = '"Android"'
            headers["X-Client"] = "featherpanel-mobile"
        else:
            headers["Sec-CH-UA-Mobile"] = "?0"
            headers["Sec-CH-UA-Platform"] = '"Windows"'
        if extra:
            headers.update(extra)
        return headers

    def set_remember_token(self, token: str) -> None:
        token = token.strip()
        if not token:
            return
        from http.cookiejar import Cookie

        cookie = Cookie(
            version=0,
            name="remember_token",
            value=token,
            port=None,
            port_specified=False,
            domain=urllib.parse.urlparse(self.base).hostname or "panel.skycastle.us",
            domain_specified=True,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=True,
            expires=int(time.time()) + 60 * 60 * 24 * 30,
            discard=False,
            comment=None,
            comment_url=None,
            rest={"HttpOnly": None},
            rfc2109=False,
        )
        self.jar.set_cookie(cookie)

    def get_remember_token(self) -> str:
        for c in self.jar:
            if c.name == "remember_token" and c.value:
                return c.value
        return ""

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        timeout: int = 45,
        retries: int = 4,
    ) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{self.base}{path}"
        data = None if body is None else json.dumps(body).encode("utf-8")
        last_err: Exception | None = None
        for attempt in range(1, retries + 1):
            req = urllib.request.Request(url, data=data, method=method.upper(), headers=self._headers())
            try:
                with self.opener.open(req, timeout=timeout) as resp:
                    raw = resp.read().decode("utf-8", "replace")
                    if not raw:
                        return {"success": True, "data": None, "status": resp.status}
                    try:
                        payload = json.loads(raw)
                    except json.JSONDecodeError:
                        return {"success": True, "data": raw, "status": resp.status, "raw": True}
                    if isinstance(payload, dict):
                        payload.setdefault("status", resp.status)
                    return payload
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", "replace")
                try:
                    payload = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    payload = {"message": raw}
                code = str(payload.get("error_code") or payload.get("code") or "")
                msg = str(
                    payload.get("message")
                    or payload.get("error_message")
                    or exc.reason
                    or f"HTTP {exc.code}"
                )
                if exc.code in (429, 502, 503, 504) and attempt < retries:
                    wait = min(30, 4 * attempt)
                    if exc.code == 429:
                        wait = max(wait, WORK_MIN_INTERVAL)
                    log(f"{method} {path} → {exc.code}, retry in {wait}s ({code or msg})", "warn")
                    time.sleep(wait)
                    last_err = ApiError(msg, code, exc.code, payload)
                    continue
                raise ApiError(msg, code, exc.code, payload) from exc
            except (urllib.error.URLError, TimeoutError, ssl.SSLError) as exc:
                last_err = exc
                wait = min(20, 3 * attempt)
                log(f"{method} {path} network error: {exc}; retry in {wait}s", "warn")
                time.sleep(wait)
        raise ApiError(f"request failed after retries: {last_err}", "NETWORK", 0)

    def save_cache(self, key: str) -> None:
        token = self.get_remember_token()
        path = os.path.join(self.cache_dir, f"{key}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"remember_token": token, "saved_at": int(time.time())}, fh)

    def load_cache(self, key: str) -> str:
        path = os.path.join(self.cache_dir, f"{key}.json")
        if not os.path.isfile(path):
            return ""
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            return str(data.get("remember_token") or "")
        except (OSError, json.JSONDecodeError):
            return ""


# ---------------------------------------------------------------------------
# captcha (optional Capsolver)
# ---------------------------------------------------------------------------

def solve_turnstile(site_key: str, page_url: str, api_key: str) -> str:
    def call(path: str, payload: dict[str, Any]) -> dict[str, Any]:
        raw = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"https://api.capsolver.com/{path}",
            data=raw,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read().decode())

    created = call(
        "createTask",
        {
            "clientKey": api_key,
            "task": {
                "type": "AntiTurnstileTaskProxyLess",
                "websiteURL": page_url,
                "websiteKey": site_key,
            },
        },
    )
    if created.get("errorId"):
        raise ApiError(created.get("errorDescription") or "capsolver create failed", "CAPTCHA")
    task_id = created.get("taskId")
    for _ in range(24):
        time.sleep(3)
        polled = call("getTaskResult", {"clientKey": api_key, "taskId": task_id})
        if polled.get("status") == "ready":
            sol = polled.get("solution") or {}
            token = sol.get("token") or sol.get("gRecaptchaResponse") or ""
            if token:
                return token
        if polled.get("errorId"):
            raise ApiError(polled.get("errorDescription") or "capsolver error", "CAPTCHA")
    raise ApiError("capsolver timed out", "CAPTCHA")


def public_turnstile_key(client: PanelClient) -> str:
    # FeatherPanel exposes captcha site key on AFK status when enabled; login page
    # does not. Try a few public endpoints, otherwise env SKYCASTLE_TURNSTILE_SITEKEY.
    key = env("SKYCASTLE_TURNSTILE_SITEKEY")
    if key:
        return key
    for path in ("/api/settings", "/api/system/settings"):
        try:
            payload = client.request("GET", path, retries=1)
            data = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data, dict):
                for k in ("turnstile_key_pub", "TURNSTILE_KEY_PUB", "site_key"):
                    if data.get(k):
                        return str(data[k])
        except ApiError:
            continue
    return ""


# ---------------------------------------------------------------------------
# auth / session
# ---------------------------------------------------------------------------

def login(client: PanelClient, account: dict[str, str]) -> dict[str, Any]:
    cache_key = (account.get("email") or "token").replace("@", "_at_")
    token = account.get("token") or client.load_cache(cache_key)
    if token:
        client.set_remember_token(token)
        try:
            session = get_session(client)
            log(f"cookie login ok · {session.get('username') or session.get('email') or 'user'}", "ok")
            client.last_user = session
            client.save_cache(cache_key)
            return session
        except ApiError as exc:
            log(f"cached token rejected ({exc.code or exc}); falling back to password", "warn")

    email = account.get("email") or ""
    password = account.get("password") or ""
    if not email or not password:
        raise ApiError(
            "Need SKYCASTLE_EMAIL + SKYCASTLE_PASSWORD, or SKYCASTLE_TOKEN (remember_token cookie)",
            "NO_CREDENTIALS",
        )
    if len(password) < 8:
        raise ApiError("Password must be at least 8 characters (panel rule)", "INVALID_DATA_LENGTH")

    body: dict[str, Any] = {"username_or_email": email, "password": password}

    capsolver = env("CAPSOLVER_KEY")
    if capsolver:
        site_key = public_turnstile_key(client)
        if site_key:
            try:
                body["turnstile_token"] = solve_turnstile(site_key, f"{client.base}/auth/login", capsolver)
                log("Turnstile solved via Capsolver", "ok")
            except ApiError as exc:
                log(f"captcha solve skipped: {exc}", "warn")

    try:
        payload = client.request("PUT", "/api/user/auth/login", body)
    except ApiError as exc:
        if exc.code == "CAPTCHA_TOKEN_REQUIRED" and capsolver:
            site_key = public_turnstile_key(client) or env("SKYCASTLE_TURNSTILE_SITEKEY")
            if not site_key:
                raise ApiError(
                    "Panel requires Turnstile. Set SKYCASTLE_TOKEN (remember_token) "
                    "or SKYCASTLE_TURNSTILE_SITEKEY + CAPSOLVER_KEY",
                    "CAPTCHA_TOKEN_REQUIRED",
                    400,
                ) from exc
            body["turnstile_token"] = solve_turnstile(site_key, f"{client.base}/auth/login", capsolver)
            payload = client.request("PUT", "/api/user/auth/login", body)
        elif exc.code == "TWO_FACTOR_REQUIRED":
            payload = {"error_code": "TWO_FACTOR_REQUIRED", "data": exc.payload.get("data") or {"email": email}}
        else:
            raise

    code = str(payload.get("error_code") or "")
    if code == "TWO_FACTOR_REQUIRED" or (not payload.get("success") and "2FA" in str(payload.get("message", "")).upper()):
        if not account.get("totp"):
            raise ApiError("2FA required — set SKYCASTLE_TOTP (base32 secret)", "TWO_FACTOR_REQUIRED", 401)
        two_email = email if "@" in email else str((payload.get("data") or {}).get("email") or email)
        payload = client.request(
            "POST",
            "/api/user/auth/two-factor",
            {"email": two_email, "code": totp(account["totp"])},
        )

    if not payload.get("success"):
        raise ApiError(str(payload.get("message") or "login failed"), str(payload.get("error_code") or ""), 401, payload)

    data = payload.get("data") or {}
    user = data.get("user") if isinstance(data, dict) else {}
    if not isinstance(user, dict):
        user = {}
    token = client.get_remember_token()
    if not token and isinstance(user.get("remember_token"), str):
        client.set_remember_token(user["remember_token"])
        token = user["remember_token"]
    client.save_cache(cache_key)
    client.last_user = user
    log(f"password login ok · {user.get('username') or user.get('email') or email}", "ok")
    if token:
        log("remember_token captured — cache it as SKYCASTLE_TOKEN to skip captcha next time", "info")
    return user


def get_session(client: PanelClient) -> dict[str, Any]:
    payload = client.request("GET", "/api/user/session")
    if not payload.get("success"):
        raise ApiError(str(payload.get("message") or "session invalid"), str(payload.get("error_code") or ""), 400, payload)
    data = payload.get("data") or payload
    if isinstance(data, dict) and isinstance(data.get("user"), dict):
        return data["user"]
    return data if isinstance(data, dict) else {}


# ---------------------------------------------------------------------------
# AFK / mobile credits
# ---------------------------------------------------------------------------

def afk_status(client: PanelClient) -> dict[str, Any]:
    payload = client.request("GET", "/api/user/billingafk/status")
    if not payload.get("success"):
        raise ApiError(str(payload.get("message") or "afk status failed"), str(payload.get("error_code") or ""), 0, payload)
    return payload.get("data") or {}


def afk_work(client: PanelClient) -> dict[str, Any]:
    payload = client.request("POST", "/api/user/billingafk/work", {"minutes_afk": 1}, retries=2)
    if not payload.get("success"):
        raise ApiError(str(payload.get("message") or "work failed"), str(payload.get("error_code") or ""), 0, payload)
    return payload.get("data") or {}


def run_afk(client: PanelClient, minutes: int, profile: str) -> dict[str, Any]:
    client.profile = profile
    status = afk_status(client)
    if status.get("is_enabled") is False:
        raise ApiError("AFK rewards are disabled on this panel", "AFK_DISABLED")
    credits0 = int(status.get("user_credits") or 0)
    cpm = status.get("credits_per_minute") or 0
    log(
        f"AFK[{profile}] start · credits={credits0} · per_min={cpm or 1} · "
        f"today={((status.get('daily_usage') or {}).get('credits_earned_today'))}",
        "afk",
    )
    try:
        client.request("POST", "/api/user/billingafk/start", {}, retries=1)
    except ApiError:
        pass  # start is a no-op on BillingAFK 2.x

    awarded_total = 0
    ticks = max(1, minutes)
    for i in range(1, ticks + 1):
        started = time.time()
        try:
            result = afk_work(client)
        except ApiError as exc:
            if exc.code == "RATE_LIMIT_EXCEEDED" or exc.status == 429:
                log("rate limited — sleeping 65s", "warn")
                time.sleep(65)
                continue
            if exc.code == "AFK_DISABLED":
                raise
            log(f"work error: {exc} ({exc.code})", "warn")
            time.sleep(WORK_MIN_INTERVAL)
            continue
        got = int(result.get("credits_awarded") or 0)
        awarded_total += got
        total = result.get("total_credits")
        log(
            f"AFK[{profile}] {i}/{ticks} · +{got} · balance={total} · minutes={result.get('total_afk_time')}",
            "afk",
        )
        leftover = WORK_MIN_INTERVAL - (time.time() - started)
        if i < ticks and leftover > 0:
            time.sleep(leftover)

    try:
        client.request("POST", "/api/user/billingafk/stop", {}, retries=1)
    except ApiError:
        pass
    end = afk_status(client)
    credits1 = int(end.get("user_credits") or 0)
    summary = {
        "profile": profile,
        "minutes": ticks,
        "credits_before": credits0,
        "credits_after": credits1,
        "credits_awarded": awarded_total,
        "delta": credits1 - credits0,
    }
    log(
        f"AFK[{profile}] done · +{summary['delta']} credits · {credits0} → {credits1}",
        "ok",
    )
    return summary


# ---------------------------------------------------------------------------
# renewal
# ---------------------------------------------------------------------------

def get_credits(client: PanelClient) -> int:
    try:
        payload = client.request("GET", "/api/user/billingcore/credits")
        data = payload.get("data") if payload.get("success") else None
        if isinstance(data, dict):
            for k in ("credits", "balance", "amount", "user_credits"):
                if data.get(k) is not None:
                    return int(data[k])
        if isinstance(data, (int, float)):
            return int(data)
    except ApiError as exc:
        log(f"credits endpoint: {exc}", "warn")
    try:
        return int(afk_status(client).get("user_credits") or 0)
    except ApiError:
        return -1


def list_subscriptions(client: PanelClient) -> tuple[list[dict[str, Any]], int]:
    payload = client.request("GET", "/api/user/billingplans/subscriptions")
    data = payload.get("data") or {}
    subs = data.get("data") if isinstance(data, dict) else data
    if not isinstance(subs, list):
        subs = []
    credits = int(data.get("user_credits") or 0) if isinstance(data, dict) else 0
    return subs, credits


def list_plans(client: PanelClient) -> list[dict[str, Any]]:
    for path in ("/api/user/billingplans/plans", "/api/billingplans/plans"):
        try:
            payload = client.request("GET", path)
            data = payload.get("data") or payload
            if isinstance(data, dict) and isinstance(data.get("data"), list):
                return data["data"]
            if isinstance(data, list):
                return data
        except ApiError:
            continue
    return []


def subscribe(client: PanelClient, plan_id: int, coupon: str = "") -> dict[str, Any]:
    body: dict[str, Any] = {}
    if coupon:
        body["coupon_code"] = coupon
    payload = client.request("POST", f"/api/user/billingplans/plans/{plan_id}/subscribe", body)
    if not payload.get("success"):
        raise ApiError(str(payload.get("message") or "subscribe failed"), str(payload.get("error_code") or ""), 0, payload)
    return payload.get("data") or {}


def list_servers(client: PanelClient) -> list[dict[str, Any]]:
    for path in ("/api/user/servers", "/api/client/servers"):
        try:
            payload = client.request("GET", path)
            data = payload.get("data") or payload
            if isinstance(data, dict):
                if isinstance(data.get("data"), list):
                    return data["data"]
                if isinstance(data.get("servers"), list):
                    return data["servers"]
            if isinstance(data, list):
                return data
        except ApiError as exc:
            log(f"{path}: {exc}", "warn")
    return []


def start_server(client: PanelClient, ident: str) -> None:
    for path in (
        f"/api/user/servers/{ident}/power/start",
        f"/api/client/servers/{ident}/power",
    ):
        try:
            body = {"signal": "start"} if path.endswith("/power") else None
            client.request("POST", path, body)
            log(f"power start → {ident}", "ok")
            return
        except ApiError as exc:
            log(f"start {ident} via {path}: {exc}", "warn")


def sub_active(sub: dict[str, Any]) -> bool:
    status = str(sub.get("status") or "").lower()
    return status in {"active", "grace", "trialing", "trial"} or status == "1"


def run_renew(client: PanelClient, account: dict[str, str]) -> dict[str, Any]:
    credits = get_credits(client)
    log(f"credits balance = {credits}", "info")
    report: dict[str, Any] = {"credits": credits, "subscriptions": [], "servers": [], "actions": []}

    try:
        subs, sub_credits = list_subscriptions(client)
        if sub_credits:
            credits = sub_credits
            report["credits"] = credits
        if not subs:
            log("no billing plan subscriptions on this account", "warn")
        for sub in subs:
            name = sub.get("plan_name") or sub.get("name") or f"plan#{sub.get('plan_id')}"
            status = sub.get("status")
            nxt = sub.get("next_renewal_at") or sub.get("expires_at")
            cost = sub.get("total_credits") or sub.get("price_credits") or sub.get("credits")
            row = {"name": name, "status": status, "next_renewal_at": nxt, "cost": cost, "id": sub.get("id")}
            report["subscriptions"].append(row)
            log(f"sub {name} · status={status} · next={nxt} · cost={cost}", "info")
            if not sub_active(sub) and account.get("plan_id"):
                try:
                    subscribe(client, int(account["plan_id"]), env("SKYCASTLE_COUPON"))
                    report["actions"].append(f"resubscribed plan {account['plan_id']}")
                    log(f"re-subscribed plan {account['plan_id']}", "ok")
                except ApiError as exc:
                    report["actions"].append(f"resubscribe failed: {exc}")
                    log(f"resubscribe failed: {exc}", "err")
            elif not sub_active(sub) and sub.get("plan_id"):
                try:
                    subscribe(client, int(sub["plan_id"]), env("SKYCASTLE_COUPON"))
                    report["actions"].append(f"resubscribed plan {sub['plan_id']}")
                    log(f"re-subscribed previous plan {sub['plan_id']}", "ok")
                except ApiError as exc:
                    report["actions"].append(f"resubscribe failed: {exc}")
                    log(f"resubscribe failed: {exc} — farm more AFK credits", "warn")
    except ApiError as exc:
        log(f"subscriptions: {exc} ({exc.code})", "warn")
        report["actions"].append(f"subscriptions error: {exc}")

    if account.get("plan_id") and not report["subscriptions"]:
        try:
            subscribe(client, int(account["plan_id"]), env("SKYCASTLE_COUPON"))
            report["actions"].append(f"subscribed plan {account['plan_id']}")
            log(f"subscribed plan {account['plan_id']}", "ok")
        except ApiError as exc:
            report["actions"].append(f"subscribe failed: {exc}")
            log(f"subscribe failed: {exc}", "err")

    if env("SKYCASTLE_START_SERVERS", "1") not in {"0", "false", "no"}:
        servers = list_servers(client)
        if not servers:
            log("no servers returned (ok if account is empty)", "info")
        for srv in servers:
            ident = str(
                srv.get("uuidShort")
                or srv.get("uuid_short")
                or srv.get("identifier")
                or srv.get("uuid")
                or srv.get("id")
                or ""
            )
            name = srv.get("name") or ident
            state = str(
                srv.get("status")
                or (srv.get("state") if not isinstance(srv.get("state"), dict) else "")
                or ((srv.get("attributes") or {}).get("status") if isinstance(srv.get("attributes"), dict) else "")
                or ""
            ).lower()
            report["servers"].append({"name": name, "id": ident, "state": state})
            log(f"server {name} · {ident} · {state or 'unknown'}", "info")
            if ident and state in {"offline", "stopped", "stopping", "exited", "installing", "suspended", ""}:
                start_server(client, ident)
                report["actions"].append(f"start {name}")
    return report


# ---------------------------------------------------------------------------
# notify
# ---------------------------------------------------------------------------

def notify(text: str) -> None:
    token = env("TELEGRAM_BOT_TOKEN") or env("TELEGRAM_TOKEN")
    chat = env("TELEGRAM_CHAT_ID") or env("TELEGRAM_CHAT")
    if token and chat:
        body = urllib.parse.urlencode(
            {"chat_id": chat, "text": text[:3900], "disable_web_page_preview": "true"}
        ).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=body,
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=20).read()
        except Exception as exc:  # noqa: BLE001
            log(f"telegram notify failed: {exc}", "warn")
    hook = env("DISCORD_WEBHOOK")
    if hook:
        raw = json.dumps({"content": text[:1900]}).encode()
        req = urllib.request.Request(
            hook, data=raw, method="POST", headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(req, timeout=20).read()
        except Exception as exc:  # noqa: BLE001
            log(f"discord notify failed: {exc}", "warn")


# ---------------------------------------------------------------------------
# account pipeline
# ---------------------------------------------------------------------------

def run_account(account: dict[str, str], mode: str, minutes: int, panel: str, cache_dir: str) -> dict[str, Any]:
    who = account.get("email") or "token-account"
    log(f"===== {who} · mode={mode} · panel={panel} =====")
    client = PanelClient(panel, profile="desktop" if mode != "mobile" else "mobile", cache_dir=cache_dir)
    login(client, account)
    summary: dict[str, Any] = {"account": who, "mode": mode}

    if mode in {"all", "renew", "status"}:
        summary["renew"] = run_renew(client, account)

    if mode in {"all", "afk"}:
        afk_min = minutes if mode == "afk" else max(1, minutes // 2) if mode == "all" else minutes
        summary["afk"] = run_afk(client, afk_min, "desktop")

    if mode in {"all", "mobile"}:
        mob_min = minutes if mode == "mobile" else max(1, minutes - minutes // 2) if mode == "all" else minutes
        # Sequential: BillingAFK last_seen is per-user, concurrent desktop+mobile 429s.
        summary["mobile"] = run_afk(client, mob_min, "mobile")

    if mode == "status":
        st = afk_status(client)
        summary["afk_status"] = {
            "credits": st.get("user_credits"),
            "minutes_afk": st.get("minutes_afk"),
            "credits_per_minute": st.get("credits_per_minute"),
            "daily_usage": st.get("daily_usage"),
        }
        log(json.dumps(summary["afk_status"], ensure_ascii=False), "info")

    return summary


def format_report(results: list[dict[str, Any]]) -> str:
    lines = ["CastleKeep · SkyCastle 续期报告", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), ""]
    for item in results:
        lines.append(f"账号 {item.get('account')}  mode={item.get('mode')}")
        renew = item.get("renew") or {}
        if renew:
            lines.append(f"  Credits: {renew.get('credits')}")
            for sub in renew.get("subscriptions") or []:
                lines.append(f"  套餐 {sub.get('name')}  {sub.get('status')}  next={sub.get('next_renewal_at')}")
            for srv in renew.get("servers") or []:
                lines.append(f"  服务器 {srv.get('name')}  {srv.get('state')}")
            for act in renew.get("actions") or []:
                lines.append(f"  动作: {act}")
        for key in ("afk", "mobile"):
            block = item.get(key)
            if block:
                lines.append(
                    f"  {key}: +{block.get('delta')} credits  "
                    f"{block.get('credits_before')}→{block.get('credits_after')}  "
                    f"{block.get('minutes')} min"
                )
        if item.get("error"):
            lines.append(f"  ERROR: {item['error']}")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SkyCastle auto-renew + AFK credits")
    parser.add_argument(
        "command",
        nargs="?",
        default=env("SKYCASTLE_MODE") or "all",
        choices=["all", "login", "status", "afk", "mobile", "renew", "run"],
    )
    parser.add_argument("--minutes", type=int, default=int(env("SKYCASTLE_AFK_MINUTES") or "240"))
    parser.add_argument("--panel", default=env("SKYCASTLE_PANEL") or PANEL_DEFAULT)
    parser.add_argument("--cache", default=env("SKYCASTLE_CACHE_DIR") or ".skycastle-cache")
    args = parser.parse_args(argv)

    mode = "all" if args.command == "run" else args.command
    accounts = parse_accounts()
    if not accounts:
        log(
            "Missing credentials. Set SKYCASTLE_EMAIL + SKYCASTLE_PASSWORD "
            "(and optional SKYCASTLE_TOTP / SKYCASTLE_TOKEN), or SKYCASTLE_ACCOUNTS JSON.",
            "err",
        )
        return 2

    # GitHub Actions jobs max out at 6h. Keep a safety margin.
    max_minutes = int(env("SKYCASTLE_MAX_MINUTES") or "330")
    minutes = max(1, min(args.minutes, max_minutes))

    results: list[dict[str, Any]] = []
    failed = 0
    for account in accounts:
        try:
            if mode == "login":
                client = PanelClient(args.panel, cache_dir=args.cache)
                login(client, account)
                results.append({"account": account.get("email") or "token", "mode": "login"})
            else:
                results.append(run_account(account, mode, minutes, args.panel, args.cache))
        except ApiError as exc:
            failed += 1
            log(f"{account.get('email')}: {exc} [{exc.code}]", "err")
            results.append({"account": account.get("email"), "error": f"{exc} [{exc.code}]"})
        except Exception as exc:  # noqa: BLE001
            failed += 1
            log(f"{account.get('email')}: {exc}", "err")
            results.append({"account": account.get("email"), "error": str(exc)})

    report = format_report(results)
    print("\n" + report, flush=True)
    notify(report)
    out = os.path.join(args.cache, "last-report.json")
    os.makedirs(args.cache, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=False, indent=2)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
