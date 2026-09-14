#!/usr/bin/env python3
"""SkyCastle (FeatherPanel) auto-renew + AFK credits farmer.

Designed to run on GitHub Actions. Stdlib only.
Default AFK is limited to 10 ticks to keep runs short.

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


def server_ident(srv: dict[str, Any]) -> str:
    return str(
        srv.get("uuidShort")
        or srv.get("uuid_short")
        or srv.get("identifier")
        or srv.get("uuid")
        or srv.get("id")
        or ""
    )


def server_name(srv: dict[str, Any]) -> str:
    return str(srv.get("name") or server_ident(srv) or "?")


def server_state(srv: dict[str, Any]) -> str:
    return str(
        srv.get("status")
        or (srv.get("state") if not isinstance(srv.get("state"), dict) else "")
        or ((srv.get("attributes") or {}).get("status") if isinstance(srv.get("attributes"), dict) else "")
        or ""
    ).lower()


def server_renewal_info(srv: dict[str, Any]) -> dict[str, Any]:
    """Extract RENEWAL card fields shown on dashboard/servers."""
    candidates = [
        srv,
        srv.get("renewal") if isinstance(srv.get("renewal"), dict) else None,
        srv.get("billing") if isinstance(srv.get("billing"), dict) else None,
        srv.get("attributes") if isinstance(srv.get("attributes"), dict) else None,
        (srv.get("attributes") or {}).get("renewal")
        if isinstance((srv.get("attributes") or {}).get("renewal"), dict)
        else None,
    ]
    due = None
    cost = None
    period = None
    for obj in candidates:
        if not isinstance(obj, dict):
            continue
        for k in (
            "renewal_due_at",
            "due_at",
            "expires_at",
            "next_renewal_at",
            "renewal_date",
            "due",
            "renews_at",
        ):
            if obj.get(k) is not None and due is None:
                due = obj.get(k)
        for k in (
            "renewal_cost",
            "renew_cost",
            "renewal_credits",
            "renew_credits",
            "price_credits",
            "credits",
        ):
            if obj.get(k) is not None and cost is None:
                cost = obj.get(k)
        for k in ("renewal_period", "period", "billing_period", "in"):
            if obj.get(k) is not None and period is None:
                period = obj.get(k)
    return {"due": due, "cost": cost, "period": period}


def power_server(client: PanelClient, ident: str, action: str) -> bool:
    """action: start | stop | restart"""
    action = action.lower().strip()
    paths_bodies: list[tuple[str, Any]] = [
        (f"/api/user/servers/{ident}/power/{action}", None),
        (f"/api/user/servers/{ident}/power", {"signal": action}),
        (f"/api/client/servers/{ident}/power/{action}", None),
        (f"/api/client/servers/{ident}/power", {"signal": action}),
    ]
    for path, body in paths_bodies:
        try:
            client.request("POST", path, body, retries=2)
            log(f"power {action} → {ident}", "ok")
            return True
        except ApiError as exc:
            log(f"power {action} {ident} via {path}: {exc}", "warn")
    return False


def start_server(client: PanelClient, ident: str) -> bool:
    return power_server(client, ident, "start")


def stop_server(client: PanelClient, ident: str) -> bool:
    return power_server(client, ident, "stop")


def restart_server(client: PanelClient, ident: str) -> bool:
    # Prefer dedicated restart; fallback stop → wait → start
    if power_server(client, ident, "restart"):
        return True
    log(f"restart fallback: stop→start for {ident}", "warn")
    ok_stop = stop_server(client, ident)
    time.sleep(3)
    ok_start = start_server(client, ident)
    return ok_stop and ok_start


def renew_server(client: PanelClient, ident: str) -> dict[str, Any]:
    """Click the server RENEWAL button (costs credits, extends due date).

    UI shows: RENEWAL · Due · N credits · in Xh
    Probe common FeatherPanel / SkyCastle endpoints.
    """
    paths_bodies: list[tuple[str, Any]] = [
        (f"/api/user/servers/{ident}/renew", {}),
        (f"/api/user/servers/{ident}/renewal", {}),
        (f"/api/user/servers/{ident}/billing/renew", {}),
        (f"/api/client/servers/{ident}/renew", {}),
        (f"/api/client/servers/{ident}/renewal", {}),
        (f"/api/user/servers/{ident}/extend", {}),
        (f"/api/user/billing/servers/{ident}/renew", {}),
    ]
    last_err: Exception | None = None
    for path, body in paths_bodies:
        try:
            payload = client.request("POST", path, body, retries=1)
            log(f"server renew → {ident} via {path}", "ok")
            data = payload.get("data") if isinstance(payload, dict) else payload
            return {"ok": True, "path": path, "data": data if isinstance(data, dict) else payload}
        except ApiError as exc:
            last_err = exc
            # 404/405 = wrong path; keep probing. Other errors may be real (insufficient credits).
            if exc.status in (404, 405, 501) or exc.code in {"NOT_FOUND", "METHOD_NOT_ALLOWED"}:
                log(f"renew probe {path}: {exc.status or exc.code}", "info")
                continue
            log(f"renew {ident} via {path}: {exc} [{exc.code}]", "warn")
            # Insufficient credits etc. — stop probing
            if exc.status in (400, 402, 403) or "credit" in str(exc).lower():
                return {"ok": False, "path": path, "error": str(exc), "code": exc.code}
            continue
    return {
        "ok": False,
        "path": None,
        "error": str(last_err) if last_err else "no renew endpoint matched",
        "code": getattr(last_err, "code", "") if last_err else "NO_ENDPOINT",
    }


def sub_active(sub: dict[str, Any]) -> bool:
    status = str(sub.get("status") or "").lower()
    return status in {"active", "grace", "trialing", "trial"} or status == "1"


def run_renew(client: PanelClient, account: dict[str, str]) -> dict[str, Any]:
    """Server-card RENEWAL (manual 1-credit style) + optional restart/start.

    Dashboard shows per-server:
      RENEWAL · Due 9月17日 · 1 credits · in 36h
    That is NOT BillingPlans auto-cron — must POST renew on the server.
    """
    credits_before = get_credits(client)
    log(f"credits balance = {credits_before}", "info")
    report: dict[str, Any] = {
        "credits_before": credits_before,
        "credits": credits_before,
        "credits_after": credits_before,
        "subscriptions": [],
        "plans": [],
        "servers": [],
        "renewals": [],
        "restarts": [],
        "actions": [],
    }

    # Optional: still surface BillingPlans info (not the primary renew path)
    try:
        subs, sub_credits = list_subscriptions(client)
        if sub_credits:
            report["credits"] = sub_credits
            credits_before = sub_credits
            report["credits_before"] = credits_before
        for sub in subs:
            name = sub.get("plan_name") or sub.get("name") or f"plan#{sub.get('plan_id')}"
            status = sub.get("status")
            nxt = sub.get("next_renewal_at") or sub.get("expires_at")
            cost = sub.get("total_credits") or sub.get("price_credits") or sub.get("credits")
            row = {
                "name": name,
                "status": status,
                "next_renewal_at": nxt,
                "cost": cost,
                "id": sub.get("id"),
                "plan_id": sub.get("plan_id"),
            }
            report["subscriptions"].append(row)
            log(f"sub {name} · status={status} · next={nxt} · cost={cost}", "info")
    except ApiError as exc:
        log(f"subscriptions: {exc} ({exc.code})", "warn")

    do_renew = env("SKYCASTLE_SERVER_RENEW", "1") not in {"0", "false", "no"}
    do_restart = env("SKYCASTLE_RESTART_SERVERS", "1") not in {"0", "false", "no"}
    do_start = env("SKYCASTLE_START_SERVERS", "1") not in {"0", "false", "no"}

    servers = list_servers(client)
    if not servers:
        log("no servers returned (ok if account is empty)", "info")

    for srv in servers:
        ident = server_ident(srv)
        name = server_name(srv)
        state = server_state(srv)
        ren_info = server_renewal_info(srv)
        row: dict[str, Any] = {
            "name": name,
            "id": ident,
            "state_before": state,
            "state_after": state,
            "renewal_due_before": ren_info.get("due"),
            "renewal_due_after": ren_info.get("due"),
            "renewal_cost": ren_info.get("cost"),
            "renewed": False,
            "restarted": False,
            "started": False,
            "errors": [],
        }
        log(
            f"server {name} · {ident} · state={state or 'unknown'} · "
            f"due={ren_info.get('due')} · cost={ren_info.get('cost')}",
            "info",
        )

        # 1) 服务器卡片「续期」按钮
        if do_renew and ident:
            result = renew_server(client, ident)
            if result.get("ok"):
                row["renewed"] = True
                report["actions"].append(f"renew {name} ok via {result.get('path')}")
                log(f"✓ 续期完成 {name}", "ok")
                data = result.get("data") or {}
                if isinstance(data, dict):
                    for k in ("due_at", "expires_at", "next_renewal_at", "renewal_due_at", "due"):
                        if data.get(k) is not None:
                            row["renewal_due_after"] = data.get(k)
                            break
                report["renewals"].append(
                    {
                        "name": name,
                        "id": ident,
                        "ok": True,
                        "path": result.get("path"),
                        "due_before": row["renewal_due_before"],
                        "due_after": row["renewal_due_after"],
                        "cost": row["renewal_cost"],
                    }
                )
            else:
                err = result.get("error") or "renew failed"
                row["errors"].append(f"renew: {err}")
                report["actions"].append(f"renew {name} failed: {err}")
                report["renewals"].append(
                    {
                        "name": name,
                        "id": ident,
                        "ok": False,
                        "error": err,
                        "code": result.get("code"),
                        "due_before": row["renewal_due_before"],
                        "cost": row["renewal_cost"],
                    }
                )
                log(f"✗ 续期失败 {name}: {err}", "err")

        # 2) 关机再重启（用户要求：关机 + 点击重启）
        if do_restart and ident:
            ok = restart_server(client, ident)
            row["restarted"] = ok
            if ok:
                report["actions"].append(f"restart {name} ok")
                report["restarts"].append({"name": name, "id": ident, "ok": True})
                log(f"✓ 重启完成 {name}", "ok")
                # 等几秒再读状态
                time.sleep(2)
            else:
                row["errors"].append("restart failed")
                report["actions"].append(f"restart {name} failed")
                report["restarts"].append({"name": name, "id": ident, "ok": False})
                log(f"✗ 重启失败 {name}", "err")
        elif do_start and ident and state in {
            "offline",
            "stopped",
            "stopping",
            "exited",
            "installing",
            "suspended",
            "",
        }:
            ok = start_server(client, ident)
            row["started"] = ok
            if ok:
                report["actions"].append(f"start {name}")
                log(f"✓ 开机 {name}", "ok")
            else:
                row["errors"].append("start failed")
                report["actions"].append(f"start {name} failed")

        report["servers"].append(row)

    # 刷新 credits + 服务器状态（续期/重启后的准确反馈）
    try:
        credits_after = get_credits(client)
        report["credits_after"] = credits_after
        report["credits"] = credits_after
        log(f"credits after = {credits_after} (was {credits_before})", "info")
    except Exception as exc:  # noqa: BLE001
        log(f"credits refresh: {exc}", "warn")

    try:
        refreshed = {server_ident(s): s for s in list_servers(client)}
        for row in report["servers"]:
            s2 = refreshed.get(row["id"])
            if not s2:
                continue
            row["state_after"] = server_state(s2)
            ren2 = server_renewal_info(s2)
            if ren2.get("due") is not None:
                row["renewal_due_after"] = ren2.get("due")
            # sync into renewals list
            for r in report["renewals"]:
                if r.get("id") == row["id"] and row.get("renewal_due_after") is not None:
                    r["due_after"] = row["renewal_due_after"]
    except Exception as exc:  # noqa: BLE001
        log(f"server refresh: {exc}", "warn")

    return report


# ---------------------------------------------------------------------------
# notify + status card (screenshot-style summary)
# ---------------------------------------------------------------------------

def _html_escape(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def format_report(results: list[dict[str, Any]]) -> str:
    """Plain-text report for logs / Discord."""
    lines = ["CastleKeep · SkyCastle 续期报告", time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()), ""]
    for item in results:
        lines.append(f"账号 {item.get('account')}  mode={item.get('mode')}")
        renew = item.get("renew") or {}
        if renew:
            cb = renew.get("credits_before", renew.get("credits"))
            ca = renew.get("credits_after", renew.get("credits"))
            lines.append(f"  Credits: {cb} → {ca}")
            for r in renew.get("renewals") or []:
                if r.get("ok"):
                    lines.append(
                        f"  ✅ 续期 {r.get('name')}: due {r.get('due_before')} → {r.get('due_after')} "
                        f"(cost={r.get('cost')})"
                    )
                else:
                    lines.append(f"  ❌ 续期 {r.get('name')}: {r.get('error')}")
            for r in renew.get("restarts") or []:
                mark = "✅" if r.get("ok") else "❌"
                lines.append(f"  {mark} 重启 {r.get('name')}")
            for srv in renew.get("servers") or []:
                lines.append(
                    f"  服务器 {srv.get('name')}  "
                    f"{srv.get('state_before')}→{srv.get('state_after')}  "
                    f"due {srv.get('renewal_due_before')}→{srv.get('renewal_due_after')}"
                )
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


def format_report_html(results: list[dict[str, Any]]) -> str:
    """Telegram HTML status card — accurate renew/restart screenshot feedback."""
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    parts = [
        "<b>🏰 CastleKeep · SkyCastle</b>",
        f"<code>{_html_escape(ts)}</code>",
        "",
    ]
    for item in results:
        acc = _html_escape(str(item.get("account") or "?"))
        mode = _html_escape(str(item.get("mode") or ""))
        parts.append(f"<b>账号</b> <code>{acc}</code> · <i>{mode}</i>")
        if item.get("error"):
            parts.append(f"❌ <b>ERROR</b> {_html_escape(item['error'])}")
            parts.append("")
            continue
        renew = item.get("renew") or {}
        if renew:
            cb = renew.get("credits_before", renew.get("credits"))
            ca = renew.get("credits_after", renew.get("credits"))
            parts.append(f"💰 Credits: <b>{cb}</b> → <b>{ca}</b>")

            renewals = renew.get("renewals") or []
            if renewals:
                parts.append("<b>📅 续期结果</b>")
                for r in renewals:
                    name = _html_escape(str(r.get("name") or "?"))
                    if r.get("ok"):
                        parts.append(
                            f"✅ <b>{name}</b> 续期成功\n"
                            f"   Due: <code>{_html_escape(str(r.get('due_before') or '-'))}</code>"
                            f" → <code>{_html_escape(str(r.get('due_after') or '-'))}</code>\n"
                            f"   花费: <code>{_html_escape(str(r.get('cost') or '?'))}</code> credits"
                        )
                    else:
                        parts.append(
                            f"❌ <b>{name}</b> 续期失败\n"
                            f"   {_html_escape(str(r.get('error') or 'unknown'))}"
                        )

            restarts = renew.get("restarts") or []
            if restarts:
                parts.append("<b>🔄 重启结果</b>")
                for r in restarts:
                    name = _html_escape(str(r.get("name") or "?"))
                    if r.get("ok"):
                        # find state after from servers list
                        st_after = "?"
                        for srv in renew.get("servers") or []:
                            if srv.get("id") == r.get("id") or srv.get("name") == r.get("name"):
                                st_after = srv.get("state_after") or srv.get("state_before") or "?"
                                break
                        parts.append(
                            f"✅ <b>{name}</b> 重启完成 · 状态 <code>{_html_escape(str(st_after))}</code>"
                        )
                    else:
                        parts.append(f"❌ <b>{name}</b> 重启失败")

            for srv in renew.get("servers") or []:
                name = _html_escape(str(srv.get("name") or "?"))
                sb = _html_escape(str(srv.get("state_before") or "?"))
                sa = _html_escape(str(srv.get("state_after") or "?"))
                icon = "🟢" if str(srv.get("state_after") or "").lower() in {
                    "running",
                    "online",
                    "started",
                    "starting",
                } else "🟡"
                parts.append(f"{icon} 服务器 <b>{name}</b> · <code>{sb}→{sa}</code>")
                if srv.get("renewal_due_before") or srv.get("renewal_due_after"):
                    parts.append(
                        f"   Due <code>{_html_escape(str(srv.get('renewal_due_before') or '-'))}</code>"
                        f" → <code>{_html_escape(str(srv.get('renewal_due_after') or '-'))}</code>"
                    )

        for key in ("afk", "mobile"):
            block = item.get(key)
            if block:
                delta = block.get("delta")
                before = block.get("credits_before")
                after = block.get("credits_after")
                mins = block.get("minutes")
                parts.append(
                    f"⏱ {key.upper()}: <b>+{delta}</b> credits "
                    f"(<code>{before}→{after}</code>) · {mins} min"
                )
        parts.append("")
    parts.append("<i>服务器续期 + 重启 + AFK 完成</i>")
    return "\n".join(parts)


def _tg_api(token: str, method: str, fields: dict[str, Any], files: dict[str, tuple[str, bytes]] | None = None) -> None:
    """Call Telegram Bot API. files = {field: (filename, content_bytes)}."""
    url = f"https://api.telegram.org/bot{token}/{method}"
    if not files:
        body = urllib.parse.urlencode({k: v for k, v in fields.items() if v is not None}).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        urllib.request.urlopen(req, timeout=30).read()
        return
    # multipart/form-data for photo/document
    boundary = f"----CastleKeep{int(time.time())}"
    chunks: list[bytes] = []
    for k, v in fields.items():
        if v is None:
            continue
        chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode())
    for name, (filename, content) in files.items():
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + content
            + b"\r\n"
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    data = b"".join(chunks)
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    urllib.request.urlopen(req, timeout=45).read()


def build_status_png(results: list[dict[str, Any]], width: int = 720, height: int = 360) -> bytes:
    """Minimal pure-stdlib status card PNG (solid bg + simple bars, no font needed).
    Acts as a visual 'screenshot' for Telegram. Text details go in the caption.
    """
    import zlib

    # Dark card background + accent bar
    bg = (22, 27, 34)  # near GitHub dark
    accent = (63, 185, 80)  # green success
    warn = (210, 153, 34)
    err = (248, 81, 73)
    muted = (48, 54, 61)

    pixels = bytearray()
    has_error = any(item.get("error") for item in results)
    top_color = err if has_error else accent

    for y in range(height):
        for x in range(width):
            if y < 8:
                r, g, b = top_color
            elif y < 10:
                r, g, b = muted
            else:
                r, g, b = bg
            # left accent strip
            if x < 6:
                r, g, b = top_color
            # bottom progress-style bar representing AFK delta
            if y > height - 14:
                r, g, b = muted
                total_delta = 0
                for item in results:
                    for key in ("afk", "mobile"):
                        block = item.get(key) or {}
                        total_delta += int(block.get("delta") or 0)
                # scale bar: each credit ~ 40px, capped
                bar_w = min(width - 20, max(0, total_delta) * 40 + 20)
                if 10 <= x < 10 + bar_w:
                    r, g, b = accent if not has_error else warn
            pixels.extend((r, g, b))

    # PNG encode (RGB, no filter sophistication)
    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + pixels[i : i + width * 3] for i in range(0, len(pixels), width * 3))
    compressed = zlib.compress(raw, 9)
    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", compressed)
    png += chunk(b"IEND", b"")
    return png


def notify(text: str, results: list[dict[str, Any]] | None = None, cache_dir: str = ".skycastle-cache") -> None:
    token = env("TELEGRAM_BOT_TOKEN") or env("TELEGRAM_TOKEN")
    chat = env("TELEGRAM_CHAT_ID") or env("TELEGRAM_CHAT")
    results = results or []

    if token and chat:
        html = format_report_html(results) if results else _html_escape(text)
        # 1) HTML 状态卡片
        try:
            _tg_api(
                token,
                "sendMessage",
                {
                    "chat_id": chat,
                    "text": html[:3900],
                    "parse_mode": "HTML",
                    "disable_web_page_preview": "true",
                },
            )
            log("telegram HTML status sent", "ok")
        except Exception as exc:  # noqa: BLE001
            log(f"telegram HTML notify failed: {exc}", "warn")
            # fallback plain
            try:
                _tg_api(
                    token,
                    "sendMessage",
                    {"chat_id": chat, "text": text[:3900], "disable_web_page_preview": "true"},
                )
            except Exception as exc2:  # noqa: BLE001
                log(f"telegram plain notify failed: {exc2}", "warn")

        # 2) 状态截图 (PNG 卡片) + caption
        if env("SKYCASTLE_TG_SCREENSHOT", "1") not in {"0", "false", "no"} and results:
            try:
                png = build_status_png(results)
                os.makedirs(cache_dir, exist_ok=True)
                png_path = os.path.join(cache_dir, "status-card.png")
                with open(png_path, "wb") as fh:
                    fh.write(png)
                caption = "CastleKeep status card"
                for item in results:
                    renew = item.get("renew") or {}
                    afk = item.get("afk") or {}
                    ren_ok = sum(1 for r in (renew.get("renewals") or []) if r.get("ok"))
                    ren_fail = sum(1 for r in (renew.get("renewals") or []) if not r.get("ok"))
                    rst_ok = sum(1 for r in (renew.get("restarts") or []) if r.get("ok"))
                    caption = (
                        f"Credits {renew.get('credits_before', '?')}→{renew.get('credits_after', renew.get('credits', '?'))} · "
                        f"续期 {ren_ok}ok/{ren_fail}fail · "
                        f"重启 {rst_ok} · "
                        f"AFK +{afk.get('delta', 0)} · "
                        f"{time.strftime('%H:%M UTC', time.gmtime())}"
                    )
                    break
                _tg_api(
                    token,
                    "sendPhoto",
                    {"chat_id": chat, "caption": caption[:900]},
                    files={"photo": ("status-card.png", png)},
                )
                log("telegram status screenshot sent", "ok")
            except Exception as exc:  # noqa: BLE001
                log(f"telegram screenshot failed: {exc}", "warn")

        # 3) 可选：附带 JSON 报告文件
        if env("SKYCASTLE_TG_DOCUMENT", "0") in {"1", "true", "yes"} and results:
            try:
                raw = json.dumps(results, ensure_ascii=False, indent=2).encode("utf-8")
                _tg_api(
                    token,
                    "sendDocument",
                    {"chat_id": chat, "caption": "last-report.json"},
                    files={"document": ("last-report.json", raw)},
                )
            except Exception as exc:  # noqa: BLE001
                log(f"telegram document failed: {exc}", "warn")

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
        # all / afk: only desktop AFK, limited to requested minutes (default 10)
        summary["afk"] = run_afk(client, minutes, "desktop")

    if mode == "mobile":
        # mobile mode kept for manual use only; not triggered by "all"
        summary["mobile"] = run_afk(client, minutes, "mobile")

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SkyCastle auto-renew + AFK credits")
    parser.add_argument(
        "command",
        nargs="?",
        default=env("SKYCASTLE_MODE") or "all",
        choices=["all", "login", "status", "afk", "mobile", "renew", "run"],
    )
    parser.add_argument("--minutes", type=int, default=int(env("SKYCASTLE_AFK_MINUTES") or "10"))
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
    notify(report, results=results, cache_dir=args.cache)
    out = os.path.join(args.cache, "last-report.json")
    os.makedirs(args.cache, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=False, indent=2)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
