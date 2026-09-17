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


def _looks_like_waf_html(raw: str) -> bool:
    """Detect CrowdSec / Cloudflare / generic HTML challenge pages."""
    s = (raw or "")[:4000].lower()
    if not s:
        return False
    markers = (
        "crowdsec",
        "captcha",
        "cf-browser-verification",
        "attention required",
        "access denied",
        "you have been blocked",
        "sorry, you have been blocked",
        "<!doctype html",
        "<html",
    )
    if any(m in s for m in markers[:7]):
        return True
    # HTML without JSON structure
    if ("<!doctype html" in s or "<html" in s) and "{" not in s[:200]:
        return True
    return False


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

    def import_browser_cookies(self, cookies: list[dict[str, Any]]) -> int:
        """Import cookies from Selenium into urllib jar (restore API session after browser login)."""
        from http.cookiejar import Cookie

        host = urllib.parse.urlparse(self.base).hostname or "panel.skycastle.us"
        n = 0
        for c in cookies or []:
            name = c.get("name")
            value = c.get("value")
            if not name or value is None:
                continue
            domain = (c.get("domain") or host).lstrip(".")
            path = c.get("path") or "/"
            try:
                cookie = Cookie(
                    version=0,
                    name=str(name),
                    value=str(value),
                    port=None,
                    port_specified=False,
                    domain=domain,
                    domain_specified=True,
                    domain_initial_dot=domain.startswith("."),
                    path=path,
                    path_specified=True,
                    secure=bool(c.get("secure", True)),
                    expires=int(time.time()) + 60 * 60 * 24 * 30,
                    discard=False,
                    comment=None,
                    comment_url=None,
                    rest={"HttpOnly": None},
                    rfc2109=False,
                )
                self.jar.set_cookie(cookie)
                n += 1
            except Exception:
                continue
        if n:
            log(f"imported {n} browser cookies into API client", "ok")
        return n

    def get_remember_token(self) -> str:
        for c in self.jar:
            if c.name == "remember_token" and c.value:
                return c.value
        return ""

    def export_cookies_for_browser(self) -> list[dict[str, Any]]:
        """Export urllib cookie jar for Playwright.

        Rule: each cookie must have either `url` OR (`domain` + `path`).
        Never set `url` together with `path`/`domain`.
        """
        base = self.base.rstrip("/")
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for c in self.jar:
            if not c.value:
                continue
            if c.name in seen:
                continue
            seen.add(c.name)
            out.append({"name": c.name, "value": str(c.value), "url": base + "/"})
        token = self.get_remember_token()
        if token and "remember_token" not in seen:
            out.append({"name": "remember_token", "value": token, "url": base + "/"})
        return out

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
                        # CrowdSec / WAF / HTML challenge page
                        if _looks_like_waf_html(raw):
                            raise ApiError(
                                "WAF/CrowdSec blocked this IP (HTML ban page). "
                                "Reduce request rate or whitelist GitHub Actions.",
                                "WAF_BLOCKED",
                                resp.status,
                            )
                        return {"success": True, "data": raw[:200], "status": resp.status, "raw": True}
                    if isinstance(payload, dict):
                        payload.setdefault("status", resp.status)
                    return payload
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8", "replace")
                if _looks_like_waf_html(raw):
                    msg = (
                        f"WAF/CrowdSec ban (HTTP {exc.code}). "
                        "Too many API probes or GHA IP blocked."
                    )
                    log(f"{method} {path} → {msg}", "err")
                    raise ApiError(msg, "WAF_BLOCKED", exc.code) from exc
                try:
                    payload = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    # never put full HTML into error message
                    snippet = raw.strip().replace("\n", " ")[:120]
                    payload = {"message": snippet or f"HTTP {exc.code}"}
                code = str(payload.get("error_code") or payload.get("code") or "")
                msg = str(
                    payload.get("message")
                    or payload.get("error_message")
                    or exc.reason
                    or f"HTTP {exc.code}"
                )
                # clamp message length for TG / logs
                if len(msg) > 180:
                    msg = msg[:177] + "..."
                if exc.code in (429, 502, 503, 504) and attempt < retries:
                    wait = min(45, 6 * attempt)
                    if exc.code == 429:
                        wait = max(wait, WORK_MIN_INTERVAL)
                    log(f"{method} {path} → {exc.code}, retry in {wait}s ({code or msg})", "warn")
                    time.sleep(wait)
                    last_err = ApiError(msg, code, exc.code, payload)
                    continue
                raise ApiError(msg, code, exc.code, payload) from exc
            except ApiError:
                raise
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
    """action: start | stop | restart — minimal probes to avoid WAF."""
    action = action.lower().strip()
    paths_bodies: list[tuple[str, Any]] = [
        (f"/api/user/servers/{ident}/power/{action}", None),
        (f"/api/user/servers/{ident}/power", {"signal": action}),
    ]
    for path, body in paths_bodies:
        try:
            client.request("POST", path, body, retries=2)
            log(f"power {action} → {ident}", "ok")
            return True
        except ApiError as exc:
            if exc.code == "WAF_BLOCKED":
                log(f"power {action} blocked by WAF", "err")
                return False
            log(f"power {action} {ident} via {path}: {str(exc)[:120]}", "warn")
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


def _is_missing_route(exc: ApiError) -> bool:
    msg = str(exc).lower()
    return (
        exc.status in (404, 405, 501)
        or exc.code in {"NOT_FOUND", "METHOD_NOT_ALLOWED", "ROUTE_NOT_FOUND"}
        or "route does not exist" in msg
        or "not found" in msg
        or "no route" in msg
    )


def renew_server(client: PanelClient, ident: str, extra_ids: list[str] | None = None) -> dict[str, Any]:
    """Click the server RENEWAL button (costs credits, extends due date).

    Keep probes minimal — too many 404s trigger CrowdSec on panel.skycastle.us.
    Override with SKYCASTLE_RENEW_PATH=/api/user/servers/{id}/renew
    """
    ids = [ident]
    for x in extra_ids or []:
        if x and x not in ids:
            ids.append(x)

    custom = env("SKYCASTLE_RENEW_PATH")
    paths_bodies: list[tuple[str, Any]] = []
    if custom:
        for i in ids:
            p = custom.replace("{id}", i).replace("{uuid}", i).replace("{uuidShort}", i)
            paths_bodies.append((p, {}))
    else:
        # only the most likely paths (max ~4 requests)
        i = ids[0]
        paths_bodies = [
            (f"/api/user/servers/{i}/renew", {}),
            (f"/api/client/servers/{i}/renew", {}),
            (f"/api/user/servers/{i}/renewal", {}),
        ]
        if len(ids) > 1:
            paths_bodies.append((f"/api/user/servers/{ids[1]}/renew", {}))

    last_err: Exception | None = None
    probed: list[str] = []
    for path, body in paths_bodies:
        probed.append(path)
        try:
            payload = client.request("POST", path, body, retries=1)
            log(f"server renew → {ident} via {path}", "ok")
            data = payload.get("data") if isinstance(payload, dict) else payload
            return {"ok": True, "path": path, "data": data if isinstance(data, dict) else payload}
        except ApiError as exc:
            last_err = exc
            if exc.code == "WAF_BLOCKED":
                return {
                    "ok": False,
                    "path": path,
                    "error": str(exc),
                    "code": "WAF_BLOCKED",
                    "probed": probed,
                }
            if _is_missing_route(exc):
                log(f"renew probe miss {path}", "info")
                time.sleep(1.5)  # slow down to avoid CrowdSec
                continue
            log(f"renew {ident} via {path}: {exc} [{exc.code}]", "warn")
            if exc.status in (400, 402, 403, 409, 422) or "credit" in str(exc).lower():
                return {"ok": False, "path": path, "error": str(exc)[:180], "code": exc.code}
            time.sleep(1.5)
            continue

    err = str(last_err) if last_err else "no renew endpoint matched"
    if len(err) > 180:
        err = err[:177] + "..."
    return {
        "ok": False,
        "path": None,
        "error": err,
        "code": getattr(last_err, "code", "") if last_err else "NO_ENDPOINT",
        "probed": probed,
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
    # 仅当状态为 offline / stopping 等异常时才 start/restart（避免打断正常 running）
    do_power_fix = env("SKYCASTLE_START_SERVERS", "1") not in {"0", "false", "no"}
    need_power_states = {
        "offline",
        "stopped",
        "stopping",
        "exited",
        "suspended",
        "dead",
    }

    servers = list_servers(client)
    if not servers:
        log("no servers returned (ok if account is empty)", "info")
    else:
        # dump first server keys once — helps discover renewal field / id shape
        try:
            sample = servers[0]
            log(f"server keys: {sorted(sample.keys()) if isinstance(sample, dict) else type(sample)}", "info")
        except Exception:
            pass

    for srv in servers:
        ident = server_ident(srv)
        name = server_name(srv)
        state = server_state(srv)
        ren_info = server_renewal_info(srv)
        full_uuid = str(srv.get("uuid") or srv.get("uuidFull") or srv.get("server_uuid") or "")
        extra_ids = [full_uuid] if full_uuid and full_uuid != ident else []
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

        # 1) 续期：直接打开 /dashboard/servers，看 RENEWAL 区域
        #    可点击 → 点击续期；不可点击 → 跳过（不算失败）
        if do_renew and ident:
            if not row.get("renewal_due_before") and srv.get("expires_at"):
                row["renewal_due_before"] = srv.get("expires_at")
            cookies = client.export_cookies_for_browser()
            result = browser_click_renew(
                panel=client.base,
                cookies=cookies,
                cache_dir=client.cache_dir,
                server_name=name,
                account=account,
            )
            # optional: also try API if user set SKYCASTLE_RENEW_PATH
            if (
                not result.get("ok")
                and not result.get("skipped")
                and env("SKYCASTLE_RENEW_PATH")
            ):
                api_result = renew_server(client, ident, extra_ids=extra_ids)
                if api_result.get("ok"):
                    result = api_result

            if result.get("ok") and result.get("skipped"):
                report["actions"].append(f"renew {name} skipped (not clickable)")
                report["renewals"].append(
                    {
                        "name": name,
                        "id": ident,
                        "ok": True,
                        "skipped": True,
                        "path": result.get("path"),
                        "error": result.get("error"),
                        "due_before": row["renewal_due_before"],
                        "cost": row["renewal_cost"],
                        "before": result.get("before"),
                        "after": result.get("after"),
                    }
                )
                log(f"· 续期跳过 {name}: {result.get('error')}", "info")
            elif result.get("ok"):
                row["renewed"] = True
                report["actions"].append(f"renew {name} ok via {result.get('path')}")
                log(f"✓ 续期完成 {name} via {result.get('path')}", "ok")
                data = result.get("data") or {}
                if isinstance(data, dict):
                    for k in ("due_at", "expires_at", "next_renewal_at", "renewal_due_at", "due"):
                        if data.get(k) is not None:
                            row["renewal_due_after"] = data.get(k)
                            break
                # browser path may return parsed Due as next_renewal / due_after
                if result.get("due_after") or result.get("next_renewal"):
                    row["renewal_due_after"] = result.get("due_after") or result.get("next_renewal")
                report["renewals"].append(
                    {
                        "name": name,
                        "id": ident,
                        "ok": True,
                        "skipped": False,
                        "path": result.get("path"),
                        "due_before": row["renewal_due_before"],
                        "due_after": row["renewal_due_after"],
                        "next_renewal": row["renewal_due_after"]
                        or result.get("next_renewal")
                        or result.get("due_after"),
                        "cost": row["renewal_cost"],
                        "before": None,
                        "after": result.get("after"),
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
                        "due_before": row["renewal_due_before"] or srv.get("expires_at"),
                        "cost": row["renewal_cost"],
                        "before": result.get("before"),
                        "after": result.get("after"),
                    }
                )
                log(f"✗ 续期失败 {name}: {err}", "err")

        # 2) 仅 offline / stopping 等才启动或重启（running/starting 不动）
        if do_power_fix and ident and state in need_power_states:
            log(f"server {name} state={state} → need power recovery", "warn")
            # stopping: 先等一下再 start；offline/stopped: 直接 start
            if state == "stopping":
                time.sleep(5)
            ok = start_server(client, ident)
            if not ok:
                # start 失败再试 restart
                ok = restart_server(client, ident)
                row["restarted"] = ok
                if ok:
                    report["actions"].append(f"restart {name} ok (was {state})")
                    report["restarts"].append({"name": name, "id": ident, "ok": True, "reason": state})
                    log(f"✓ 重启完成 {name} (was {state})", "ok")
                else:
                    row["errors"].append("start/restart failed")
                    report["actions"].append(f"restart {name} failed (was {state})")
                    report["restarts"].append({"name": name, "id": ident, "ok": False, "reason": state})
                    log(f"✗ 重启失败 {name}", "err")
            else:
                row["started"] = True
                report["actions"].append(f"start {name} ok (was {state})")
                report["restarts"].append({"name": name, "id": ident, "ok": True, "action": "start", "reason": state})
                log(f"✓ 开机 {name} (was {state})", "ok")
            time.sleep(2)
        elif ident:
            log(f"server {name} state={state or 'unknown'} — skip power (only offline/stopping need it)", "info")

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
                if r.get("ok") and r.get("skipped"):
                    lines.append(f"  ⏭ 续期 {r.get('name')}: 跳过")
                elif r.get("ok"):
                    nxt = r.get("next_renewal") or r.get("due_after") or ""
                    extra = f" · 预计下次续期 {nxt}" if nxt else ""
                    lines.append(
                        f"  ✅ 续期 {r.get('name')}: due {r.get('due_before')} → {r.get('due_after')} "
                        f"(cost={r.get('cost')}){extra}"
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
            err = str(item["error"])
            if len(err) > 200:
                err = err[:197] + "..."
            # never dump HTML ban pages into Telegram
            if _looks_like_waf_html(err) or "<html" in err.lower():
                err = "WAF/CrowdSec blocked API (IP banned or rate-limited)"
            parts.append(f"❌ <b>ERROR</b> {_html_escape(err)}")
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
                    if r.get("ok") and r.get("skipped"):
                        parts.append(
                            f"⏭ <b>{name}</b> 续期跳过（按钮不可点）\n"
                            f"   {_html_escape(str(r.get('error') or 'not clickable'))}"
                        )
                    elif r.get("ok"):
                        due_b = r.get("due_before") or "-"
                        due_a = r.get("due_after") or r.get("next_renewal") or "-"
                        next_est = r.get("next_renewal") or r.get("due_after") or ""
                        line = (
                            f"✅ <b>{name}</b> 续期成功\n"
                            f"   Due: <code>{_html_escape(str(due_b))}</code>"
                            f" → <code>{_html_escape(str(due_a))}</code>\n"
                            f"   花费: <code>{_html_escape(str(r.get('cost') or '?'))}</code> credits"
                        )
                        if next_est and str(next_est) not in {"-", "None", ""}:
                            line += f"\n   📅 预计下次续期: <b>{_html_escape(str(next_est))}</b>"
                        parts.append(line)
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
                    due_a = srv.get("renewal_due_after") or srv.get("renewal_due_before") or "-"
                    parts.append(
                        f"   Due <code>{_html_escape(str(srv.get('renewal_due_before') or '-'))}</code>"
                        f" → <code>{_html_escape(str(srv.get('renewal_due_after') or '-'))}</code>"
                    )
                    if srv.get("renewal_due_after"):
                        parts.append(
                            f"   📅 预计下次续期: <b>{_html_escape(str(srv.get('renewal_due_after')))}</b>"
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



# ---------------------------------------------------------------------------
# browser (SeleniumBase UC) — login + RENEWAL click + real screenshots
# Mirrors skymc_renew.py Cloudflare Turnstile bypass via uc_gui_click_captcha
# ---------------------------------------------------------------------------

def _is_login_url(url: str) -> bool:
    u = (url or "").lower()
    return "login" in u or "/auth/" in u


def _sb_challenge_visible(sb: Any) -> bool:
    """True only for full-page Cloudflare interstitial — NOT the login Turnstile widget."""
    try:
        src = (sb.get_page_source() or "")[:8000]
        low = src.lower()
        # Normal login form includes Turnstile text — do not treat as interstitial
        if 'type="password"' in low or "sign in" in low or "username or email" in low:
            return (
                "checking if the site connection is secure" in low
                or "just a moment" in low
                or "enable javascript and cookies to continue" in low
            )
        return (
            "checking if the site connection is secure" in low
            or "just a moment" in low
            or "enable javascript and cookies to continue" in low
            or ("verify you are human" in low and "password" not in low)
        )
    except Exception:
        return False


def _sb_click_turnstile_once(sb: Any) -> None:
    """One UC click for the embedded Turnstile checkbox (skymc style)."""
    try:
        sb.uc_gui_click_captcha()
        log("uc_gui_click_captcha (turnstile widget)", "ok")
        time.sleep(4)
    except Exception as exc:  # noqa: BLE001
        log(f"uc_gui_click_captcha: {exc}", "warn")


def _sb_handle_cloudflare(sb: Any, max_retry: int = 3) -> bool:
    """Pass full-page Cloudflare interstitial via UC GUI click."""
    if not _sb_challenge_visible(sb):
        return True
    log("Cloudflare interstitial — uc_gui_click_captcha…", "warn")
    for i in range(max_retry):
        log(f"captcha attempt {i + 1}/{max_retry}", "info")
        try:
            sb.uc_gui_click_captcha()
            log("uc_gui_click_captcha called", "ok")
            time.sleep(5)
            if not _sb_challenge_visible(sb):
                log("interstitial passed", "ok")
                return True
        except Exception as exc:  # noqa: BLE001
            log(f"uc_gui_click_captcha: {exc}", "warn")
        time.sleep(2)
    log("interstitial may still be present — continue", "warn")
    return False


def _sb_wait_challenge_gone(sb: Any, timeout: int = 15) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if not _sb_challenge_visible(sb):
            return True
        _sb_handle_cloudflare(sb, max_retry=1)
        time.sleep(1)
    return not _sb_challenge_visible(sb)


def _sb_fill_field(sb: Any, selectors: list[str], value: str, label: str) -> bool:
    """Fill input and verify the value actually stuck (React/controlled inputs)."""
    if not value:
        log(f"fill {label}: empty value", "err")
        return False
    for sel in selectors:
        try:
            if not sb.is_element_visible(sel):
                continue
            sb.wait_for_element_visible(sel, timeout=5)
            try:
                sb.click(sel)
            except Exception:
                pass
            try:
                sb.clear(sel)
            except Exception:
                pass
            # human-like typing helps React controlled inputs
            try:
                sb.type(sel, value)
            except Exception:
                sb.execute_script(
                    "arguments[0].value = arguments[1];"
                    "arguments[0].dispatchEvent(new Event('input',{bubbles:true}));"
                    "arguments[0].dispatchEvent(new Event('change',{bubbles:true}));",
                    sb.find_element(sel),
                    value,
                )
            time.sleep(0.3)
            try:
                got = sb.get_value(sel) or ""
            except Exception:
                got = sb.execute_script(
                    "var e=document.querySelector(arguments[0]); return e?e.value:'';",
                    sel,
                ) or ""
            if got == value or (len(got) >= max(1, len(value) - 1) and label != "password"):
                log(f"filled {label} via {sel} (len={len(got)})", "ok")
                return True
            # force native value setter for React
            ok = sb.execute_script(
                """
                var sel = arguments[0], value = arguments[1];
                var el = document.querySelector(sel);
                if (!el) return false;
                var proto = window.HTMLInputElement.prototype;
                var desc = Object.getOwnPropertyDescriptor(proto, 'value');
                if (desc && desc.set) desc.set.call(el, value); else el.value = value;
                el.dispatchEvent(new Event('input', { bubbles: true }));
                el.dispatchEvent(new Event('change', { bubbles: true }));
                el.dispatchEvent(new Event('blur', { bubbles: true }));
                return el.value === value;
                """,
                sel,
                value,
            )
            if ok:
                log(f"filled {label} via React setter {sel}", "ok")
                return True
        except Exception as exc:  # noqa: BLE001
            log(f"fill {label} try {sel}: {exc}", "info")
            continue
    log(f"unable to fill {label}", "err")
    return False


def _sb_click_login(sb: Any) -> bool:
    for sel in (
        'button:contains("Sign in")',
        'button:contains("Sign In")',
        'button:contains("Login")',
        'button:contains("登录")',
        'button[type="submit"]',
    ):
        try:
            if sb.is_element_visible(sel):
                try:
                    sb.uc_click(sel)
                except Exception:
                    sb.click(sel)
                log(f"clicked login {sel}", "ok")
                return True
        except Exception:
            continue
    try:
        ok = sb.execute_script(
            """
            var btns = document.querySelectorAll('button');
            for (var i = 0; i < btns.length; i++) {
                var t = (btns[i].innerText || '').toLowerCase();
                if (t.indexOf('sign in') >= 0 || t.indexOf('login') >= 0 || t.indexOf('登录') >= 0) {
                    btns[i].click(); return true;
                }
            }
            var s = document.querySelector('button[type="submit"]');
            if (s) { s.click(); return true; }
            return false;
            """
        )
        if ok:
            log("clicked login via JS", "ok")
            return True
    except Exception as exc:  # noqa: BLE001
        log(f"login click failed: {exc}", "warn")
    return False


def _sb_browser_login(sb: Any, panel: str, email: str, password: str) -> bool:
    """Full browser login with email/password + UC Turnstile click."""
    login_url = panel.rstrip("/") + "/auth/login"
    log(f"browser open login {login_url}", "info")
    try:
        sb.uc_open_with_reconnect(login_url, reconnect_time=6)
    except Exception:
        sb.open(login_url)
    try:
        sb.wait_for_ready_state_complete()
    except Exception:
        pass
    time.sleep(3)
    _sb_handle_cloudflare(sb)
    time.sleep(1)

    email_sels = [
        'input[type="email"]',
        'input[name="email"]',
        'input[name="username"]',
        'input[name="username_or_email"]',
        'input[placeholder*="Email" i]',
        'input[placeholder*="Username" i]',
        'input[type="text"]',
    ]
    pass_sels = [
        'input[type="password"]',
        'input[name="password"]',
    ]
    if not _sb_fill_field(sb, email_sels, email, "email"):
        return False
    time.sleep(0.5)
    if not _sb_fill_field(sb, pass_sels, password, "password"):
        return False
    time.sleep(0.5)
    # verify password not empty before submit
    try:
        plen = sb.execute_script(
            """
            var p = document.querySelector('input[type="password"]');
            return p && p.value ? p.value.length : 0;
            """
        )
        if not plen:
            log("password still empty after fill — retry", "warn")
            _sb_fill_field(sb, pass_sels, password, "password")
            time.sleep(0.5)
    except Exception:
        pass

    # embedded Turnstile checkbox — click once
    _sb_click_turnstile_once(sb)
    time.sleep(2)

    for attempt in range(4):
        log(f"browser Sign in click #{attempt + 1}", "info")
        # re-ensure fields before each attempt (page may re-render)
        _sb_fill_field(sb, email_sels, email, "email")
        _sb_fill_field(sb, pass_sels, password, "password")
        time.sleep(0.3)
        _sb_click_login(sb)
        time.sleep(4)
        if _sb_challenge_visible(sb):
            _sb_handle_cloudflare(sb, max_retry=2)
            time.sleep(2)
        for _ in range(10):
            url = (sb.get_current_url() or "").lower()
            if not _is_login_url(url):
                log(f"browser login ok → {sb.get_current_url()}", "ok")
                return True
            if _sb_challenge_visible(sb):
                _sb_handle_cloudflare(sb, max_retry=1)
            time.sleep(1)
        if attempt < 3:
            _sb_click_turnstile_once(sb)
            time.sleep(2)
    log(f"browser login failed, url={sb.get_current_url()}", "err")
    return False


def _sb_open_servers(
    sb: Any,
    panel: str,
    cookies: list[dict[str, Any]] | None,
    account: dict[str, str] | None,
) -> bool:
    """Open /dashboard/servers; reuse API cookies if possible, else browser login."""
    panel = panel.rstrip("/")
    target = panel + "/dashboard/servers"
    account = account or {}

    # seed domain
    try:
        sb.uc_open_with_reconnect(panel + "/", reconnect_time=4)
    except Exception:
        sb.open(panel + "/")
    time.sleep(1)
    _sb_handle_cloudflare(sb, max_retry=2)

    # inject cookies from API session (AFK already logged in)
    if cookies:
        try:
            for c in cookies:
                name = c.get("name")
                value = c.get("value")
                if not name or not value:
                    continue
                try:
                    sb.driver.add_cookie(
                        {
                            "name": name,
                            "value": str(value),
                            "path": "/",
                            "domain": urlparse_host(panel),
                        }
                    )
                except Exception:
                    try:
                        sb.driver.add_cookie({"name": name, "value": str(value), "path": "/"})
                    except Exception:
                        pass
            log(f"browser cookies injected: {len(cookies)}", "ok")
        except Exception as exc:  # noqa: BLE001
            log(f"cookie inject: {exc}", "warn")

    try:
        sb.uc_open_with_reconnect(target, reconnect_time=5)
    except Exception:
        sb.open(target)
    try:
        sb.wait_for_ready_state_complete()
    except Exception:
        pass
    time.sleep(3)
    _sb_handle_cloudflare(sb)
    _sb_wait_challenge_gone(sb, timeout=12)

    if _is_login_url(sb.get_current_url() or ""):
        email = account.get("email") or env("SKYCASTLE_EMAIL") or ""
        password = account.get("password") or env("SKYCASTLE_PASSWORD") or ""
        if not email or not password:
            log("on login page and no email/password", "err")
            return False
        log("API cookies not enough — browser login with email/password + Turnstile", "warn")
        if not _sb_browser_login(sb, panel, email, password):
            return False
        try:
            sb.uc_open_with_reconnect(target, reconnect_time=5)
        except Exception:
            sb.open(target)
        time.sleep(3)
        _sb_handle_cloudflare(sb)
        _sb_wait_challenge_gone(sb, timeout=12)
        if _is_login_url(sb.get_current_url() or ""):
            log("still on login after browser auth", "err")
            return False
    else:
        log("already authenticated in browser — skip login", "ok")

    log(f"on servers page: {sb.get_current_url()}", "ok")
    return True


def urlparse_host(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or "panel.skycastle.us"


def _sb_save_shot(sb: Any, path: str) -> str | None:
    try:
        _sb_wait_challenge_gone(sb, timeout=10)
        time.sleep(0.8)
        sb.save_screenshot(path)
        if os.path.isfile(path) and os.path.getsize(path) > 1000:
            log(f"screenshot → {path} ({os.path.getsize(path)} bytes)", "ok")
            return path
    except Exception as exc:  # noqa: BLE001
        log(f"screenshot failed: {exc}", "warn")
    return None


def capture_panel_screenshot(
    panel: str,
    remember_token: str = "",
    cache_dir: str = ".skycastle-cache",
    path: str = "/dashboard/servers",
    filename: str = "panel-servers.png",
    cookies: list[dict[str, Any]] | None = None,
    account: dict[str, str] | None = None,
) -> tuple[str | None, str]:
    """Real screenshot of dashboard/servers via SeleniumBase UC."""
    try:
        from seleniumbase import SB  # type: ignore
    except ImportError:
        msg = "seleniumbase not installed (pip install seleniumbase)"
        log(msg, "warn")
        return None, msg

    os.makedirs(cache_dir, exist_ok=True)
    out = os.path.abspath(os.path.join(cache_dir, filename))
    jar = list(cookies or [])
    if remember_token and not any(c.get("name") == "remember_token" for c in jar):
        jar.append(
            {
                "name": "remember_token",
                "value": remember_token,
                "url": panel.rstrip("/") + "/",
            }
        )

    try:
        # headless=False required for uc_gui_click_captcha (use xvfb on GHA)
        with SB(uc=True, headless=False, locale_code="zh-CN") as sb:
            ok = _sb_open_servers(sb, panel, jar, account or {})
            shot = _sb_save_shot(sb, out)
            if not ok:
                return shot, f"browser auth failed url={sb.get_current_url()}"
            if shot:
                return shot, f"ok url={sb.get_current_url()}"
            return None, "screenshot empty"
    except Exception as exc:  # noqa: BLE001
        msg = f"seleniumbase screenshot failed: {exc}"
        log(msg, "warn")
        return None, msg


def browser_click_renew(
    panel: str,
    cookies: list[dict[str, Any]],
    cache_dir: str = ".skycastle-cache",
    server_name: str = "",
    account: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Open /dashboard/servers; click RENEWAL if enabled, else skip.

    Uses SeleniumBase UC + uc_gui_click_captcha (same idea as skymc_renew.py).
    """
    try:
        from seleniumbase import SB  # type: ignore
    except ImportError:
        return {"ok": False, "error": "seleniumbase not installed", "code": "NO_SB"}

    os.makedirs(cache_dir, exist_ok=True)
    before = os.path.abspath(os.path.join(cache_dir, "renew-before.png"))
    after = os.path.abspath(os.path.join(cache_dir, "renew-after.png"))

    try:
        with SB(uc=True, headless=False, locale_code="zh-CN") as sb:
            if not _sb_open_servers(sb, panel, cookies, account or {}):
                _sb_save_shot(sb, before)
                return {
                    "ok": False,
                    "error": f"browser on login page ({sb.get_current_url()})",
                    "code": "AUTH_FAILED",
                    "before": before if os.path.isfile(before) else None,
                }

            # Expand folder / wait for server cards + RENEWAL to render
            try:
                # click Unassigned / folder if present
                for label in ("Unassigned", "By Folder", "All Servers"):
                    try:
                        if sb.is_element_visible(f'span:contains("{label}")') or sb.is_element_visible(
                            f'div:contains("{label}")'
                        ):
                            try:
                                sb.click(f'div:contains("{label}")')
                            except Exception:
                                pass
                    except Exception:
                        pass
                # scroll down so server cards load
                for _ in range(4):
                    sb.execute_script("window.scrollBy(0, 400);")
                    time.sleep(0.6)
                sb.execute_script("window.scrollTo(0, 0);")
                time.sleep(1)
                # wait up to ~20s for RENEWAL text
                end = time.time() + 20
                while time.time() < end:
                    body = ""
                    try:
                        body = sb.get_text("body") or ""
                    except Exception:
                        try:
                            body = sb.execute_script(
                                "return document.body ? document.body.innerText : '';"
                            ) or ""
                        except Exception:
                            body = ""
                    if "RENEWAL" in body or "续期" in body or (server_name and server_name in body):
                        log("server card / RENEWAL visible", "ok")
                        break
                    sb.execute_script("window.scrollBy(0, 300);")
                    time.sleep(1.5)
            except Exception as exc:  # noqa: BLE001
                log(f"prepare servers UI: {exc}", "warn")

            # Scroll RENEWAL / credit button into view before shot + scan
            try:
                sb.execute_script(
                    """
                    var nodes = document.querySelectorAll('button, a, [role="button"], div');
                    for (var i = 0; i < nodes.length; i++) {
                        var t = (nodes[i].innerText || '').replace(/\\s+/g, ' ').trim().toLowerCase();
                        if (/\\d+\\s*credits?/.test(t) || t.indexOf('renewal') >= 0) {
                            nodes[i].scrollIntoView({block: 'center', behavior: 'instant'});
                            break;
                        }
                    }
                    """
                )
                time.sleep(1)
            except Exception:
                pass

            _sb_save_shot(sb, before)

            # Find the real renew action: "1 credit · 3 days" / "1 credits · in 3h"
            # Do NOT treat bare "RENEWAL" label as a button.
            # Disabled = only disabled attr / aria-disabled / cursor-not-allowed (not "opacity" class).
            info = {}
            try:
                info = sb.execute_script(
                    """
                    var body = document.body ? document.body.innerText : '';
                    var hasRenewal = body.indexOf('RENEWAL') >= 0 || body.indexOf('续期') >= 0;
                    var buttons = [];
                    var clickable = null;
                    var disabledFound = false;

                    function isDisabled(el) {
                        if (!el) return true;
                        if (el.disabled) return true;
                        if ((el.getAttribute('aria-disabled') || '') === 'true') return true;
                        var cls = (el.className ? String(el.className) : '').toLowerCase();
                        if (cls.indexOf('cursor-not-allowed') >= 0) return true;
                        if (cls.indexOf('pointer-events-none') >= 0) return true;
                        // greyed-out style often uses opacity-50 / opacity-60 alone — check computed
                        try {
                            var st = window.getComputedStyle(el);
                            if (st && st.pointerEvents === 'none') return true;
                            if (st && parseFloat(st.opacity) < 0.5) return true;
                        } catch (e) {}
                        return false;
                    }

                    function isRenewAction(text) {
                        var low = (text || '').toLowerCase().replace(/\\s+/g, ' ').trim();
                        if (!low || low.length > 50) return false;
                        // "1 credit · 3 days" / "1 credits · in 3h" / "续期"
                        if (/\\d+\\s*credits?/.test(low)) return true;
                        if (low.indexOf('续期') >= 0) return true;
                        // avoid bare "RENEWAL" section title
                        if (low === 'renewal' || low.indexOf('renewal') === 0 && low.indexOf('credit') < 0)
                            return false;
                        if (low.indexOf('renew') >= 0 && low.indexOf('renewal') < 0) return true;
                        return false;
                    }

                    // 1) native buttons / links
                    var nodes = document.querySelectorAll('button, a, [role="button"]');
                    for (var i = 0; i < nodes.length; i++) {
                        var b = nodes[i];
                        var text = (b.innerText || b.textContent || '').replace(/\\s+/g, ' ').trim();
                        if (!isRenewAction(text)) continue;
                        var vis = b.offsetParent !== null || (b.getClientRects && b.getClientRects().length > 0);
                        var dis = isDisabled(b);
                        buttons.push({text: text, disabled: dis, visible: !!vis, tag: b.tagName});
                        if (!vis) continue;
                        if (dis) { disabledFound = true; continue; }
                        if (!clickable) clickable = b;
                    }

                    // 2) near RENEWAL label — card row may use styled div as button
                    if (!clickable) {
                        var all = document.querySelectorAll('div, span');
                        for (var j = 0; j < all.length; j++) {
                            var el = all[j];
                            var t = (el.innerText || '').replace(/\\s+/g, ' ').trim();
                            // leaf-ish: short text matching credit pattern
                            if (!isRenewAction(t)) continue;
                            if (el.children && el.children.length > 3) continue;
                            var vis2 = el.offsetParent !== null;
                            var dis2 = isDisabled(el);
                            buttons.push({text: t, disabled: dis2, visible: !!vis2, tag: el.tagName});
                            if (!vis2) continue;
                            if (dis2) { disabledFound = true; continue; }
                            // prefer clickable parent button if any
                            var btn = el.closest('button, a, [role="button"]') || el;
                            if (isDisabled(btn)) { disabledFound = true; continue; }
                            clickable = btn;
                            break;
                        }
                    }

                    if (clickable) {
                        try { clickable.scrollIntoView({block:'center'}); } catch (e) {}
                        clickable.setAttribute('data-skycastlereew', '1');
                    }
                    return {
                        hasRenewal: hasRenewal,
                        disabledFound: disabledFound,
                        canClick: !!clickable,
                        buttons: buttons.slice(0, 15)
                    };
                    """
                )
            except Exception as exc:  # noqa: BLE001
                log(f"renew DOM scan: {exc}", "warn")
                info = {}

            log(f"RENEWAL scan: {json.dumps(info, ensure_ascii=False)[:500]}", "info")

            def _browser_cookies():
                try:
                    return sb.driver.get_cookies() or []
                except Exception:
                    return []

            if not info.get("hasRenewal") and not info.get("canClick"):
                _sb_save_shot(sb, after)
                return {
                    "ok": True,
                    "skipped": True,
                    "path": "browser:RENEWAL-skip",
                    "error": "RENEWAL section not found / no renew action",
                    "code": "NO_RENEWAL_UI",
                    "before": before if os.path.isfile(before) else None,
                    "after": after if os.path.isfile(after) else None,
                    "cookies": _browser_cookies(),
                }

            if not info.get("canClick"):
                _sb_save_shot(sb, after)
                reason = "RENEWAL present but action button disabled/not clickable — skip"
                log(reason, "info")
                return {
                    "ok": True,
                    "skipped": True,
                    "path": "browser:RENEWAL-skip",
                    "error": reason,
                    "code": "SKIP_NOT_CLICKABLE",
                    "before": before if os.path.isfile(before) else None,
                    "after": after if os.path.isfile(after) else None,
                    "cookies": _browser_cookies(),
                }

            # click marked element
            clicked = False
            try:
                clicked = bool(
                    sb.execute_script(
                        """
                        var el = document.querySelector('[data-skycastlereew="1"]');
                        if (!el) return false;
                        el.click();
                        return true;
                        """
                    )
                )
            except Exception as exc:  # noqa: BLE001
                log(f"renew click JS: {exc}", "warn")

            if not clicked:
                # only try buttons that look like "N credits" renew action
                for name in ("credits", "Credits", "续期"):
                    sel = f'button:contains("{name}")'
                    try:
                        if sb.is_element_visible(sel) and sb.is_element_enabled(sel):
                            try:
                                sb.uc_click(sel)
                            except Exception:
                                sb.click(sel)
                            clicked = True
                            log(f"clicked renew via {sel}", "ok")
                            break
                    except Exception:
                        continue

            if not clicked:
                _sb_save_shot(sb, after)
                # if we only saw disabled credits button, treat as skip not failure
                if info.get("disabledFound") or info.get("hasRenewal"):
                    return {
                        "ok": True,
                        "skipped": True,
                        "path": "browser:RENEWAL-skip",
                        "error": "RENEWAL action not clickable — skip",
                        "code": "SKIP_NOT_CLICKABLE",
                        "before": before if os.path.isfile(before) else None,
                        "after": after if os.path.isfile(after) else None,
                    }
                return {
                    "ok": False,
                    "error": "RENEWAL action click failed",
                    "code": "CLICK_FAILED",
                    "before": before if os.path.isfile(before) else None,
                    "after": after if os.path.isfile(after) else None,
                }

            log("clicked RENEWAL action on /dashboard/servers", "ok")
            time.sleep(2)
            if _sb_challenge_visible(sb):
                _sb_handle_cloudflare(sb, max_retry=3)
            # confirm dialogs
            for name in ("Confirm", "OK", "确认", "续期", "Renew"):
                sel = f'button:contains("{name}")'
                try:
                    if sb.is_element_visible(sel) and sb.is_element_enabled(sel):
                        try:
                            sb.uc_click(sel)
                        except Exception:
                            sb.click(sel)
                        log(f"clicked confirm {name}", "ok")
                        time.sleep(2)
                        break
                except Exception:
                    continue
            time.sleep(3)
            _sb_wait_challenge_gone(sb, timeout=10)
            # re-scroll to card and read Due for next renewal estimate
            next_renewal = ""
            try:
                sb.execute_script(
                    """
                    var nodes = document.querySelectorAll('button, a, [role="button"], div');
                    for (var i = 0; i < nodes.length; i++) {
                        var t = (nodes[i].innerText || '').toLowerCase();
                        if (t.indexOf('credit') >= 0 || t.indexOf('renewal') >= 0) {
                            nodes[i].scrollIntoView({block:'center'});
                            break;
                        }
                    }
                    """
                )
                time.sleep(1)
                next_renewal = sb.execute_script(
                    """
                    var body = document.body ? document.body.innerText : '';
                    // "Due 9月19日" / "Due Sep 19" / "Due 2026-09-19"
                    var m = body.match(/Due\\s*([\\d月日年月日\\-/]+|\\w+\\s+\\d{1,2})/i);
                    if (m) return m[1].trim();
                    m = body.match(/到期[:：]?\\s*([^\\n]+)/);
                    if (m) return m[1].trim().slice(0, 40);
                    return '';
                    """
                ) or ""
            except Exception:
                pass
            _sb_save_shot(sb, after)
            browser_cookies = []
            try:
                browser_cookies = sb.driver.get_cookies() or []
            except Exception:
                pass
            if next_renewal:
                log(f"next renewal / Due after click: {next_renewal}", "ok")
            return {
                "ok": True,
                "skipped": False,
                "path": "browser:RENEWAL",
                "before": None,  # only keep success after-shot
                "after": after if os.path.isfile(after) else None,
                "next_renewal": next_renewal or None,
                "due_after": next_renewal or None,
                "cookies": browser_cookies,
            }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:200], "code": "BROWSER_ERROR"}



def notify(
    text: str,
    results: list[dict[str, Any]] | None = None,
    cache_dir: str = ".skycastle-cache",
    panel: str = "",
    remember_token: str = "",
) -> None:
    token = env("TELEGRAM_BOT_TOKEN") or env("TELEGRAM_TOKEN")
    chat = env("TELEGRAM_CHAT_ID") or env("TELEGRAM_CHAT")
    results = results or []
    panel = panel or env("SKYCASTLE_PANEL") or PANEL_DEFAULT

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
            try:
                _tg_api(
                    token,
                    "sendMessage",
                    {"chat_id": chat, "text": text[:3900], "disable_web_page_preview": "true"},
                )
            except Exception as exc2:  # noqa: BLE001
                log(f"telegram plain notify failed: {exc2}", "warn")

        # 2) 仅续期成功后的截图（不要续期前 / 不要额外整页截图）
        if env("SKYCASTLE_TG_SCREENSHOT", "1") not in {"0", "false", "no"}:
            try:
                sent_any = False
                for item in results:
                    renew = item.get("renew") or {}
                    for r in renew.get("renewals") or []:
                        if not (r.get("ok") and not r.get("skipped")):
                            continue
                        p = r.get("after")
                        if not (p and os.path.isfile(p)):
                            continue
                        next_est = r.get("next_renewal") or r.get("due_after") or ""
                        caption = f"✅ 续期成功 · {r.get('name') or ''}"
                        if next_est:
                            caption += f" · 预计下次续期 {next_est}"
                        try:
                            with open(p, "rb") as fh:
                                data = fh.read()
                            _tg_api(
                                token,
                                "sendPhoto",
                                {"chat_id": chat, "caption": caption[:900]},
                                files={"photo": (os.path.basename(p), data)},
                            )
                            sent_any = True
                            log("telegram renew-success screenshot sent", "ok")
                        except Exception as exc:  # noqa: BLE001
                            log(f"tg send renew after shot: {exc}", "warn")
                if not sent_any:
                    log("no renew-success screenshot to send", "info")
            except Exception as exc:  # noqa: BLE001
                log(f"telegram screenshot failed: {exc}", "warn")

        # 3) 可选：附带 JSON 报告文件
        if env("SKYCASTLE_TG_DOCUMENT", "0") in {"1", "true", "yes"} and results:
            try:
                safe = []
                for item in results:
                    copy = dict(item)
                    copy.pop("remember_token", None)
                    copy.pop("cookies", None)
                    safe.append(copy)
                raw = json.dumps(safe, ensure_ascii=False, indent=2).encode("utf-8")
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
    api_ok = False
    api_err = ""
    try:
        login(client, account)
        api_ok = True
    except ApiError as exc:
        api_err = f"{exc} [{exc.code}]"
        log(f"API login failed: {api_err}", "err")
        if exc.code != "WAF_BLOCKED" and mode in {"afk", "mobile", "status"}:
            # non-WAF auth errors: cannot continue AFK-only modes
            raise
        log("API blocked/unavailable — will try browser-only for renew/screenshot", "warn")

    summary: dict[str, Any] = {
        "account": who,
        "mode": mode,
        "panel": panel,
        "remember_token": client.get_remember_token() or account.get("token") or "",
        "cookies": client.export_cookies_for_browser() if api_ok else [],
        "api_ok": api_ok,
    }
    if api_err:
        summary["api_error"] = api_err

    browser_cookies: list[dict[str, Any]] = []
    if mode in {"all", "renew", "status"}:
        if api_ok:
            summary["renew"] = run_renew(client, account)
        else:
            # browser-only renew when CrowdSec bans GHA API login
            log("browser-only renew path (no API session)", "warn")
            result = browser_click_renew(
                panel=panel,
                cookies=[],
                cache_dir=cache_dir,
                server_name="",
                account=account,
            )
            browser_cookies = list(result.get("cookies") or [])
            if browser_cookies:
                client.import_browser_cookies(browser_cookies)
                # try API session with browser cookies
                try:
                    session = get_session(client)
                    api_ok = True
                    summary["api_ok"] = True
                    summary["remember_token"] = client.get_remember_token() or ""
                    log(
                        f"API session restored via browser cookies · "
                        f"{session.get('username') or session.get('email') or 'user'}",
                        "ok",
                    )
                except ApiError as exc:
                    log(f"API still blocked after browser cookies: {exc}", "warn")
            summary["renew"] = {
                "credits_before": None,
                "credits_after": None,
                "credits": None,
                "renewals": [
                    {
                        "name": "browser",
                        "ok": bool(result.get("ok")),
                        "skipped": bool(result.get("skipped")),
                        "path": result.get("path"),
                        "error": result.get("error"),
                        "before": None,
                        "after": result.get("after")
                        if (result.get("ok") and not result.get("skipped"))
                        else None,
                        "next_renewal": result.get("next_renewal") or result.get("due_after"),
                        "due_after": result.get("due_after") or result.get("next_renewal"),
                    }
                ],
                "restarts": [],
                "servers": [],
                "actions": [f"browser renew: {result.get('path') or result.get('error')}"],
            }
            # if API restored, refresh credits into report
            if api_ok:
                try:
                    credits = get_credits(client)
                    summary["renew"]["credits_before"] = credits
                    summary["renew"]["credits_after"] = credits
                    summary["renew"]["credits"] = credits
                except Exception:
                    pass

    if mode in {"all", "afk"}:
        if api_ok:
            summary["afk"] = run_afk(client, minutes, "desktop")
        else:
            summary["afk"] = {
                "delta": 0,
                "error": "skipped: API WAF/CrowdSec blocked (AFK needs API)",
            }
            log("AFK skipped — API blocked by WAF/CrowdSec", "warn")

    if mode == "mobile":
        if api_ok:
            summary["mobile"] = run_afk(client, minutes, "mobile")
        else:
            summary["mobile"] = {"delta": 0, "error": "API blocked"}

    if mode == "status" and api_ok:
        st = afk_status(client)
        summary["afk_status"] = {
            "credits": st.get("user_credits"),
            "minutes_afk": st.get("minutes_afk"),
            "credits_per_minute": st.get("credits_per_minute"),
            "daily_usage": st.get("daily_usage"),
        }
        log(json.dumps(summary["afk_status"], ensure_ascii=False), "info")

    summary["remember_token"] = client.get_remember_token() or summary.get("remember_token") or ""
    summary["cookies"] = client.export_cookies_for_browser() if api_ok else summary.get("cookies") or []
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
    remember = ""
    for item in results:
        if item.get("remember_token"):
            remember = str(item["remember_token"])
            break
    if not remember:
        remember = env("SKYCASTLE_TOKEN") or env("SKYCASTLE_REMEMBER_TOKEN")
    notify(
        report,
        results=results,
        cache_dir=args.cache,
        panel=args.panel,
        remember_token=remember,
    )
    out = os.path.join(args.cache, "last-report.json")
    os.makedirs(args.cache, exist_ok=True)
    safe_results = []
    for item in results:
        copy = dict(item)
        copy.pop("remember_token", None)
        copy.pop("cookies", None)
        safe_results.append(copy)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(safe_results, fh, ensure_ascii=False, indent=2)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
