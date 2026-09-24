"""Passwordless CAS SMS protocol, isolated from the existing app login.

The web protocol is verified against CAS 6.26.2.100. A successful CAS login
alone is NOT a SmartHome AuthSession; the caller must validate the ticket
through the existing app authorization chain before persisting credentials.
"""

from __future__ import annotations

import json
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from html import unescape
from http.cookiejar import CookieJar
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from ..errors import AuthenticationError

CAS_ORIGIN = "https://id1.cloud.huawei.com"
CAS_LOGIN = CAS_ORIGIN + "/CAS/portal/login.html"
CAS_AJAX = CAS_ORIGIN + "/CAS/IDM_W/ajaxHandler/"
SMS_COOLDOWN = 60
SMS_SESSION_TTL = 600
MAX_CODE_ATTEMPTS = 5
MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class SmsLoginError(AuthenticationError):
    """A safe, fixed reason code. Never includes upstream response bodies."""

    def __init__(self, reason: str, *, remote_code: str = "") -> None:
        super().__init__(reason)
        self.reason = reason
        self.remote_code = remote_code if re.fullmatch(r"[0-9]{1,10}", remote_code) else ""


def _trusted_web_url(url: str) -> bool:
    parts = urlparse(url)
    return (
        parts.scheme == "https"
        and parts.netloc == "id1.cloud.huawei.com"
        and parts.path.startswith(("/CAS/", "/AMW/"))
        and not parts.username
        and not parts.password
    )


class _SameOriginRedirects(HTTPRedirectHandler):
    """Do not send an authenticated web request to a response-supplied host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _trusted_web_url(newurl):
            raise SmsLoginError("unexpected_redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(repr=False)
class WebLoginResult:
    """Private in-memory login result; credentials are excluded from repr."""

    payload: dict = field(repr=False)
    cookies: CookieJar = field(repr=False)

    def credentials(self) -> tuple[str, str]:
        """Return only explicitly identified ticket/user fields, never guesses."""
        ticket = self.payload.get("TGC")
        user_id = self.payload.get("userID")
        # Only accept cookies that the cookie policy would send back to CAS.
        request = Request(CAS_LOGIN)
        self.cookies.add_cookie_header(request)
        eligible = dict(
            item.strip().split("=", 1)
            for item in request.get_header("Cookie", "").split(";")
            if "=" in item
        )
        ticket = ticket or eligible.get("TGC")
        user_id = user_id or eligible.get("userID")
        if not isinstance(ticket, str) or not ticket or not isinstance(user_id, str) or not user_id:
            raise SmsLoginError("bridge_unverified")
        return ticket, user_id


class CasSmsLogin:
    """One in-memory mainland-China web login; callers serialize operations.

    Deliberately no automatic SMS retries, no password fallback and no captcha
    bypass. Requests use a CookieJar so repeated Set-Cookie, expiry, domains,
    paths and redirects are handled by the standard HTTP cookie policy.
    """

    def __init__(
        self,
        *,
        request: Callable | None = None,
        clock: Callable[[], float] = time.monotonic,
        timeout: float = 20.0,
    ) -> None:
        self.cookies = CookieJar()
        self._opener = build_opener(HTTPCookieProcessor(self.cookies), _SameOriginRedirects())
        self._request = request or self._http_request
        self._clock = clock
        self.timeout = timeout
        self._local: dict = {}
        self._context: dict = {}
        self._version = ""
        self._phone = ""
        self._risk: dict = {}
        self._sent_at: float | None = None
        self._next_send = 0.0
        self._attempts = 0

    @property
    def retry_after(self) -> int:
        return max(0, int(self._next_send - self._clock() + 0.999))

    @staticmethod
    def normalize_phone(phone: str) -> str:
        phone = re.sub(r"[\s-]", "", phone)
        if phone.startswith("+86"):
            phone = phone[3:]
        elif phone.startswith("0086"):
            phone = phone[4:]
        if not re.fullmatch(r"1[3-9][0-9]{9}", phone):
            raise SmsLoginError("invalid_phone")
        return phone

    def initialize(self) -> None:
        """Load the public login page and get a fresh page-bound CAS session."""
        self.cookies.clear()
        self._local = {}
        self._context = {}
        self._sent_at = None
        self._phone = ""
        html = self._request("GET", CAS_LOGIN).decode("utf-8")
        match = re.search(r"cVersion=([A-Za-z0-9_.-]+)", html)
        if not match:
            raise SmsLoginError("protocol_changed")
        self._version = match.group(1)
        result = self._ajax("login/getPageInfo", {
            "pageName": "login", "lang": "zh-cn",
            "reqClientType": "7", "loginChannel": "7000000",
        })
        local = result.get("localInfo")
        if not isinstance(local, dict) or not result.get("pageToken") or not result.get("pageTokenKey"):
            raise SmsLoginError("protocol_changed")
        if str(local.get("isOpenSMSLogin")).lower() not in ("true", "1"):
            raise SmsLoginError("sms_unavailable")
        if local.get("localHttpsAjaxPath") != CAS_AJAX.removesuffix("/ajaxHandler/"):
            raise SmsLoginError("unsupported_region")
        self._local = {k: unescape(v) if isinstance(v, str) else v for k, v in local.items()}
        self._context.update({k: result[k] for k in ("pageToken", "pageTokenKey")})

    def send_code(self, phone: str) -> None:
        """Check risk and send one login SMS, with a local resend guard."""
        phone = self.normalize_phone(phone)
        if self.retry_after:
            raise SmsLoginError("rate_limited")
        self._sent_at = None
        # Guard failed/ambiguous sends as well: never retry a timed-out SMS POST.
        self._next_send = self._clock() + SMS_COOLDOWN
        if not self._local:
            self.initialize()
        self._phone = phone
        account = "0086" + phone
        self._risk = self._ajax("chkRisk", {
            "userAccount": account, "operType": "11", "callingCode": "0086",
            "registerCountry": "cn", "lowLogin": self._local.get("lowLogin", ""),
        })
        if str(self._risk.get("isNeedImageCode", "0")).lower() in ("1", "true"):
            raise SmsLoginError("captcha_required")
        if str(self._risk.get("siteID")) != "1":
            raise SmsLoginError("unsupported_region")
        self._ajax("getSMSCodeV3", {
            "smsReqType": "2", "operType": "20", "accountType": "2",
            "mobilePhone": account, "userAccount": account,
            "regionCode": "cn", "callingCode": "0086",
            "siteID": self._risk["siteID"], "lowLogin": self._risk.get("lowLogin", ""),
            "session_code_key": "sms_login_session_ramdom_code_key", "randomCode": "",
        })
        self._sent_at = self._clock()
        self._attempts = 0

    def complete(self, code: str) -> WebLoginResult:
        """Submit the SMS code, returning a web result, not an app session."""
        if self._sent_at is None or self._clock() - self._sent_at > SMS_SESSION_TTL:
            self._sent_at = None
            raise SmsLoginError("session_expired")
        code = code.strip()
        if not re.fullmatch(r"[0-9]{6}", code):
            raise SmsLoginError("invalid_code")
        if self._attempts >= MAX_CODE_ATTEMPTS:
            self._sent_at = None
            raise SmsLoginError("rate_limited")
        self._attempts += 1
        result = self._ajax("loginBySMS", {
            "userAccount": "0086" + self._phone, "orgUserAccount": self._phone,
            "smsAuthCode": code, "opType": "11", "siteID": self._risk["siteID"],
            "lowLogin": self._risk.get("lowLogin", ""),
            "quickAuth": self._local.get("quickAuth", ""), "isThirdBind": "0",
        })
        self._sent_at = None
        callback = result.get("callbackURL")
        if callback:
            if not isinstance(callback, str) or not _trusted_web_url(callback):
                raise SmsLoginError("unexpected_redirect")
            self._request("GET", unescape(callback))
        return WebLoginResult(result, self.cookies)

    def _ajax(self, endpoint: str, values: dict) -> dict:
        params = {
            k: self._local[k]
            for k in ("reqClientType", "loginChannel", "clientID", "lang", "service", "scope")
            if self._local.get(k) is not None
        }
        params["languageCode"] = self._local.get("lang", "zh-cn")
        params.update(self._context)
        params.update(values)
        query = urlencode({"reflushCode": "0." + str(secrets.randbelow(10**16)), "cVersion": self._version})
        raw = self._request("POST", CAS_AJAX + endpoint + "?" + query, urlencode(params).encode())
        try:
            payload = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as error:
            raise SmsLoginError("protocol_changed") from error
        if not isinstance(payload, dict):
            raise SmsLoginError("protocol_changed")
        if str(payload.get("isSuccess")) != "1":
            code = str(payload.get("errorCode", ""))
            reasons = {
                "10000402": "invalid_code", "10002058": "invalid_code",
                "10002057": "code_expired", "10000600": "session_expired",
                "10000201": "captcha_required", "10000706": "captcha_required",
                "10002083": "rate_limited", "70002030": "rate_limited",
                "70008800": "additional_verification", "70008805": "sms_unavailable",
                "10012076": "password_required",
            }
            reason = reasons.get(code, "huawei_rejected")
            if reason == "session_expired":
                self._local = {}
                self._sent_at = None
            raise SmsLoginError(reason, remote_code=code)
        for key in ("localStorageID", "hwid_cas_sid"):
            if isinstance(payload.get(key), str):
                self._context[key] = payload[key]
        return payload

    def _http_request(self, method: str, url: str, data: bytes | None = None) -> bytes:
        if not _trusted_web_url(url):
            raise SmsLoginError("unexpected_redirect")
        request = Request(url, data=data, method=method, headers={
            "Accept": "application/json, text/html;q=0.9",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": CAS_LOGIN, "Origin": CAS_ORIGIN,
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
        })
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise SmsLoginError("protocol_changed")
                return body
        except HTTPError as error:
            raise SmsLoginError("rate_limited" if error.code == 429 else "cannot_connect") from None
        except (URLError, TimeoutError, OSError):
            raise SmsLoginError("cannot_connect") from None
