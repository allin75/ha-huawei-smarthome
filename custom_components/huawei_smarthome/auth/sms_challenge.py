"""Native account authentication with the SMS challenge verified on a real account."""

import asyncio
import json
import re
import time
from dataclasses import replace

from ..errors import InvalidCredentialsError
from .huawei import HuaweiSmartHomeAuthProvider, _first, _parse_form
from .interface import LoginChallenge, LoginStart
from .sms import CasSmsLogin, SmsLoginError

CHALLENGE_TTL = 600
SMS_TYPES = frozenset({"2", "6"})


class HuaweiSmsAuthProvider(HuaweiSmartHomeAuthProvider):
    """Prefer offered SMS channels; retain the existing device-code fallback."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._login_fields = {}
        self._sms = None
        self._sms_ready = False
        self._send_attempted = False
        self._expires = 0.0
        self._cas = None

    def _login_request(self, *args, **kwargs):
        response = super()._login_request(*args, **kwargs)
        self._login_fields = _parse_form(response.body)
        return response

    def _begin_login(self, account, password):
        self._sms = None
        self._sms_ready = self._send_attempted = False
        self._cas = None
        try:
            account = CasSmsLogin.normalize_phone(account)
            mainland_phone = True
        except SmsLoginError:
            mainland_phone = False
        result = super()._begin_login(account, password)
        self._expires = time.monotonic() + CHALLENGE_TTL
        if result.session is not None or self._pending is None or not mainland_phone:
            return result
        try:
            details = json.loads(_first(self._login_fields, "errorDesc") or "{}")
        except (ValueError, TypeError):
            return result
        items = details.get("authCodeSentList") if isinstance(details, dict) else None
        if not isinstance(items, list):
            return result
        choices = [item for item in items[:20] if isinstance(item, dict)
                   and str(item.get("accountType")) in SMS_TYPES
                   and isinstance(item.get("name"), str) and 0 < len(item["name"]) <= 256]
        if not choices:
            return result
        self._sms = next((item for item in choices if str(item.get("sent")) == "1"), choices[0])
        self._sms_ready = str(self._sms.get("sent")) == "1"
        self._send_attempted = self._sms_ready
        self._pending = replace(self._pending, challenge_name=self._sms["name"], challenge_type=str(self._sms["accountType"]))
        return LoginStart(challenge=self._challenge())

    def _challenge(self):
        return LoginChallenge(
            prompt="请查看本次发送到绑定手机的短信验证码",
            challenge_name="",  # No phone identifiers in flow metadata.
            challenge_type=self._pending.challenge_type,
            sms=True, needs_send=not self._sms_ready,
        )

    def _require_pending(self):
        if self._pending is None or time.monotonic() >= self._expires:
            self._pending = None
            self._cas = None
            raise SmsLoginError("session_expired")

    async def async_send_sms(self):
        return await asyncio.to_thread(self._send_sms)

    def _send_sms(self):
        self._require_pending()
        if self._sms is None:
            raise SmsLoginError("sms_unavailable")
        if self._sms_ready:
            return self._challenge()
        if self._send_attempted:
            raise SmsLoginError("rate_limited")
        self._send_attempted = True
        self._cas = CasSmsLogin()
        self._cas.initialize()
        risk = self._cas._ajax("chkRisk", {
            "userAccount": self._pending.account, "operType": "11", "registerCountry": "cn",
            "service": self._cas._local.get("service", ""), "lowLogin": "", "ext_clientInfo": "",
        })
        if str(risk.get("isNeedImageCode", "0")).lower() in ("1", "true"):
            raise SmsLoginError("captcha_required")
        if str(risk.get("siteID", "1")) != "1":
            raise SmsLoginError("unsupported_region")
        self._cas._ajax("getSMSCodeV3", {
            "userAccount": self._pending.account, "accountType": "2",
            "mobilePhone": self._sms["name"], "operType": "8", "smsReqType": "6", "siteID": "1",
        })
        self._sms_ready = True
        return self._challenge()

    async def async_complete_challenge(self, code):
        self._require_pending()
        if self._sms is not None:
            if not self._sms_ready:
                raise SmsLoginError("sms_unavailable")
            if not re.fullmatch(r"[0-9]{6}", code.strip()):
                raise InvalidCredentialsError("six-digit SMS code required")
        try:
            return await super().async_complete_challenge(code)
        finally:
            self._cas = None
            self._sms = None
            self._sms_ready = False
            self._login_fields = {}
