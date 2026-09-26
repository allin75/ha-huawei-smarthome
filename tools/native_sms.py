"""Local experiment: native app login followed by a server-offered SMS challenge.

CAS dispatch is based on a community implementation, not a verified app API.
Keep native and CAS sessions separate; only device discovery proves success.
"""

import json
import re
import time
import uuid

from custom_components.huawei_smarthome.api.errors import SmartHomeApiError
from custom_components.huawei_smarthome.auth.huawei import (
    HuaweiSmartHomeAuthProvider,
    _first,
    _parse_form,
)
from custom_components.huawei_smarthome.auth.sms import CasSmsLogin, SmsLoginError
from custom_components.huawei_smarthome.errors import (
    AuthenticationError,
    InvalidCredentialsError,
    InvalidProtocolDataError,
    TransientAuthenticationError,
)
from tools.sms_bridge import _discover

CHALLENGE_TTL = 600
LOGIN_COOLDOWN = 60
MAX_LOGIN_ATTEMPTS = 3
MAX_CODE_ATTEMPTS = 3
SMS_TYPES = frozenset({"2", "6"})

MESSAGES = {
    "ready": "请输入手机号和华为账号密码，检查可用的短信验证方式。",
    "checking": "正在处理，请稍候。",
    "sms_available": "华为提供了短信验证方式，请点击获取短信验证码。",
    "sent": "短信请求已被华为接受，请输入本次收到的验证码。",
    "marked_sent": "华为标记该手机渠道已发送验证码，请输入本次收到的验证码。",
    "sms_unavailable": "本次原生登录没有提供短信渠道。请返回 Codex，暂时不要重复登录。",
    "sms_dispatch_failed": "短信请求未成功。已保留本轮验证上下文，请返回 Codex，暂时不要重复发码。",
    "invalid_phone": "请输入中国大陆手机号（+86）。",
    "invalid_password": "请输入华为账号密码。",
    "login_rejected": "华为未接受本次原生登录，错误编号可供继续排查。",
    "invalid_code": "请输入六位数字验证码。",
    "challenge_rejected": "华为未接受本次短信验证。请返回 Codex 核对，暂时不要重新发码。",
    "session_expired": "本轮验证已过期，需要重新登录。",
    "rate_limited": "本地重试限制已生效，请稍后再试。",
    "cannot_connect": "暂时无法连接华为，请返回 Codex 检查。",
    "authorization_failed": "账号验证已通过，但智慧生活授权尚未完成，请返回 Codex。",
    "discovery_failed": "智慧生活授权已完成，家庭或设备读取失败，请返回 Codex。",
    "verified": "智慧生活授权及家庭、设备读取成功，可以返回 Codex 继续安装。",
    "unexpected_error": "测试遇到未预期的问题，已保留安全状态供排查。",
}


class NativeProvider(HuaweiSmartHomeAuthProvider):
    """Retain native login metadata privately, without changing production code."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.last_fields = {}

    def _login_request(self, *args, **kwargs):
        response = super()._login_request(*args, **kwargs)
        self.last_fields = _parse_form(response.body)
        return response


class NativeState:
    def __init__(self):
        self.device_id = uuid.uuid4().hex
        self.provider_factory = NativeProvider
        self.clock = time.monotonic
        self.provider = None
        self.cas = None
        self.channel = None
        self.session = None
        self.expires = 0
        self.next_login = 0
        self.login_attempts = 0
        self.code_attempts = 0
        self.send_attempted = False
        self.code_ready = False
        self.stage = "ready"
        self.diagnostics = {}
        self.status = {"outcome": "ready", "message": MESSAGES["ready"], "can_begin": True, "can_send": False, "can_verify": False}


def _channels(fields):
    try:
        details = json.loads(_first(fields, "errorDesc") or "{}")
    except (ValueError, TypeError):
        return []
    items = details.get("authCodeSentList") if isinstance(details, dict) else None
    if not isinstance(items, list):
        return []
    result = []
    for item in items[:20]:
        if not isinstance(item, dict):
            continue
        name, kind = item.get("name"), str(item.get("accountType"))
        if isinstance(name, str) and name and len(name) <= 256 and re.fullmatch(r"-?[0-9]{1,3}", kind):
            result.append({"name": name, "account_type": kind, "sent": str(item.get("sent")) == "1"})
    return result


def _safe_code(fields):
    code = _first(fields, "resultCode") or ""
    return code if re.fullmatch(r"[0-9]{1,10}", code) else ""


def _expire(state):
    if state.provider and state.provider._pending and state.clock() >= state.expires:
        state.provider._pending = None
        state.channel = None
        state.code_ready = False
        state.cas = None
        return True
    return False


def snapshot(state):
    if _expire(state):
        state.status = {"outcome": "session_expired", "message": MESSAGES["session_expired"]}
    result = dict(state.status)
    pending = bool(state.provider and state.provider._pending)
    result.update(
        can_begin=not pending and state.session is None and state.login_attempts < MAX_LOGIN_ATTEMPTS and state.clock() >= state.next_login,
        can_send=pending and state.channel is not None and not state.send_attempted and not state.code_ready,
        can_verify=pending and state.code_ready and state.code_attempts < MAX_CODE_ATTEMPTS,
        stage=state.stage,
        diagnostics=state.diagnostics,
    )
    return result


def _begin(state, data):
    if not snapshot(state)["can_begin"]:
        return state.status["outcome"] if state.provider and state.provider._pending else "rate_limited"
    account = CasSmsLogin.normalize_phone(str(data.get("phone", "")))
    password = data.get("password")
    if not isinstance(password, str) or not 0 < len(password) <= 256:
        return "invalid_password"
    state.login_attempts += 1
    state.next_login = state.clock() + LOGIN_COOLDOWN
    state.expires = state.clock() + CHALLENGE_TTL
    state.code_attempts = 0
    state.send_attempted = state.code_ready = False
    state.channel = state.cas = None
    state.diagnostics = {}
    state.provider = state.provider_factory(device_id=state.device_id, device_name="Home Assistant SMS check")
    state.stage = "native_login"
    start = state.provider._begin_login(account, password)
    if start.session is not None:
        state.session = start.session
        return _read_devices(state)
    channels = _channels(state.provider.last_fields)
    state.diagnostics = {
        "channel_count": len(channels),
        "sms_channels": sum(c["account_type"] in SMS_TYPES for c in channels),
        "offered_types": sorted({c["account_type"] for c in channels}),
        "marked_sent_count": sum(c["sent"] for c in channels),
    }
    choices = [c for c in channels if c["account_type"] in SMS_TYPES]
    if not choices:
        return "sms_unavailable"
    state.channel = next((c for c in choices if c["sent"]), choices[0])
    state.code_ready = state.channel["sent"]
    state.send_attempted = state.code_ready
    state.diagnostics["selected_sms_type"] = state.channel["account_type"]
    return "marked_sent" if state.code_ready else "sms_available"


def _send(state):
    if not snapshot(state)["can_send"]:
        return state.status["outcome"]
    state.send_attempted = True  # A timeout may still have sent a message.
    pending = state.provider._pending
    state.cas = CasSmsLogin()
    state.stage = "sms_initialize"
    try:
        state.cas.initialize()
        state.stage = "sms_risk"
        risk = state.cas._ajax("chkRisk", {
            "userAccount": pending.account, "operType": "11", "registerCountry": "cn",
            "service": state.cas._local.get("service", ""), "lowLogin": "", "ext_clientInfo": "",
        })
        if str(risk.get("isNeedImageCode", "0")).lower() in ("1", "true"):
            raise SmsLoginError("captcha_required")
        if str(risk.get("siteID", "1")) != "1":
            raise SmsLoginError("unsupported_region")
        state.stage = "sms_dispatch"
        state.cas._ajax("getSMSCodeV3", {
            "userAccount": pending.account, "accountType": "2",
            "mobilePhone": state.channel["name"], "operType": "8", "smsReqType": "6", "siteID": "1",
        })
    except SmsLoginError as error:
        state.diagnostics.update(dispatch_reason=error.reason, dispatch_code=error.remote_code)
        return "sms_dispatch_failed"
    state.code_ready = True
    return "sent"


def _read_devices(state):
    state.stage = "device_read"
    try:
        counts = _discover(state.session)
    except (SmartHomeApiError, InvalidProtocolDataError, AuthenticationError):
        return "discovery_failed"
    state.diagnostics.update(counts)
    return "verified"


def _verify(state, data):
    if not snapshot(state)["can_verify"]:
        return state.status["outcome"]
    code = str(data.get("code", "")).strip()
    if not re.fullmatch(r"[0-9]{6}", code):
        return "invalid_code"
    state.code_attempts += 1
    state.code_ready = False  # A timeout may still have consumed the code.
    state.stage = "native_verify"
    pending = state.provider._pending
    response = state.provider._login_request(
        pending.account, pending.encrypted_password,
        challenge=(code, state.channel["name"], state.channel["account_type"]), retry=True,
    )
    fields = _parse_form(response.body)
    state.diagnostics["native_code"] = _safe_code(fields)
    if response.status >= 400 or _first(fields, "resultCode") != "0":
        state.code_ready = False  # Don't invite replays of an unverified channel.
        return "challenge_rejected"
    state.provider._pending = None
    state.code_ready = False
    state.stage = "native_authorize"
    try:
        state.session = state.provider._finish_login(pending.account, fields)
    except AuthenticationError:
        return "authorization_failed"
    return _read_devices(state)


def perform(state, path, data):
    """Only fixed outcomes and counts leave this in-memory state machine."""
    try:
        if _expire(state) and path != "/begin":
            outcome = "session_expired"
        elif path == "/begin":
            outcome = _begin(state, data)
        elif path == "/send":
            outcome = _send(state)
        elif path == "/verify":
            outcome = _verify(state, data)
        elif path == "/continue" and state.session is not None:
            outcome = _read_devices(state)
        else:
            outcome = state.status["outcome"]
    except SmsLoginError as error:
        outcome = error.reason if error.reason in MESSAGES else "login_rejected"
        state.diagnostics["remote_code"] = error.remote_code
    except TransientAuthenticationError:
        outcome = "cannot_connect"
    except InvalidCredentialsError:
        outcome = "login_rejected"
        state.diagnostics["native_code"] = _safe_code(state.provider.last_fields)
    except AuthenticationError:
        outcome = "authorization_failed"
    except Exception:  # noqa: BLE001 -- Never log authentication exception values.
        outcome = "unexpected_error"
    finally:
        data.pop("password", None)
        data.pop("code", None)
    state.status = {"outcome": outcome, "message": MESSAGES[outcome]}
    return snapshot(state)
