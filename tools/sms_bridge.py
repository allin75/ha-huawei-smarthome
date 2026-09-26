"""Reloadable local authorization check. Never serialize authentication values."""

import asyncio
import json
import re
import secrets
import uuid
from html import unescape
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import Request

from custom_components.huawei_smarthome.api.client import SmartHomeDiscoveryApi
from custom_components.huawei_smarthome.api.errors import SmartHomeApiError
from custom_components.huawei_smarthome.api.transport import UrllibHttpTransport
from custom_components.huawei_smarthome.auth.huawei import HuaweiSmartHomeAuthProvider
from custom_components.huawei_smarthome.auth.sms import (
    MAX_RESPONSE_BYTES,
    SmsLoginError,
)
from custom_components.huawei_smarthome.errors import (
    AuthenticationError,
    InvalidProtocolDataError,
)

# Only known protocol names are emitted; even unknown key names may contain PII.
FIELD_NAMES = frozenset({"TGC", "userID", "userAccount", "callbackURL", "data", "isSuccess", "resultCode", "errorCode", "errorDesc", "ticket", "service", "code", "state"})
COOKIE_NAMES = frozenset({"TGC", "userID", "JSESSIONID", "HWCAS", "HWCAS_ID", "HWCAS_TGC", "CASLOGINSITE", "hwid_cas_sid"})
CALLBACK_PATHS = frozenset({"/AMW/portal/home.html", "/AMW/portal/userCenter/index.html", "/CAS/portal/login.html"})
AMW_PAGE_INFO = "https://id1.cloud.huawei.com/AMW/ajaxHandler/common/getPageInfo"


def describe(result):
    """Presence and whitelisted names only; no raw URL, payload or cookie value."""
    payload = result.payload
    callback = payload.get("callbackURL")
    try:
        parts = urlsplit(callback if isinstance(callback, str) else "")
        query = set(parse_qs(parts.query, keep_blank_values=True))
        trusted = parts.scheme == "https" and parts.netloc == "id1.cloud.huawei.com"
    except ValueError:
        query, trusted = set(), False
    cookie_names = {c.name for c in result.cookies}
    try:
        result.credentials()
        candidate = True
    except SmsLoginError:
        candidate = False
    return {
        "response_fields": sorted(payload.keys() & FIELD_NAMES),
        "unknown_response_field_count": len(payload.keys() - FIELD_NAMES),
        "cookie_names": sorted(cookie_names & COOKIE_NAMES),
        "unknown_cookie_count": len(cookie_names - COOKIE_NAMES),
        "callback_query_fields": sorted(query & FIELD_NAMES),
        "unknown_callback_field_count": len(query - FIELD_NAMES),
        "callback_on_account_host": trusted,
        "callback_destination": parts.path if trusted and parts.path in CALLBACK_PATHS else "other",
        "explicit_service_ticket": candidate,
    }


def _probe_account(state):
    """One read-only CAS query, observed in the official public SDK.

    This is diagnostic only, never a ticket exchange or a login retry.
    Endpoint response values are discarded, not added to login credentials.
    """
    previous = getattr(state, "account_probe", None)
    if isinstance(previous, dict):
        return previous
    state.account_probe = {"outcome": "incomplete"}
    try:
        payload = state.client._ajax("getUserAccInfo", {})
        state.account_probe = {
            "outcome": "responded",
            "response_fields": sorted(payload.keys() & FIELD_NAMES),
            "unknown_response_field_count": len(payload.keys() - FIELD_NAMES),
        }
    except SmsLoginError as error:
        state.account_probe = {"outcome": "rejected", "remote_code": error.remote_code}
    except Exception:  # noqa: BLE001 -- Never expose authentication response bodies.
        state.account_probe = {"outcome": "unavailable"}
    return state.account_probe


def _account_center_summary(payload):
    local = payload.get("localInfo")
    local = local if isinstance(local, dict) else {}
    redirect = payload.get("redirectUrl")
    destination = urlsplit(redirect if isinstance(redirect, str) else "")
    return {
        "outcome": "redirect_required" if redirect else "initialized",
        "response_fields": sorted(payload.keys() & FIELD_NAMES),
        "local_fields": sorted(local.keys() & FIELD_NAMES),
        "has_page_token": bool(payload.get("pageToken")),
        "redirect_requested": bool(redirect),
        "redirect_on_account_host": destination.netloc == "id1.cloud.huawei.com",
        "redirect_destination": destination.path if destination.path in CALLBACK_PATHS else "other",
        "redirect_path_markers": [word for word in ("login", "logout", "error", "verify", "usercenter", "oauth", "remote", "ticket") if word in destination.path.lower()],
        "redirect_query_fields": sorted(set(parse_qs(destination.query)) & FIELD_NAMES),
    }


def _initialize_account_center(state):
    """Complete the observed AMW webUserCenter initialization once.

    The official AMW index-entry-legacy.js passes the callback query to
    common/getPageInfo with pageName=webUserCenter. A GET alone skips this.
    Keep its private response in RAM for analysis; emit only safe metadata.
    This establishes a web account-center session, not an app session.
    """
    previous = getattr(state, "account_center", None)
    if isinstance(previous, dict):
        payload = getattr(state, "account_center_payload", None)
        if isinstance(payload, dict):
            state.account_center = _account_center_summary(payload)
            return state.account_center
        return previous
    state.account_center = {"outcome": "not_applicable"}
    callback = getattr(state, "account_center_callback", None) or state.web_result.payload.get("callbackURL")
    if not isinstance(callback, str):
        return state.account_center
    try:
        parts = urlsplit(unescape(callback))
        if (parts.scheme != "https" or parts.netloc != "id1.cloud.huawei.com"
                or parts.path != "/AMW/portal/userCenter/index.html"):
            return state.account_center
        fields = {k: v[-1] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        if not fields.get("ticket"):
            return state.account_center
        fields.update(pageName="webUserCenter", urlParam=parts.query, supportHarmonyTheme="false")
        state.account_center = {"outcome": "incomplete"}
        query = urlencode({"cVersion": state.client._version, "reflushCode": "0." + str(secrets.randbelow(10**16))})
        raw = state.client._request("POST", AMW_PAGE_INFO + "?" + query, urlencode(fields).encode())
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise TypeError
        if str(payload.get("isSuccess")) != "1":
            code = str(payload.get("errorCode", ""))
            state.account_center = {"outcome": "rejected", "remote_code": code if re.fullmatch(r"[0-9]{1,10}", code) else ""}
        else:
            state.account_center_payload = payload
            state.account_center = _account_center_summary(payload)
    except Exception:  # noqa: BLE001 -- Never print private callbacks or payloads.
        state.account_center = {"outcome": "unavailable"}
    return state.account_center


def _follow_account_redirect(state):
    """Follow one server-issued CAS SSO redirect; never resubmit credentials."""
    previous = getattr(state, "account_sso", None)
    if isinstance(previous, dict):
        # Upgrade recovery: the old request failed before transmission because
        # the server-issued URL contained Unicode. Retry with URI encoding once.
        if previous.get("error_type") == "UnicodeEncodeError" and not getattr(state, "sso_uri_retry", False):
            state.sso_uri_retry = True
        else:
            return previous
    state.account_sso = {"outcome": "not_applicable"}
    payload = getattr(state, "account_center_payload", None)
    if not isinstance(payload, dict) or not isinstance(payload.get("redirectUrl"), str):
        return state.account_sso
    try:
        url = unescape(payload["redirectUrl"])
        parts = urlsplit(url)
        if (parts.scheme != "https" or parts.netloc != "id1.cloud.huawei.com"
                or parts.path != "/CAS/remoteLogin"):
            return state.account_sso
        state.account_sso = {"outcome": "incomplete"}
        request = Request(quote(url, safe=":/?&=%@+;,!~*'()[]"), headers={"User-Agent": "Mozilla/5.0", "Referer": "https://id1.cloud.huawei.com/AMW/portal/userCenter/index.html"})
        # This opener carries the same CookieJar and same-host redirect guard.
        with state.client._opener.open(request, timeout=state.client.timeout) as response:
            final_url = response.geturl()
            if len(response.read(MAX_RESPONSE_BYTES + 1)) > MAX_RESPONSE_BYTES:
                raise SmsLoginError("protocol_changed")
        final = urlsplit(final_url)
        if final.scheme != "https" or final.netloc != "id1.cloud.huawei.com":
            raise SmsLoginError("unexpected_redirect")
        if final.path == "/CAS/portal/login.html":
            state.account_sso = {"outcome": "login_required"}
        elif final.path == "/AMW/portal/userCenter/index.html":
            state.account_center_callback = final_url
            state.account_center = None
            state.account_center_payload = None
            state.account_sso = {"outcome": "returned_to_account_center"}
            _initialize_account_center(state)
        else:
            state.account_sso = {"outcome": "unrecognized_destination"}
    except SmsLoginError as error:
        state.account_sso = {"outcome": "unavailable", "reason": error.reason}
    except HTTPError as error:
        state.account_sso = {"outcome": "unavailable", "http_status": error.code}
        error.close()
    except (URLError, TimeoutError, OSError):
        state.account_sso = {"outcome": "unavailable", "reason": "cannot_connect"}
    except Exception as error:  # noqa: BLE001 -- Only fixed class names and source lines.
        state.account_sso = {"outcome": "unavailable", "reason": "unexpected_response"}
        names = {"TypeError", "AttributeError", "ValueError", "UnicodeEncodeError", "NameError", "RuntimeError"}
        state.account_sso["error_type"] = type(error).__name__ if type(error).__name__ in names else "other"
        trace = error.__traceback__
        while trace:
            if trace.tb_frame.f_code.co_filename == __file__:
                state.account_sso["source_line"] = trace.tb_lineno
            trace = trace.tb_next
    return state.account_sso


def _discover(session):
    api = SmartHomeDiscoveryApi(transport=UrllibHttpTransport())
    snapshot = asyncio.run(api.async_get_snapshot(session))
    return {"homes": len(snapshot.homes), "devices": len(snapshot.devices)}


def continue_login(state):
    """Validate explicit candidates, then read devices; no speculative exchange."""
    if state.session is None:
        if state.web_result is None:
            return {"outcome": "login_required"}
        state.bridge_metadata = describe(state.web_result)
        try:
            ticket, user_id = state.web_result.credentials()
        except SmsLoginError:
            state.bridge_metadata["account_probe"] = _probe_account(state)
            state.bridge_metadata["account_center"] = _initialize_account_center(state)
            state.bridge_metadata["account_sso"] = _follow_account_redirect(state)
            state.bridge_metadata["account_center"] = state.account_center
            return {"outcome": "bridge_unverified", "diagnostics": state.bridge_metadata}
        if getattr(state, "authorization_attempted", False):
            return {"outcome": "authorization_failed", "diagnostics": state.bridge_metadata}
        state.authorization_attempted = True
        try:
            provider = HuaweiSmartHomeAuthProvider(
                device_id=uuid.uuid4().hex, device_name="Home Assistant SMS check",
            )
            state.session = provider._finish_login(
                state.client._phone, {"TGC": [ticket], "userID": [user_id]},
            )
        except AuthenticationError:
            return {"outcome": "authorization_failed", "diagnostics": state.bridge_metadata}
    try:
        return {"outcome": "verified", **_discover(state.session)}
    except (SmartHomeApiError, InvalidProtocolDataError, AuthenticationError):
        return {"outcome": "discovery_failed"}
