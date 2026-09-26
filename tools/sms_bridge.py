"""Reloadable local authorization check. Never serialize authentication values."""

import asyncio
import uuid
from urllib.parse import parse_qs, urlsplit

from custom_components.huawei_smarthome.api.client import SmartHomeDiscoveryApi
from custom_components.huawei_smarthome.api.errors import SmartHomeApiError
from custom_components.huawei_smarthome.api.transport import UrllibHttpTransport
from custom_components.huawei_smarthome.auth.huawei import HuaweiSmartHomeAuthProvider
from custom_components.huawei_smarthome.auth.sms import SmsLoginError
from custom_components.huawei_smarthome.errors import (
    AuthenticationError,
    InvalidProtocolDataError,
)

# Only known protocol names are emitted; even unknown key names may contain PII.
FIELD_NAMES = frozenset({"TGC", "userID", "userAccount", "callbackURL", "data", "isSuccess", "resultCode", "errorCode", "errorDesc", "ticket", "service", "code", "state"})
COOKIE_NAMES = frozenset({"TGC", "userID", "JSESSIONID", "HWCAS", "HWCAS_ID", "HWCAS_TGC", "CASLOGINSITE", "hwid_cas_sid"})


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
        "explicit_service_ticket": candidate,
    }


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
