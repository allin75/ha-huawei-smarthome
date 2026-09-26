"""Exercise actual flow methods with a minimal HA form adapter locally."""

import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from custom_components.huawei_smarthome.auth.interface import LoginChallenge, LoginStart
from custom_components.huawei_smarthome.errors import (
    AuthenticationError,
    InvalidCredentialsError,
)


class FlowBase:
    def __init_subclass__(cls, **kwargs):
        pass

    def async_show_form(self, **kwargs):
        return {"type": "form", **kwargs}

    def async_abort(self, **kwargs):
        return {"type": "abort", **kwargs}


def load_flow():
    modules = {name: ModuleType(name) for name in ["homeassistant", "homeassistant.config_entries", "homeassistant.core", "homeassistant.helpers", "homeassistant.helpers.config_validation"]}
    entries = modules["homeassistant.config_entries"]
    entries.ConfigFlow = entries.OptionsFlow = FlowBase
    entries.ConfigFlowResult = dict
    modules["homeassistant"].config_entries = entries
    modules["homeassistant.core"].callback = lambda f: f
    modules["homeassistant.helpers.config_validation"].multi_select = lambda choices: dict
    path = Path(__file__).parents[1] / "custom_components/huawei_smarthome/config_flow.py"
    spec = importlib.util.spec_from_file_location("custom_components.huawei_smarthome._flow_test", path)
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


class FlowTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.module = load_flow()
        self.flow = self.module.HuaweiSmartHomeConfigFlow()
        self.flow.hass = object()
        self.flow._provider = SimpleNamespace(async_send_sms=AsyncMock(), async_complete_challenge=AsyncMock())
        self.flow._challenge = LoginChallenge("SMS", "", "2", sms=True, needs_send=True)

    async def test_sms_form_does_not_send_until_submitted(self):
        self.assertEqual((await self.flow.async_step_sms())["step_id"], "sms")
        self.flow._provider.async_send_sms.assert_not_called()
        self.flow._provider.async_send_sms.return_value = LoginChallenge("SMS", "", "2", sms=True)
        self.assertEqual((await self.flow.async_step_sms({}))["step_id"], "challenge")
        self.flow._provider.async_send_sms.assert_awaited_once()

    async def test_send_failure_aborts_instead_of_resending(self):
        self.flow._provider.async_send_sms.side_effect = AuthenticationError("private")
        result = await self.flow.async_step_sms({})
        self.assertEqual(result, {"type": "abort", "reason": "sms_failed"})

    async def test_invalid_format_never_calls_native_api(self):
        result = await self.flow.async_step_challenge({"challenge_code": "abc"})
        self.assertEqual(result["errors"], {"base": "invalid_auth"})
        self.flow._provider.async_complete_challenge.assert_not_called()

    async def test_rejection_does_not_show_unusable_retry_form(self):
        self.flow._provider.async_complete_challenge.side_effect = InvalidCredentialsError("private")
        result = await self.flow.async_step_challenge({"challenge_code": "123456"})
        self.assertEqual(result, {"type": "abort", "reason": "challenge_failed"})

    async def test_login_routes_to_sms_and_normalizes_identity_account(self):
        identity = Mock()
        identity.async_get_or_create = AsyncMock(return_value={"device_id": "d", "device_name": "n", "pushtmid": "p", "identity_fingerprint": "f"})
        provider = Mock()
        provider.async_begin_login = AsyncMock(return_value=LoginStart(challenge=self.flow._challenge))
        with patch.object(self.module, "ClientIdentityStore", return_value=identity), patch.object(self.module, "HuaweiSmsAuthProvider", return_value=provider):
            result = await self.flow.async_step_user({"account": "+86 13800000000", "password": "SECRET"})
        self.assertEqual(result["step_id"], "sms")
        identity.async_get_or_create.assert_awaited_once_with("13800000000")
        provider.async_begin_login.assert_awaited_once_with("13800000000", "SECRET")
