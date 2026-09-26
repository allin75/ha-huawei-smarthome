"""Production provider regression tests using synthetic Huawei responses."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from custom_components.huawei_smarthome.auth.huawei import (
    HuaweiSmartHomeAuthProvider,
    _PendingLogin,
)
from custom_components.huawei_smarthome.auth.interface import LoginChallenge, LoginStart
from custom_components.huawei_smarthome.auth.sms import SmsLoginError
from custom_components.huawei_smarthome.auth.sms_challenge import HuaweiSmsAuthProvider


class ProviderTests(unittest.IsolatedAsyncioTestCase):
    def prepare(self, channels):
        provider = HuaweiSmsAuthProvider(device_id="test", device_name="test")

        def begin(account, password):
            provider._pending = _PendingLogin(account, "CIPHER", "device", "-1")
            provider._login_fields = {"errorDesc": [json.dumps({"authCodeSentList": channels})]}
            return LoginStart(challenge=LoginChallenge("device", "device", "-1"))

        with patch.object(HuaweiSmartHomeAuthProvider, "_begin_login", side_effect=begin):
            result = provider._begin_login("+8613800000000", "SECRET")
        return provider, result

    async def test_sms_preferred_and_one_send_uses_verified_parameters(self):
        provider, start = self.prepare([{"name": "device", "accountType": -1, "sent": 1}, {"name": "138****0000", "accountType": 2, "sent": 0}])
        self.assertTrue(start.challenge.needs_send)
        self.assertEqual(provider._pending.account, "13800000000")
        cas = Mock()
        cas._local = {"service": "test"}
        cas._ajax.side_effect = [{"siteID": "1"}, {"isSuccess": 1}]
        with patch("custom_components.huawei_smarthome.auth.sms_challenge.CasSmsLogin", return_value=cas):
            challenge = await provider.async_send_sms()
            await provider.async_send_sms()
        self.assertFalse(challenge.needs_send)
        self.assertEqual(cas._ajax.call_count, 2)
        self.assertEqual(cas._ajax.call_args.args[1], {"userAccount": "13800000000", "accountType": "2", "mobilePhone": "138****0000", "operType": "8", "smsReqType": "6", "siteID": "1"})

    async def test_dispatch_failure_is_not_retried(self):
        provider, _ = self.prepare([{"name": "phone", "accountType": 6, "sent": 0}])
        cas = Mock()
        cas.initialize.side_effect = SmsLoginError("cannot_connect")
        with patch("custom_components.huawei_smarthome.auth.sms_challenge.CasSmsLogin", return_value=cas):
            for _ in range(2):
                with self.assertRaises(SmsLoginError):
                    await provider.async_send_sms()
        cas.initialize.assert_called_once()

    async def test_sms_completion_uses_same_native_session(self):
        provider, start = self.prepare([{"name": "phone", "accountType": 6, "sent": 1}])
        self.assertTrue(start.challenge.sms)
        self.assertFalse(start.challenge.needs_send)
        session = object()
        with patch.object(provider, "_login_request", return_value=SimpleNamespace(status=200, body=b"resultCode=0&TGC=ticket&userID=user")) as request, patch.object(provider, "_finish_login", return_value=session):
            self.assertIs(await provider.async_complete_challenge("123456"), session)
        self.assertEqual(request.call_args.kwargs["challenge"], ("123456", "phone", "6"))
        self.assertIsNone(provider._pending)

    async def test_expiry_stops_network_and_clears_pending(self):
        provider, _ = self.prepare([{"name": "phone", "accountType": 2, "sent": 1}])
        provider._expires = 0
        with patch.object(provider, "_login_request") as request, self.assertRaises(SmsLoginError):
            await provider.async_complete_challenge("123456")
        request.assert_not_called()
        self.assertIsNone(provider._pending)

    async def test_existing_device_fallback_is_preserved(self):
        _, start = self.prepare([{"name": "device", "accountType": -1, "sent": 1}])
        self.assertFalse(start.challenge.sms)
        self.assertEqual(start.challenge.prompt, "device")
