"""Native challenge selection and bounded SMS experiments, no cloud traffic."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from custom_components.huawei_smarthome.auth.interface import LoginStart
from custom_components.huawei_smarthome.auth.sms import SmsLoginError
from custom_components.huawei_smarthome.errors import AuthenticationError
from tools import native_sms


class NativeTests(unittest.TestCase):
    def state(self, channels):
        state = native_sms.NativeState()
        provider = Mock()
        provider.last_fields = {"resultCode": ["70002058"], "errorDesc": [json.dumps({"authCodeSentList": channels})]}
        provider._pending = SimpleNamespace(account="13800000000", encrypted_password="CIPHER", challenge_name="device", challenge_type="-1")
        provider._begin_login.return_value = LoginStart()
        state.provider_factory = Mock(return_value=provider)
        state.clock = Mock(return_value=100)
        return state, provider

    def test_selects_offered_sms_over_already_sent_device(self):
        state, provider = self.state([{"name": "device", "accountType": -1, "sent": 1}, {"name": "138****0000", "accountType": 6, "sent": 0}])
        result = native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        self.assertEqual(result["outcome"], "sms_available")
        self.assertEqual(state.channel["account_type"], "6")
        self.assertNotIn("138", json.dumps(result))
        self.assertNotIn("SECRET", json.dumps(result))
        provider._login_request.assert_not_called()

    def test_no_sms_does_not_guess_a_channel(self):
        state, _ = self.state([{"name": "device", "accountType": -1, "sent": 1}])
        result = native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        self.assertEqual(result["outcome"], "sms_unavailable")
        self.assertFalse(result["can_send"])

    def test_password_data_cleared_even_on_failure(self):
        state, provider = self.state([])
        provider._begin_login.side_effect = SmsLoginError("cannot_connect")
        data = {"phone": "13800000000", "password": "SECRET"}
        result = native_sms.perform(state, "/begin", data)
        self.assertNotIn("password", data)
        self.assertNotIn("SECRET", json.dumps(result))

    def test_dispatch_is_single_attempt_in_same_cas_session(self):
        state, _ = self.state([{"name": "138****0000", "accountType": 2, "sent": 0}])
        native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        cas = Mock()
        cas._local = {"service": "https://id1.cloud.huawei.com/AMW/portal/userCenter/index.html"}
        cas._ajax.side_effect = [{"siteID": "1"}, {"isSuccess": 1}]
        with patch.object(native_sms, "CasSmsLogin", return_value=cas):
            result = native_sms.perform(state, "/send", {})
            native_sms.perform(state, "/send", {})
        self.assertEqual(result["outcome"], "sent")
        self.assertEqual(cas._ajax.call_count, 2)
        self.assertEqual(cas._ajax.call_args.args[0], "getSMSCodeV3")
        self.assertEqual(cas._ajax.call_args.args[1]["operType"], "8")
        self.assertEqual(cas._ajax.call_args.args[1]["smsReqType"], "6")
        cas.initialize.assert_called_once()

    def test_failed_send_is_not_repeated(self):
        state, _ = self.state([{"name": "138****0000", "accountType": 2, "sent": 0}])
        native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        cas = Mock()
        cas.initialize.side_effect = SmsLoginError("cannot_connect")
        with patch.object(native_sms, "CasSmsLogin", return_value=cas):
            result = native_sms.perform(state, "/send", {})
            native_sms.perform(state, "/send", {})
        self.assertFalse(result["can_send"])
        cas.initialize.assert_called_once()

    def test_expired_challenge_never_sends_or_submits(self):
        state, provider = self.state([{"name": "138****0000", "accountType": 2, "sent": 1}])
        native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        state.clock.return_value = 1000
        result = native_sms.perform(state, "/verify", {"code": "123456"})
        self.assertEqual(result["outcome"], "session_expired")
        provider._login_request.assert_not_called()
        self.assertIsNone(provider._pending)

    def test_code_goes_back_to_native_flow_and_requires_device_read(self):
        state, provider = self.state([{"name": "138****0000", "accountType": 6, "sent": 1}])
        native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        provider._login_request.return_value = SimpleNamespace(status=200, body=b"resultCode=0&TGC=TICKET&userID=PRIVATE")
        session = object()
        provider._finish_login.return_value = session
        with patch.object(native_sms, "_discover", return_value={"homes": 1, "devices": 2}):
            result = native_sms.perform(state, "/verify", {"code": "123456"})
        self.assertEqual(result["outcome"], "verified")
        self.assertEqual(provider._login_request.call_args.kwargs["challenge"], ("123456", "138****0000", "6"))
        self.assertIs(state.session, session)
        self.assertIsNone(provider._pending)

    def test_password_login_is_throttled_even_after_failure(self):
        state, provider = self.state([])
        provider._pending = None
        provider._begin_login.side_effect = SmsLoginError("cannot_connect")
        native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        result = native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        self.assertEqual(result["outcome"], "rate_limited")
        provider._begin_login.assert_called_once()

    def test_rejected_challenge_stops_replays_and_redacts_response(self):
        state, provider = self.state([{"name": "138****0000", "accountType": 6, "sent": 1}])
        native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        provider._login_request.return_value = SimpleNamespace(status=200, body=b"resultCode=70001201&errorDesc=SECRET")
        result = native_sms.perform(state, "/verify", {"code": "123456"})
        native_sms.perform(state, "/verify", {"code": "123456"})
        self.assertEqual(result["outcome"], "challenge_rejected")
        self.assertFalse(result["can_verify"])
        self.assertFalse(result["can_send"])
        self.assertNotIn("SECRET", json.dumps(result))
        provider._login_request.assert_called_once()

    def test_authorized_session_survives_discovery_failure(self):
        state, provider = self.state([])
        session = object()
        provider._pending = None
        provider._begin_login.return_value = LoginStart(session=session)
        with patch.object(native_sms, "_discover", side_effect=AuthenticationError("SECRET")):
            result = native_sms.perform(state, "/begin", {"phone": "13800000000", "password": "SECRET"})
        self.assertEqual(result["outcome"], "discovery_failed")
        self.assertNotIn("SECRET", json.dumps(result))
        with patch.object(native_sms, "_discover", return_value={"homes": 0, "devices": 0}):
            self.assertEqual(native_sms.perform(state, "/continue", {})["outcome"], "verified")
        provider._begin_login.assert_called_once()


if __name__ == "__main__":
    unittest.main()
