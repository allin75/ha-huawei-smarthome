"""Bridge diagnostics must never turn a web login into unverified app success."""

import json
import unittest
from http.cookiejar import Cookie, CookieJar
from types import SimpleNamespace
from unittest.mock import patch

from custom_components.huawei_smarthome.auth.sms import WebLoginResult
from tools import sms_bridge


class BridgeTests(unittest.TestCase):
    def state(self, payload):
        return SimpleNamespace(web_result=WebLoginResult(payload, CookieJar()),
                               client=SimpleNamespace(_phone="13800000000"),
                               session=None, bridge_metadata={})

    def test_diagnostics_expose_names_and_presence_only(self):
        state = self.state({"callbackURL": "https://id1.cloud.huawei.com/AMW/portal/userCenter/index.html?ticket=SECRET&userID=PRIVATE",
                            "userAccount": "13800000000", "data": {"userID": "PRIVATE"}})
        state.web_result.cookies.set_cookie(Cookie(0, "JSESSIONID", "SECRET", None, False,
            "id1.cloud.huawei.com", False, False, "/CAS", True, True, None, True, None, None, {}, False))
        result = sms_bridge.describe(state.web_result)
        text = json.dumps(result)
        for value in ["SECRET", "PRIVATE", "13800000000"]:
            self.assertNotIn(value, text)
        self.assertIn("JSESSIONID", text)
        self.assertIn("ticket", result["callback_query_fields"])
        self.assertFalse(result["explicit_service_ticket"])

    def test_missing_ticket_never_calls_app_or_claims_success(self):
        state = self.state({"isSuccess": 1, "callbackURL": "https://id1.cloud.huawei.com/AMW/portal/userCenter/index.html"})
        with patch.object(sms_bridge, "HuaweiSmartHomeAuthProvider") as provider:
            result = sms_bridge.continue_login(state)
        provider.assert_not_called()
        self.assertEqual(result["outcome"], "bridge_unverified")
        self.assertIsNone(state.session)

    def test_no_login_cannot_continue(self):
        state = self.state({})
        state.web_result = None
        self.assertEqual(sms_bridge.continue_login(state)["outcome"], "login_required")

    def test_unknown_names_cannot_leak_secrets(self):
        state = self.state({"SECRET": "PRIVATE", "callbackURL": "https://id1.cloud.huawei.com/?SECRET=PRIVATE"})
        result = sms_bridge.describe(state.web_result)
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(result["unknown_response_field_count"], 1)
        self.assertEqual(result["unknown_callback_field_count"], 1)

    def test_existing_app_session_is_reused_for_discovery(self):
        state = self.state({})
        session = object()
        state.session = session
        with patch.object(sms_bridge, "HuaweiSmartHomeAuthProvider") as provider, \
             patch.object(sms_bridge, "_discover", return_value={"homes": 2, "devices": 3}) as discover:
            result = sms_bridge.continue_login(state)
        provider.assert_not_called()
        discover.assert_called_once_with(session)
        self.assertEqual(result["outcome"], "verified")

    def test_auth_failure_is_redacted_and_not_retried(self):
        state = self.state({"TGC": "SECRET", "userID": "PRIVATE"})
        with patch.object(sms_bridge, "HuaweiSmartHomeAuthProvider") as provider:
            provider.return_value._finish_login.side_effect = sms_bridge.AuthenticationError("SECRET")
            result = sms_bridge.continue_login(state)
            sms_bridge.continue_login(state)
        self.assertEqual(result["outcome"], "authorization_failed")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertEqual(provider.return_value._finish_login.call_count, 1)


if __name__ == "__main__":
    unittest.main()
