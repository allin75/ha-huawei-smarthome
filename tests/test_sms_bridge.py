"""Bridge diagnostics must never turn a web login into unverified app success."""

import json
import unittest
from http.cookiejar import Cookie, CookieJar
from types import SimpleNamespace
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

from custom_components.huawei_smarthome.auth.sms import SmsLoginError, WebLoginResult
from tools import sms_bridge


class BridgeTests(unittest.TestCase):
    def state(self, payload):
        return SimpleNamespace(web_result=WebLoginResult(payload, CookieJar()),
                               client=SimpleNamespace(_phone="13800000000", _ajax=Mock(return_value={"isSuccess": 1})),
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

    def test_account_center_consumes_callback_only_at_fixed_endpoint_once(self):
        state = self.state({"callbackURL": "https://id1.cloud.huawei.com/AMW/portal/userCenter/index.html?ticket=SECRET&lang=zh-cn"})
        state.client._version = "test-version"
        state.client._request = Mock(return_value=json.dumps({"isSuccess": 1, "localInfo": {"userID": "PRIVATE"}}).encode())
        result = sms_bridge.continue_login(state)
        sms_bridge.continue_login(state)
        state.client._request.assert_called_once()
        method, url, data = state.client._request.call_args.args
        self.assertEqual(method, "POST")
        self.assertEqual(url.split('?')[0], "https://id1.cloud.huawei.com/AMW/ajaxHandler/common/getPageInfo")
        fields = parse_qs(data.decode())
        self.assertEqual(fields["ticket"], ["SECRET"])
        self.assertEqual(fields["pageName"], ["webUserCenter"])
        self.assertEqual(result["diagnostics"]["account_center"]["outcome"], "initialized")
        self.assertNotIn("SECRET", json.dumps(result))
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertIsNone(state.session)

    def test_account_center_rejects_untrusted_callback_without_request(self):
        state = self.state({"callbackURL": "https://evil.test/AMW/portal/userCenter/index.html?ticket=SECRET"})
        state.client._request = Mock()
        sms_bridge.continue_login(state)
        state.client._request.assert_not_called()

    def test_remote_sso_is_bounded_and_stops_at_login_page(self):
        state = self.state({})
        state.account_center_payload = {"redirectUrl": "https://id1.cloud.huawei.com/CAS/remoteLogin?service=PRIVATE&label=华为"}
        response = Mock()
        response.geturl.return_value = "https://id1.cloud.huawei.com/CAS/portal/login.html?service=PRIVATE"
        response.read.return_value = b"<html></html>"
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        state.client._opener = Mock()
        state.client._opener.open.return_value = context
        state.client.timeout = 20
        result = sms_bridge._follow_account_redirect(state)
        sms_bridge._follow_account_redirect(state)
        state.client._opener.open.assert_called_once()
        actual_url = state.client._opener.open.call_args.args[0].full_url
        self.assertTrue(actual_url.isascii())
        self.assertIn("%E5%8D%8E%E4%B8%BA", actual_url)
        self.assertEqual(result["outcome"], "login_required")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_remote_sso_does_not_follow_external_or_logout_url(self):
        for url in ["https://evil.test/CAS/remoteLogin", "https://id1.cloud.huawei.com/CAS/logout"]:
            state = self.state({})
            state.account_center_payload = {"redirectUrl": url}
            state.client._opener = Mock()
            sms_bridge._follow_account_redirect(state)
            state.client._opener.open.assert_not_called()

    def test_redirect_response_is_not_account_center_success(self):
        result = sms_bridge._account_center_summary({"isSuccess": 1, "redirectUrl": "https://id1.cloud.huawei.com/CAS/remoteLogin?service=SECRET"})
        self.assertEqual(result["outcome"], "redirect_required")
        self.assertFalse(result["has_page_token"])
        self.assertNotIn("SECRET", json.dumps(result))

    def test_transport_failure_is_cached_without_repeated_requests(self):
        state = self.state({})
        state.account_center_payload = {"redirectUrl": "https://id1.cloud.huawei.com/CAS/remoteLogin?service=PRIVATE"}
        state.client._opener = Mock()
        state.client._opener.open.side_effect = TimeoutError("PRIVATE")
        state.client.timeout = 20
        result = sms_bridge._follow_account_redirect(state)
        sms_bridge._follow_account_redirect(state)
        state.client._opener.open.assert_called_once()
        self.assertEqual(result["reason"], "cannot_connect")
        self.assertNotIn("PRIVATE", json.dumps(result))

    def test_account_probe_is_read_only_once_and_redacted(self):
        state = self.state({"isSuccess": 1})
        state.client._ajax.return_value = {"isSuccess": 1, "userID": "PRIVATE", "userAccount": "13800000000"}
        result = sms_bridge.continue_login(state)
        sms_bridge.continue_login(state)
        state.client._ajax.assert_called_once_with("getUserAccInfo", {})
        self.assertEqual(result["diagnostics"]["account_probe"]["outcome"], "responded")
        self.assertIn("userID", result["diagnostics"]["account_probe"]["response_fields"])
        self.assertNotIn("PRIVATE", json.dumps(result))
        self.assertNotIn("13800000000", json.dumps(result))
        self.assertEqual(result["outcome"], "bridge_unverified")

    def test_failed_probe_does_not_retry_or_lose_web_login(self):
        state = self.state({"isSuccess": 1})
        original = state.web_result
        state.client._ajax.side_effect = SmsLoginError("session_expired", remote_code="10000600")
        result = sms_bridge.continue_login(state)
        sms_bridge.continue_login(state)
        self.assertEqual(state.client._ajax.call_count, 1)
        self.assertEqual(result["diagnostics"]["account_probe"]["remote_code"], "10000600")
        self.assertIs(state.web_result, original)

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
