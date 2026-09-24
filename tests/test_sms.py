"""Protocol and failure-path tests; no live accounts or SMS messages."""

import json
import unittest
from urllib.parse import parse_qs

from custom_components.huawei_smarthome.auth.sms import CasSmsLogin, SmsLoginError


class FakeWeb:
    def __init__(self):
        self.calls = []
        self.risk = {"isSuccess": 1, "siteID": "1", "lowLogin": "0"}
        self.send = {"isSuccess": 1}
        self.login = {"isSuccess": 1, "TGC": "test-ticket", "userID": "test-user"}

    def __call__(self, method, url, data=None):
        self.calls.append((method, url, parse_qs(data.decode()) if data else {}))
        if method == "GET":
            return b'<script src="/CAS/jsconfig/hwidConfig.js?cVersion=UP_CAS_TEST"></script>'
        if "getPageInfo" in url:
            value = {
                "isSuccess": 1, "pageToken": "test-page", "pageTokenKey": "test-key",
                "localStorageID": "test-storage",
                "localInfo": {"reqClientType": "7", "loginChannel": "7000000",
                    "lang": "zh-cn", "service": "https://id1.cloud.huawei.com/AMW/portal/userCenter/index.html",
                    "localHttpsAjaxPath": "https://id1.cloud.huawei.com/CAS/IDM_W",
                    "isOpenSMSLogin": True, "regionCode": "cn"},
            }
        elif "chkRisk" in url:
            value = self.risk
        elif "getSMSCodeV3" in url:
            value = self.send
        else:
            value = self.login
        return json.dumps(value).encode()


class SmsTests(unittest.TestCase):
    def setUp(self):
        self.web = FakeWeb()
        self.now = 1000.0
        self.client = CasSmsLogin(request=self.web, clock=lambda: self.now)

    def test_passwordless_protocol_and_page_context(self):
        self.client.send_code("13800000000")
        result = self.client.complete("123456")
        self.assertEqual(result.credentials(), ("test-ticket", "test-user"))
        forms = [c[2] for c in self.web.calls]
        self.assertEqual(forms[2]["operType"], ["11"])
        self.assertEqual(forms[3]["operType"], ["20"])
        self.assertEqual(forms[3]["smsReqType"], ["2"])
        self.assertEqual(forms[3]["mobilePhone"], ["008613800000000"])
        self.assertEqual(forms[3]["pageToken"], ["test-page"])
        self.assertEqual(forms[3]["localStorageID"], ["test-storage"])
        self.assertEqual(forms[4]["opType"], ["11"])
        self.assertEqual(forms[4]["smsAuthCode"], ["123456"])
        self.assertFalse(any("password" in f or "pw" in f for f in forms))

    def test_captcha_stops_before_sending_sms(self):
        self.web.risk["isNeedImageCode"] = "1"
        with self.assertRaisesRegex(SmsLoginError, "captcha_required"):
            self.client.send_code("13800000000")
        self.assertFalse(any("getSMSCodeV3" in c[1] for c in self.web.calls))

    def test_resend_throttled_even_when_phone_changes(self):
        self.client.send_code("13800000000")
        with self.assertRaisesRegex(SmsLoginError, "rate_limited"):
            self.client.send_code("13900000000")
        self.now += 61
        self.client.send_code("13900000000")

    def test_wrong_code_can_be_retried_without_resending(self):
        self.client.send_code("13800000000")
        self.web.login = {"isSuccess": 0, "errorCode": "10000402", "errorDesc": "secret"}
        with self.assertRaisesRegex(SmsLoginError, "invalid_code") as cm:
            self.client.complete("000000")
        self.assertNotIn("secret", str(cm.exception))
        self.web.login = {"isSuccess": 1, "TGC": "test-ticket", "userID": "test-user"}
        self.assertEqual(self.client.complete("123456").credentials()[1], "test-user")

    def test_expired_local_session_never_submits_code(self):
        self.client.send_code("13800000000")
        self.now += 601
        with self.assertRaisesRegex(SmsLoginError, "session_expired"):
            self.client.complete("123456")
        self.assertEqual(len(self.web.calls), 4)

    def test_no_code_submission_before_successful_send(self):
        self.web.send = {"isSuccess": 0, "errorCode": "70002057"}
        with self.assertRaises(SmsLoginError):
            self.client.send_code("13800000000")
        with self.assertRaisesRegex(SmsLoginError, "session_expired"):
            self.client.complete("123456")

    def test_reject_invalid_phone_and_code_locally(self):
        for phone in ["", "alice@example.com", "123", "13800000000&x=y"]:
            with self.assertRaisesRegex(SmsLoginError, "invalid_phone"):
                self.client.send_code(phone)
        self.assertEqual(self.web.calls, [])
        self.client.send_code("+86 13800000000")
        with self.assertRaisesRegex(SmsLoginError, "invalid_code"):
            self.client.complete("abcdef")

    def test_success_without_service_ticket_is_not_full_auth(self):
        self.web.login = {"isSuccess": 1, "callbackURL": "https://id1.cloud.huawei.com/AMW/portal/userCenter/index.html"}
        self.client.send_code("13800000000")
        with self.assertRaisesRegex(SmsLoginError, "bridge_unverified"):
            self.client.complete("123456").credentials()

    def test_cross_origin_callback_is_never_followed(self):
        self.web.login = {"isSuccess": 1, "callbackURL": "https://example.com/steal"}
        self.client.send_code("13800000000")
        with self.assertRaisesRegex(SmsLoginError, "unexpected_redirect"):
            self.client.complete("123456")
        self.assertFalse(any("example.com" in c[1] for c in self.web.calls))

    def test_success_is_consumed_and_requires_new_code(self):
        self.client.send_code("13800000000")
        self.client.complete("123456")
        with self.assertRaisesRegex(SmsLoginError, "session_expired"):
            self.client.complete("123456")

    def test_additional_verification_is_distinct_and_redacted(self):
        self.client.send_code("13800000000")
        self.web.login = {"isSuccess": 0, "errorCode": "10012072", "errorDesc": json.dumps({
            "isDoubleVerification": True, "extInfo": "private-ticket",
            "twoFactorList": [{"factorType": "5", "name": "private-name"},
                              {"factorType": "3", "anonymousValue": "private-email"}],
        })}
        with self.assertRaisesRegex(SmsLoginError, "additional_verification"):
            self.client.complete("123456")
        summary = self.client.verification_summary
        self.assertEqual(summary["methods"], ["password", "email"])
        self.assertTrue(summary["double_verification"])
        self.assertNotIn("private", json.dumps(summary))
        calls = len(self.web.calls)
        with self.assertRaisesRegex(SmsLoginError, "additional_verification"):
            self.client.complete("123456")
        self.assertEqual(len(self.web.calls), calls)

    def test_verification_error_codes_do_not_assume_password(self):
        for code in ["10002080", "10012072", "10012076"]:
            with self.subTest(code=code):
                client = CasSmsLogin(request=self.web)
                client.send_code("13800000000")
                self.web.login = {"isSuccess": 0, "errorCode": code,
                    "errorDesc": json.dumps({"twoFactorList": [{"factorType": "2"}]})}
                with self.assertRaisesRegex(SmsLoginError, "additional_verification"):
                    client.complete("123456")
                self.assertEqual(client.verification_summary["methods"], ["phone"])

    def test_malformed_verification_details_remain_safe(self):
        for value in ["not-json", "null", "[]", '{"twoFactorList":"private-value"}']:
            client = CasSmsLogin(request=self.web)
            client.send_code("13800000000")
            self.web.login = {"isSuccess": 0, "errorCode": "10012072", "errorDesc": value}
            with self.assertRaisesRegex(SmsLoginError, "additional_verification"):
                client.complete("123456")
            self.assertEqual(client.verification_summary["methods"], [])

    def password_challenge(self):
        self.client.send_code("13800000000")
        self.web.login = {"isSuccess": 0, "errorCode": "10012072", "errorDesc": json.dumps({
            "twoFactorList": [{"factorType": "5"}], "isNotTrustBrowserVerify": True,
        })}
        with self.assertRaises(SmsLoginError):
            self.client.complete("123456")

    def test_password_continues_same_sms_session(self):
        self.password_challenge()
        self.web.login = {"isSuccess": 1, "TGC": "ticket", "userID": "user"}
        self.assertEqual(self.client.complete_password("test-password").credentials(), ("ticket", "user"))
        form = self.web.calls[-1][2]
        self.assertEqual(form["twoFactorType"], ["5"])
        self.assertEqual(form["twoFactorValue"], ["test-password"])
        self.assertEqual(form["smsAuthCode"], ["123456"])
        self.assertEqual(form["pageToken"], ["test-page"])
        self.assertFalse(self.client._sms_code)
        self.assertNotIn("test-password", repr(vars(self.client)))

    def test_password_wrong_can_retry_but_is_bounded(self):
        self.password_challenge()
        self.web.login = {"isSuccess": 0, "errorCode": "11000400"}
        for _ in range(3):
            with self.assertRaisesRegex(SmsLoginError, "invalid_password"):
                self.client.complete_password("wrong")
        calls = len(self.web.calls)
        with self.assertRaisesRegex(SmsLoginError, "rate_limited"):
            self.client.complete_password("wrong")
        self.assertEqual(calls, len(self.web.calls))

    def test_password_requires_live_server_offered_challenge(self):
        with self.assertRaisesRegex(SmsLoginError, "session_expired"):
            self.client.complete_password("secret")
        self.password_challenge()
        with self.assertRaisesRegex(SmsLoginError, "invalid_password"):
            self.client.complete_password("")
        self.now += 601
        with self.assertRaisesRegex(SmsLoginError, "session_expired"):
            self.client.complete_password("secret")
        self.assertFalse(self.client._sms_code)


if __name__ == "__main__":
    unittest.main()
