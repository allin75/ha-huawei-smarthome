"""Cookie isolation and local interactive endpoint tests, without cloud traffic."""

import json
import re
import threading
import unittest
from email.message import Message
from http.cookiejar import CookieJar
from unittest.mock import Mock
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from custom_components.huawei_smarthome.auth.sms import (
    CAS_LOGIN,
    CasSmsLogin,
    SmsLoginError,
    WebLoginResult,
    _SameOriginRedirects,
)
from tools.sms_login_check import LoginCheck, make_server


class CookieTests(unittest.TestCase):
    def test_repeated_set_cookie_and_scope(self):
        client = CasSmsLogin()
        headers = Message()
        headers.add_header("Set-Cookie", "JSESSIONID=one; Path=/CAS; Secure")
        headers.add_header("Set-Cookie", "TGC=two; Path=/CAS; Secure")
        headers.add_header("Set-Cookie", "userID=test-user; Path=/CAS; Secure")
        response = Mock()
        response.info.return_value = headers
        client.cookies.extract_cookies(response, Request(CAS_LOGIN))
        self.assertEqual(len(client.cookies), 3)
        result = WebLoginResult({}, client.cookies)
        self.assertEqual(result.credentials(), ("two", "test-user"))
        for url in ["https://example.com/CAS/login", "http://id1.cloud.huawei.com/CAS/login", "https://id1.cloud.huawei.com/other"]:
            request = Request(url)
            client.cookies.add_cookie_header(request)
            self.assertIsNone(request.get_header("Cookie"))

    def test_transport_blocks_unsafe_redirect_before_following(self):
        redirect = _SameOriginRedirects()
        for url in ["http://id1.cloud.huawei.com/CAS/login", "https://example.com/CAS/login", "https://id1.cloud.huawei.com.evil.test/CAS/login"]:
            with self.assertRaisesRegex(SmsLoginError, "unexpected_redirect"):
                redirect.redirect_request(Request(CAS_LOGIN), None, 302, "", {}, url)


class ContinuationTests(unittest.TestCase):
    def test_reload_preserves_login_and_never_resends_sms(self):
        check = LoginCheck()
        check.client = Mock(retry_after=0, stage="loginBySMS")
        check.web_result = WebLoginResult({"isSuccess": 1}, CookieJar())
        original = check.web_result
        first = check.act("/continue", {})
        self.assertEqual(first["outcome"], "bridge_unverified")
        self.assertIn("diagnostics", first)
        check.act("/continue", {})
        check.act("/send", {"phone": "13800000000"})
        self.assertIs(check.web_result, original)
        check.client.send_code.assert_not_called()
        check.client.complete.assert_not_called()


class LocalServerTests(unittest.TestCase):
    def setUp(self):
        self.check = Mock()
        self.check.status = {"outcome": "ready"}
        self.check.act.return_value = {"outcome": "sent"}
        self.server = make_server(check=self.check)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        with urlopen(self.url) as response:
            self.html = response.read().decode()
            self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.csrf = re.search(r"const csrf='([^']+)'", self.html).group(1)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def test_valid_local_submit_calls_protocol_once(self):
        request = Request(self.url + "/send", data=json.dumps({"phone": "13800000000"}).encode(), headers={"Origin": self.url, "X-Local-CSRF": self.csrf})
        with urlopen(request) as response:
            self.assertEqual(json.load(response)["outcome"], "sent")
        self.check.act.assert_called_once_with("/send", {"phone": "13800000000"})

    def test_cross_origin_and_missing_csrf_cannot_trigger_sms(self):
        for headers in [{"Origin": "https://evil.test", "X-Local-CSRF": self.csrf}, {"Origin": self.url}]:
            with self.assertRaises(HTTPError) as cm:
                urlopen(Request(self.url + "/send", data=b'{}', headers=headers))
            self.assertEqual(cm.exception.code, 403)
            cm.exception.close()
        self.check.act.assert_not_called()

    def test_continue_requires_same_origin_and_csrf(self):
        with self.assertRaises(HTTPError) as cm:
            urlopen(Request(self.url + "/continue", data=b'{}'))
        self.assertEqual(cm.exception.code, 403)
        cm.exception.close()
        self.check.act.assert_not_called()
        with urlopen(Request(self.url + "/continue", data=b'{}', headers={"Origin": self.url, "X-Local-CSRF": self.csrf})) as response:
            self.assertEqual(response.status, 200)
        self.check.act.assert_called_once_with("/continue", {})

    def test_native_begin_uses_same_local_protections(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.server = make_server(check=self.check, paths=("/begin",))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        with urlopen(self.url) as response:
            csrf = re.search(r"const csrf='([^']+)'", response.read().decode()).group(1)
        with self.assertRaises(HTTPError) as cm:
            urlopen(Request(self.url + "/begin", data=b'{}'))
        self.assertEqual(cm.exception.code, 403)
        cm.exception.close()
        self.check.act.assert_not_called()
        with urlopen(Request(self.url + "/begin", data=b'{}', headers={"Origin": self.url, "X-Local-CSRF": csrf})) as response:
            self.assertEqual(response.status, 200)
        self.check.act.assert_called_once_with("/begin", {})

    def test_reject_host_rebinding_and_oversized_input(self):
        with self.assertRaises(HTTPError) as cm:
            urlopen(Request(self.url, headers={"Host": "evil.test"}))
        self.assertEqual(cm.exception.code, 403)
        cm.exception.close()
        with self.assertRaises(HTTPError) as cm:
            urlopen(Request(self.url + "/send", data=b'x' * 1025, headers={"Origin": self.url, "X-Local-CSRF": self.csrf}))
        self.assertEqual(cm.exception.code, 400)
        cm.exception.close()
        self.check.act.assert_not_called()

    def test_status_contains_no_credentials(self):
        with urlopen(self.url + "/status") as response:
            self.assertEqual(json.load(response), {"outcome": "ready"})


if __name__ == "__main__":
    unittest.main()
