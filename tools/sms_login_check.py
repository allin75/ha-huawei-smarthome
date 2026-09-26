"""Local-only interactive SMS check. No account, code or ticket is written out.

Run from the repository root: .venv/bin/python tools/sms_login_check.py
The production Home Assistant instance is never modified by this tool.
"""

from __future__ import annotations

import argparse
import importlib
import json
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from custom_components.huawei_smarthome.auth.sms import CasSmsLogin, SmsLoginError
from tools import sms_bridge

MESSAGES = {
    "ready": "准备好了。请输入绑定华为账号的中国大陆手机号。",
    "login_required": "请先通过短信和华为要求的二次验证登录。",
    "sent": "验证码已发送，请输入收到的六位数字。",
    "checking": "正在验证短信并检查智慧生活授权，请稍候。",
    "verified": "短信登录和智慧生活设备读取验证成功。可以返回 Codex 继续安装。",
    "invalid_phone": "请输入正确的中国大陆手机号（+86）。",
    "invalid_code": "验证码不正确，请核对后重试。",
    "invalid_password": "密码校验未通过，请核对华为账号密码后重试。",
    "password_locked": "华为已限制密码验证，请稍后重新登录，暂时不要重复尝试。",
    "code_expired": "验证码已过期，请重新获取。",
    "session_expired": "登录会话已过期，请重新获取验证码。",
    "rate_limited": "请求过于频繁，请稍后再试。不要连续点击获取验证码。",
    "captcha_required": "华为要求图形或滑块验证。请返回 Codex，我会继续处理浏览器验证入口。",
    "additional_verification": "华为在短信登录后要求额外身份验证。当前验证码不能代替该步骤，请返回 Codex 继续处理。",
    "password_required": "华为对当前账号要求密码登录，请返回 Codex 查看替代方案。",
    "sms_unavailable": "华为未向当前账号或入口开放短信登录。",
    "unsupported_region": "当前仅验证中国大陆站点，账号返回了其他站点。",
    "unexpected_redirect": "登录要求跳转到另一站点，已停止。请返回 Codex 继续核对。",
    "protocol_changed": "华为返回的数据与当前登录协议不同，请返回 Codex。",
    "cannot_connect": "暂时无法连接华为，请稍后再试。",
    "huawei_rejected": "华为拒绝了本次请求。错误编号已记录，返回 Codex 即可继续检查。",
    "bridge_unverified": "网页登录成功，但尚未取得智慧生活所需的票据。请返回 Codex 继续处理授权衔接。",
    "authorization_failed": "网页登录成功，但智慧生活授权尚未完成。请返回 Codex 继续处理。",
    "discovery_failed": "智慧生活授权已完成，但家庭或设备读取失败。请返回 Codex。",
    "unexpected_error": "本地检查遇到问题，请返回 Codex。未保存你的手机号或验证码。",
}

HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>华为短信登录验证</title>
<style>
body{margin:0;background:#f4f6fa;color:#172333;font:16px/1.65 system-ui,sans-serif}
main{max-width:480px;margin:7vh auto;padding:30px;background:white;border-radius:18px;box-shadow:0 8px 40px #17233310}
h1{font-size:25px;margin:0 0 12px}p{color:#576579}label{display:block;margin:20px 0 6px;font-weight:600}
input,button{box-sizing:border-box;font:inherit;border-radius:9px;padding:12px;width:100%}
input{border:1px solid #bdc7d4;background:#fff}button{border:0;background:#2161d9;color:#fff;margin-top:14px;cursor:pointer}
button:disabled{background:#9baecb;cursor:wait}#result{padding:16px;background:#eef4ff;border-radius:9px;margin-top:20px;white-space:pre-line}
.note{font-size:13px}a{color:#2161d9} @media(max-width:540px){main{margin:20px 12px;padding:22px}}
</style><main><h1>华为短信登录验证</h1>
<p>先用短信登录华为账号；若华为要求密码二次验证，下方会显示密码框。</p>
<form id="phoneForm"><label for="phone">手机号（中国大陆 +86）</label>
<input id="phone" type="tel" inputmode="tel" autocomplete="off" placeholder="请输入手机号" required>
<button id="send" type="submit">获取短信验证码</button></form>
<form id="codeForm" hidden><label for="code">短信验证码</label>
<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
<button id="verify" type="submit">验证并检查智慧生活连接</button></form>
<form id="passwordForm" hidden><label for="password">华为账号密码（二次验证）</label>
<input id="password" type="password" autocomplete="off" maxlength="256" required>
<button id="verifyPassword" type="submit">提交密码并继续</button></form>
<button id="continueCheck" type="button" hidden>继续检查智慧生活连接</button>
<div id="result" role="status" aria-live="polite">准备好了。请输入绑定华为账号的手机号。</div>
<p class="note">这是仅在本机运行的测试页。手机号、验证码、密码和登录票据不写入文件或日志，也不会修改 Home Assistant。密码仅通过 HTTPS 发送给华为验证。</p>
</main><script>
const csrf='__CSRF__';let busy=false,until=0,verificationPending=false;
const phone=document.querySelector('#phone'),code=document.querySelector('#code');
const send=document.querySelector('#send'),verify=document.querySelector('#verify'),result=document.querySelector('#result');
const password=document.querySelector('#password'),verifyPassword=document.querySelector('#verifyPassword');
const continueCheck=document.querySelector('#continueCheck');
let passwordBlocked=false,webLoggedIn=false;
function buttons(){let seconds=Math.max(0,Math.ceil((until-Date.now())/1000));send.disabled=busy||seconds>0||verificationPending||webLoggedIn;verify.disabled=busy||verificationPending;verifyPassword.disabled=busy||passwordBlocked;continueCheck.disabled=busy;phone.disabled=busy||!document.querySelector('#codeForm').hidden;send.textContent=seconds?seconds+' 秒后可重新获取':'获取短信验证码';}
async function submit(path,data){if(busy)return;busy=true;buttons();result.textContent=path==='/send'?'正在请求验证码，请稍候。':'正在验证并检查智慧生活授权，请稍候。';try{
let r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Local-CSRF':csrf},body:JSON.stringify(data)});let s=await r.json();render(s);
}catch(e){result.textContent='本机测试服务连接中断，请返回 Codex。';}finally{code.value='';password.value='';busy=false;buttons();}}
function render(s){result.textContent=s.message+(s.remote_code?'（华为错误编号 '+s.remote_code+'）':'');until=Date.now()+(s.retry_after||0)*1000;
if(s.outcome==='sent'){document.querySelector('#codeForm').hidden=false;code.focus();}
if(s.outcome==='additional_verification'){verificationPending=true;const labels={identity:'实名信息',phone:'手机验证',email:'邮箱验证',password:'密码验证'};const methods=s.verification?.methods||[];if(methods.length)result.textContent+=String.fromCharCode(10)+'华为返回的验证方式：'+methods.map(m=>labels[m]).filter(Boolean).join('、');if(s.verification?.double_verification)result.textContent+=String.fromCharCode(10)+'华为启用了双重验证，官方网页会要求进一步验证密码。';}
if(['additional_verification','invalid_password','password_locked'].includes(s.outcome)&&(s.verification?.methods||[]).includes('password')){verificationPending=true;document.querySelector('#codeForm').hidden=true;document.querySelector('#passwordForm').hidden=false;if(s.outcome==='additional_verification')result.textContent='华为要求确认账号密码，请在下方输入并提交。';password.focus();}
if(['password_locked','rate_limited'].includes(s.outcome)&&verificationPending){passwordBlocked=true;}
if(s.outcome==='session_expired'){verificationPending=false;document.querySelector('#passwordForm').hidden=true;document.querySelector('#codeForm').hidden=true;}
if(['verified','bridge_unverified','authorization_failed','discovery_failed'].includes(s.outcome)){webLoggedIn=true;document.querySelector('#phoneForm').hidden=true;document.querySelector('#codeForm').hidden=true;document.querySelector('#passwordForm').hidden=true;continueCheck.hidden=!['bridge_unverified','discovery_failed'].includes(s.outcome);}
buttons();}
document.querySelector('#phoneForm').addEventListener('submit',e=>{e.preventDefault();submit('/send',{phone:phone.value});});
document.querySelector('#codeForm').addEventListener('submit',e=>{e.preventDefault();submit('/verify',{code:code.value});});
document.querySelector('#passwordForm').addEventListener('submit',e=>{e.preventDefault();submit('/password',{password:password.value});});
continueCheck.addEventListener('click',()=>submit('/continue',{}));
busy=true;fetch('/status').then(r=>r.json()).then(render).catch(()=>{result.textContent='无法读取本机测试状态，请返回 Codex。';}).finally(()=>{busy=false;buttons();});
setInterval(buttons,500);buttons();
</script></html>"""


class LoginCheck:
    def __init__(self):
        self.client = CasSmsLogin()
        self.lock = threading.Lock()
        self.session = None
        self.web_result = None
        self.bridge_metadata = {}
        self.authorization_attempted = False
        self.status = {"outcome": "ready", "message": MESSAGES["ready"]}

    def act(self, path, data):
        if not self.lock.acquire(blocking=False):
            return {"outcome": "checking", "message": MESSAGES["checking"]}
        try:
            if path == "/send":
                if self.web_result is not None or self.session is not None:
                    return self.status
                self.client.send_code(str(data.get("phone", "")))
                outcome = "sent"
            else:
                if path == "/continue" or self.web_result is not None:
                    # Only reload this fixed, locally maintained module. The
                    # request cannot select code, files or upstream endpoints.
                    importlib.reload(sms_bridge)
                elif path == "/password":
                    try:
                        self.web_result = self.client.complete_password(str(data.get("password", "")))
                    finally:
                        data.pop("password", None)
                else:
                    self.web_result = self.client.complete(str(data.get("code", "")))
                self.status = sms_bridge.continue_login(self)
                outcome = self.status["outcome"]
            self.status.update(outcome=outcome, message=MESSAGES[outcome], remote_code="")
        except SmsLoginError as error:
            self.status = {"outcome": error.reason, "message": MESSAGES.get(error.reason, MESSAGES["unexpected_error"]), "remote_code": error.remote_code}
            if error.reason in ("additional_verification", "invalid_password", "password_locked"):
                self.status["verification"] = self.client.verification_summary
        except Exception:  # noqa: BLE001 -- Never log authentication exception bodies.
            self.status = {"outcome": "unexpected_error", "message": MESSAGES["unexpected_error"]}
        finally:
            self.status["retry_after"] = self.client.retry_after
            self.status["stage"] = self.client.stage
            self.lock.release()
        # Deliberately only fixed outcome codes, never exception text or bodies.
        print(json.dumps({"outcome": self.status["outcome"], "remote_code": self.status.get("remote_code", "")}), flush=True)
        return self.status


def make_server(port=0, check=None, *, html=HTML, paths=("/send", "/verify", "/password", "/continue")):
    check = check or LoginCheck()
    csrf = secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def host_ok(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def reply(self, status, body, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type + "; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if not self.host_ok():
                return self.reply(403, b'{}')
            if self.path == "/":
                return self.reply(200, html.replace("__CSRF__", csrf).encode(), "text/html")
            if self.path == "/status":
                status = dict(check.status)
                if isinstance(check, LoginCheck):
                    status["retry_after"] = check.client.retry_after
                return self.reply(200, json.dumps(status).encode())
            return self.reply(404, b'{}')

        def do_POST(self):
            origin = f"http://127.0.0.1:{self.server.server_port}"
            if not self.host_ok() or self.headers.get("Origin") != origin or not secrets.compare_digest(self.headers.get("X-Local-CSRF", ""), csrf):
                return self.reply(403, b'{}')
            if self.path not in paths:
                return self.reply(404, b'{}')
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 1024:
                    raise ValueError
                data = json.loads(self.rfile.read(size))
                if not isinstance(data, dict):
                    raise TypeError
            except (TypeError, ValueError, UnicodeDecodeError):
                return self.reply(400, b'{}')
            self.reply(200, json.dumps(check.act(self.path, data)).encode())

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    server = make_server(port=parser.parse_args().port)
    print(f"http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
