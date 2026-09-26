"""Loopback-only UI for native Huawei login; no credentials are written out."""

import argparse
import importlib
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools import native_sms
from tools.sms_login_check import make_server

HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>智慧生活登录验证</title><style>
body{margin:0;background:#f4f6fa;color:#172333;font:16px/1.65 system-ui,sans-serif}
main{max-width:480px;margin:6vh auto;padding:30px;background:white;border-radius:18px}
h1{font-size:25px;margin:0 0 12px}p{color:#576579}label{display:block;margin:18px 0 6px;font-weight:600}
input,button{box-sizing:border-box;font:inherit;border-radius:9px;padding:12px;width:100%}
input{border:1px solid #bdc7d4}button{border:0;background:#2161d9;color:white;margin-top:14px;cursor:pointer}
button:disabled{background:#9baecb;cursor:wait}#result{padding:16px;background:#eef4ff;border-radius:9px;margin-top:20px;white-space:pre-line}
.note{font-size:13px} [hidden]{display:none!important} @media(max-width:540px){main{margin:20px 12px;padding:22px}}
</style><main><h1>智慧生活登录验证</h1>
<p>先用华为账号密码登录，再检查能否使用短信完成验证。</p>
<form id="loginForm"><label for="phone">手机号（中国大陆 +86）</label>
<input id="phone" type="tel" inputmode="tel" autocomplete="off" required>
<label for="password">华为账号密码</label>
<input id="password" type="password" autocomplete="off" maxlength="256" required>
<button id="begin" type="submit">登录并检查验证方式</button></form>
<button id="send" type="button" hidden>获取短信验证码</button>
<form id="codeForm" hidden><label for="code">短信验证码</label>
<input id="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
<button id="verify" type="submit">验证并读取设备</button></form>
<button id="continueCheck" type="button" hidden>重试读取设备</button>
<div id="result" role="status" aria-live="polite">正在读取测试状态……</div>
<p class="note">这是本机测试页，不会修改 Home Assistant。密码仅用于本次华为登录，提交后清空；验证码和登录状态不写入文件或日志。此路线尚待真实验证。</p>
</main><script>
const csrf='__CSRF__';
const q=s=>document.querySelector(s);let busy=true,current={};
function render(s){if(s.outcome==='checking')return;current=s;
q('#result').textContent=s.message;
q('#loginForm').hidden=s.can_send||s.can_verify||['sms_available','sent','marked_sent','sms_unavailable','sms_dispatch_failed','challenge_rejected','authorization_failed','discovery_failed','verified'].includes(s.outcome);
q('#send').hidden=!s.can_send;q('#codeForm').hidden=!s.can_verify;
q('#continueCheck').hidden=s.outcome!=='discovery_failed';buttons();}
function buttons(){q('#begin').disabled=busy||!current.can_begin;q('#send').disabled=busy||!current.can_send;q('#verify').disabled=busy||!current.can_verify;q('#continueCheck').disabled=busy;q('#phone').disabled=busy;q('#password').disabled=busy;}
async function readStatus(){if(busy)return;try{const r=await fetch('/status');if(!r.ok)throw Error();render(await r.json());}catch(e){q('#result').textContent='本机测试服务连接中断，请返回 Codex。';}}
async function submit(path,data){if(busy)return;busy=true;buttons();q('#result').textContent='正在连接华为，请稍候。';
try{const r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Local-CSRF':csrf},body:JSON.stringify(data)});if(!r.ok)throw Error();render(await r.json());}
catch(e){q('#result').textContent='请求未完成，请返回 Codex，暂时不要重复提交。';}
finally{q('#password').value='';q('#code').value='';busy=false;buttons();}}
q('#loginForm').addEventListener('submit',e=>{e.preventDefault();submit('/begin',{phone:q('#phone').value,password:q('#password').value});});
q('#send').addEventListener('click',()=>submit('/send',{}));
q('#codeForm').addEventListener('submit',e=>{e.preventDefault();submit('/verify',{code:q('#code').value});});
q('#continueCheck').addEventListener('click',()=>submit('/continue',{}));
buttons();busy=false;readStatus();setInterval(readStatus,5000);
</script></html>"""


class NativeCheck:
    def __init__(self):
        self.state = native_sms.NativeState()
        self.lock = threading.Lock()

    @property
    def status(self):
        if not self.lock.acquire(blocking=False):
            return {"outcome": "checking", "message": native_sms.MESSAGES["checking"]}
        try:
            return native_sms.snapshot(self.state)
        finally:
            self.lock.release()

    def act(self, path, data):
        if not self.lock.acquire(blocking=False):
            data.pop("password", None)
            data.pop("code", None)
            return {"outcome": "checking", "message": native_sms.MESSAGES["checking"]}
        try:
            # Fixed local module only; requests cannot select code or a URL.
            importlib.reload(native_sms)
            return native_sms.perform(self.state, path, data)
        except Exception:  # noqa: BLE001 -- Do not expose reload or auth exceptions.
            return {"outcome": "unexpected_error", "message": native_sms.MESSAGES["unexpected_error"]}
        finally:
            data.pop("password", None)
            data.pop("code", None)
            self.lock.release()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    server = make_server(port=parser.parse_args().port, check=NativeCheck(), html=HTML,
                         paths=("/begin", "/send", "/verify", "/continue"))
    print(f"http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
