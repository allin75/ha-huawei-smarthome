# 免密码短信登录：验证阶段

用户目标：使用中国大陆手机号和短信验证码连接智慧生活、不依赖设备挑战码。实测华为要求不受信任浏览器进行密码验证后，用户已授权补充密码二次验证。

上游基线：758f68fe39484ac7f7605f5437ada7f89384c8cd。2026-09-24 只读核对 NAS 的 auth/huawei.py、auth/interface.py、config_flow.py 与此提交一致。

## 当前交付与边界

- `auth/sms.py`：独立 CAS 会话、网页初始化、风控检查、短信发送、验证码提交、会话过期和发送冷却。
- `tools/sms_login_check.py`：仅监听本机回环地址的人工测试页。账号、短信验证码、Cookie 和登录票据仅保存在进程内存；不记录请求正文和认证异常正文。
- 保留现有密码认证实现。尚未修改 HA 配置流，未上传 GitHub、未部署或重启 NAS。
- 单元测试使用虚构账号与响应，仅证明协议处理与错误分支；不代表真实短信或智慧生活授权已成功。
- 真实测试已成功发短信，loginBySMS 返回 10012072；验证方式只有 password，isNotTrustBrowserVerify=true、isDoubleVerification=false。用户随后完成密码二次验证，网页账号登录成功，但返回 `bridge_unverified`：尚未取得明确的智慧生活票据，设备读取未验证。
- `tools/sms_bridge.py`：将后续授权检查隔离为可重新加载的本地模块；`/continue` 复用内存中的网页登录结果。它目前只验证明确的 TGC/userID 候选，不包含已证实的网页到应用票据交换协议。
- 2026-09-26 核对公开 CAS 脚本和社区分支：CAS 成功回调不证明拥有应用票据；Suprmaster 分支使用原生 loginV3 的密码登录加短信挑战，并非本方案 loginBySMS 的授权衔接，未据此声称打通。

## 已核实的协议

来源为华为 `CAS/portal/login.html` 当前公开网页和 `smsLoginMixin-legacy.js`（资源版本 rss_20260824，CAS 6.26.2.100）：

1. GET 登录页读取 cVersion，POST `login/getPageInfo` 获取 pageToken、pageTokenKey 和业务上下文。
2. `chkRisk`：operType=11；中国大陆手机号格式为 0086 加 11 位号码。
3. `getSMSCodeV3`：operType=20、smsReqType=2、accountType=2，session_code_key=sms_login_session_ramdom_code_key。
4. `loginBySMS`：opType=11、smsAuthCode，不提交密码。
5. 登录成功回调只允许当前已验证的 HTTPS 华为账号站点；站点变化明确停止，不猜测跨站协议。

密码二次验证依据 `smsLoginValidateMixin-legacy.js`：在相同 loginBySMS 请求中保留短信验证码和会话，增加 twoFactorType=5、twoFactorValue=用户输入的密码。只有服务器提供密码方式时允许提交；本地最多尝试三次，不自动重试。密码不保存在会话对象或文件，页面请求结束后清空密码框。短信验证码仅在等待验证期间留在内存，成功/会话过期时清除。

`CookieJar` 保留重复 Set-Cookie，并处理域、路径、过期和 Secure 属性。风控要求图形验证时停止，不尝试绕过。发码无自动重试，超时也保留本地冷却。

## 必须通过的真实验证

### 2026-09-26 续接实测

新版 55345 已收到用户完成的短信和密码验证；安全诊断确认回调是 `/AMW/portal/userCenter/index.html`，有 `ticket`，没有明确 TGC/userID。CAS `getUserAccInfo` 只读探测返回 10000001，不将此错误直接解释为密码错误或会话过期。

继续核对官方 AMW 资源发现，先前 GET 回调网页遗漏了前端初始化：
`https://id1.cloud.huawei.com/CAS/static_rss/red/rss_20260824/AMW/vue3/vuebuild/js/webUserCenter/portal/index-entry-legacy.js`
以 `webUserCenter` 为 pageName，将回调查询参数（包含 ticket）提交到 `/AMW/ajaxHandler/common/getPageInfo`。已在可重载模块补充这一固定端点，认证参数及响应仅留在内存。

真实响应 isSuccess=1 但带 redirectUrl、没有 pageToken，因此只是要求重定向，不能认作账号中心初始化成功。返回目标为当前华为域名的 `/CAS/remoteLogin`。本地 urllib 首次因地址含中文抛出 UnicodeEncodeError（请求尚未发出）；补充 URI 百分号编码并通过回归测试后，实际跟随跳转最终到 `/CAS/portal/login.html`。现有会话无法完成该次账号中心接续，原因尚未确定；没有拿到智慧生活授权，不能断言所有网页授权方案均不可行。

查询及 SSO 结果在内存缓存，失败不循环重试，且不自动发送新短信。所有认证字段继续只在内存中处理，诊断只显示固定分类。保留网页登录实验代码；建议下一步评估原生 loginV3 的密码加短信挑战路线，该路线也尚未实测成功。

网页登录成功后检查明确的 TGC/userID 字段或对应 Cookie，再通过原集成 `_finish_login` 执行 stAuth、OAuth 和 HMS-lite 授权，最后读取家庭/设备快照。网页登录成功但没有可用票据时返回 `bridge_unverified`，不能宣称集成已连接。

普通网页登录票据是否可被智慧生活接受目前未验证；不得将猜测的返回字段或票据类型硬塞入生产认证。若需要额外票据交换，以人工登录后的实际响应继续分析。若触发滑块，改为用户在官方网页完成验证后继续研究授权交接。

## 运行与验证

在仓库根目录运行：

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python tools/sms_login_check.py
```

打开第二条命令输出的本机地址，输入手机号获取短信并提交验证码。状态接口仅返回固定结果码、数字错误编号、白名单字段/Cookie 名称及存在性、未知字段数量和成功后的家庭/设备数量，不返回认证值或完整回调 URL。服务停止即清除内存会话。

网页登录成功后隐藏登录表单。维护者修改本地固定的授权模块后，可点击“继续检查智慧生活连接”，在保留会话的同时加载新代码；请求不能指定代码或外部 URL，且需要与其他提交相同的 Host/Origin/CSRF 验证。已有应用会话仅重试读取；明确票据授权失败后不会重复提交。刷新页面从 `/status` 恢复进度。

旧测试进程没有续接接口，无法从普通接口取出或移交其内存会话。因此首次启用新版需一次新的人工登录；保留旧进程，在另一个本机端口启动新版，不尝试调试器抓取内存或落盘认证数据。该登录用于继续调查，不承诺下一次就能完成智慧生活授权。

验证成功后继续：接入 HA 登录方式选择、手机号与验证码步骤、错误提示和重新认证；补配置流测试；按 NAS 约定保存版本、备份组件和 core.config_entries，再部署和验证。正式部署前仍需满足工作区先 GitHub 后 NAS 的流程，不上传任何登录状态。
