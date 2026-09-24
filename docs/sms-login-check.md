# 免密码短信登录：验证阶段

用户目标：使用中国大陆手机号和短信验证码连接智慧生活，不输入密码、不依赖设备挑战码。

上游基线：758f68fe39484ac7f7605f5437ada7f89384c8cd。2026-09-24 只读核对 NAS 的 auth/huawei.py、auth/interface.py、config_flow.py 与此提交一致。

## 当前交付与边界

- `auth/sms.py`：独立 CAS 会话、网页初始化、风控检查、短信发送、验证码提交、会话过期和发送冷却。
- `tools/sms_login_check.py`：仅监听本机回环地址的人工测试页。账号、短信验证码、Cookie 和登录票据仅保存在进程内存；不记录请求正文和认证异常正文。
- 保留现有密码认证实现。尚未修改 HA 配置流，未上传 GitHub、未部署或重启 NAS。
- 单元测试使用虚构账号与响应，仅证明协议处理与错误分支；不代表真实短信或智慧生活授权已成功。

## 已核实的协议

来源为华为 `CAS/portal/login.html` 当前公开网页和 `smsLoginMixin-legacy.js`（资源版本 rss_20260824，CAS 6.26.2.100）：

1. GET 登录页读取 cVersion，POST `login/getPageInfo` 获取 pageToken、pageTokenKey 和业务上下文。
2. `chkRisk`：operType=11；中国大陆手机号格式为 0086 加 11 位号码。
3. `getSMSCodeV3`：operType=20、smsReqType=2、accountType=2，session_code_key=sms_login_session_ramdom_code_key。
4. `loginBySMS`：opType=11、smsAuthCode，不提交密码。
5. 登录成功回调只允许当前已验证的 HTTPS 华为账号站点；站点变化明确停止，不猜测跨站协议。

`CookieJar` 保留重复 Set-Cookie，并处理域、路径、过期和 Secure 属性。风控要求图形验证时停止，不尝试绕过。发码无自动重试，超时也保留本地冷却。

## 必须通过的真实验证

网页登录成功后检查明确的 TGC/userID 字段或对应 Cookie，再通过原集成 `_finish_login` 执行 stAuth、OAuth 和 HMS-lite 授权，最后读取家庭/设备快照。网页登录成功但没有可用票据时返回 `bridge_unverified`，不能宣称集成已连接。

普通网页登录票据是否可被智慧生活接受目前未验证；不得将猜测的返回字段或票据类型硬塞入生产认证。若需要额外票据交换，以人工登录后的实际响应继续分析。若触发滑块，改为用户在官方网页完成验证后继续研究授权交接。

## 运行与验证

在仓库根目录运行：

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python tools/sms_login_check.py
```

打开第二条命令输出的本机地址，输入手机号获取短信并提交验证码。状态接口仅返回固定结果码、数字错误编号及成功后的家庭/设备数量，不返回认证资料。服务停止即清除内存会话。

验证成功后继续：接入 HA 登录方式选择、手机号与验证码步骤、错误提示和重新认证；补配置流测试；按 NAS 约定保存版本、备份组件和 core.config_entries，再部署和验证。正式部署前仍需满足工作区先 GitHub 后 NAS 的流程，不上传任何登录状态。
