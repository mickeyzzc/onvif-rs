# 认证与加固

## WS-UsernameToken 双模式

客户端以 WS-Security UsernameToken 头认证。两种 profile 模式都校验：

- **PasswordText**——token 里带明文密码。
- **PasswordDigest**——`base64(SHA1(base64_decode(Nonce) + Created + Password))`。

比较是常量时间的；用户名不匹配与摘要错误都只是安静地失败。要自己算
摘要（客户端侧工具）：

```rust
use onvif_device_rs::auth::compute_password_digest;

let digest = compute_password_digest(&nonce_b64, &created, &password);
```

## 凭证 fail-closed

`OnvifConfig` 默认**空凭证 + `allow_no_auth = false`**：忘记配置认证
的宿主得到的是对每个认证动作都回 401 的服务器，不是开放的服务器。
要有意跑开放设备（隔离实验网络），显式设 `allow_no_auth: true`：

```rust
let config = OnvifConfig {
    port: 8080,
    username: String::new(),
    password: String::new(),
    allow_no_auth: true, // 所有动作开放——你的显式选择
    ..Default::default()
};
```

非法配置（空密码且未设 `allow_no_auth`）在 `start()` 处报配置错误
——绝不会静默变成开放服务器。

## 免认证动作

`register_anonymous_action(action)` 让指定动作免凭证应答
（GetSystemDateAndTime、GetCapabilities、GetServices）——对齐真机
行为。粒度是按动作的，选择在代码里可见。

## 传输层加固

- **请求体上限**——超过 `max_body_bytes`（默认 1 MiB）的请求回
  `413 Content Too Large`；连接先短暂排空再关，客户端能读到状态码。
- **读超时**——请求中途卡住的连接在 `read_timeout`（默认 30 秒）
  后被断开。
- **头部上限**——超大/不终止的头部读取在固定上限处截断。
- SOAP listener 自身不带 TLS——部署需要 HTTPS 时前置你自己的反向
  代理。

## 卫生测试钉死了什么

`tests/library_hygiene.rs` 守住中性保证：库代码里无品牌字符串、无
panic 路径、无实验室地址，以及上面的认证 fail-closed 行为。
