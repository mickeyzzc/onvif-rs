# 配置参考

配置一个 ONVIF 设备用两个结构体：[`OnvifConfig`] 管 SOAP 服务器（端口、
认证、限制），[`DeviceConfig`] 管 GetDeviceInformation 上报的设备身份。

## OnvifConfig

```rust
use std::time::Duration;
use onvif_device_rs::OnvifConfig;

let config = OnvifConfig {
    port: 8080,
    username: "admin".to_string(),
    password: "secret".to_string(),
    allow_no_auth: false,
    max_body_bytes: 1024 * 1024,
    read_timeout: Duration::from_secs(30),
};
```

| 字段 | 类型 | 默认 | 含义 |
|---|---|---|---|
| `port` | `u16` | `8080` | `start()` 绑定的端口；`start_on()` 忽略它（listener 由你传入）。 |
| `username` | `String` | `""` | 期望客户端出示的 WS-UsernameToken 用户名。 |
| `password` | `String` | `""` | WS-UsernameToken 密码。**空密码默认 fail-closed**，除非设 `allow_no_auth`。 |
| `allow_no_auth` | `bool` | `false` | 显式允许无认证运行（所有动作开放）。 |
| `max_body_bytes` | `usize` | 1 MiB | HTTP 请求体上限；超限回 `413`。 |
| `read_timeout` | `Duration` | 30 秒 | 每连接读超时（头 + 体）。 |

空凭证默认值是有意的：忘记配置认证的宿主得到的是**拒绝认证动作**
的服务器，而不是来者不拒的服务器。要真跑一个开放设备（实验室、
隔离网络），显式设 `allow_no_auth: true`——这个选择写在你的代码里，
而不是默认值的意外。

## DeviceConfig

GetDeviceInformation 上报的身份：

```rust
use onvif_device_rs::device::DeviceConfig;

let device = DeviceConfig {
    name: "前门摄像头".into(),
    manufacturer: "Acme".into(),
    model: "Cam-X".into(),
    firmware: env!("CARGO_PKG_VERSION").into(),
    hardware_id: "Cam-X-SoC".into(),
    serial_number: "SN-000042".into(),
};
```

默认值描述出身硬件（`Pi Camera V1` / `Raspberry Pi` / `OV5647`）——
是为了与抽取源项目的配置文件兼容而保留的占位值。**生产环境务必换成
你自己的**；`Default` 与空 serde 节产出相同值（有测试钉死）。支持
TOML/JSON，可直接 re-export 进宿主自己的配置结构体。

## 服务器生命周期

```rust
let mut soap = OnvifServer::new(&config);
// ... 注册 handler（见 handlers 篇）...
let mut handle = soap.start().await?;       // 绑定 config.port
// 或: soap.start_on(listener).await?;      // 你自己的 TcpListener（端口 0、socket 激活……）
handle.shutdown().await?;                   // 优雅停机；handle.await 等待退出
```

`start_on` 面向自管 listener 的宿主（动态端口、systemd socket
激活、测试台）。

> **务必持有句柄。** `start()` 在接收循环启动后立即返回，返回句柄的
> `Drop` 会**停止服务器**。在派生任务里 await 它
> （`let handle = soap.start().await?; handle.await;`），或保存并调用
> `shutdown()`。丢弃 `Ok` 值会悄悄杀死服务器——自 0.3.1 起两个句柄均为
> `#[must_use]`，在编译期拦截该错误。
