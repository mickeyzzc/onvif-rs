# 快速开始：最小 ONVIF 设备

`onvif-device-rs` 是 ONVIF Device 服务端：注册几个 handler，就把你的
设备身份与媒体端点播报给任意 NVR。本页给最小可编译示例。

## 安装

```bash
cargo add onvif-device-rs@0.7.0  # crate 名与仓库（onvif-rs）不同
```

示例还需要异步运行时：

```toml
[dependencies]
onvif-device-rs = "=0.6.0"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## 最小示例

```rust
use std::sync::Arc;

use onvif_device_rs::config::DeviceConfig;
use onvif_device_rs::device::{DeviceHandler, DeviceServiceHandlers};
use onvif_device_rs::media::{GetProfilesHandler, GetStreamUriHandler, OnvifMediaConfig};
use onvif_device_rs::server::{OnvifConfig, OnvifServer};

#[tokio::main]
async fn main() {
    let port = 8080u16;
    let device_ip = "192.0.2.10".to_string();

    let mut soap = OnvifServer::new(&OnvifConfig {
        port,
        username: "admin".to_string(),
        password: "secret".to_string(),
        ..Default::default()
    });

    let device = Arc::new(
        DeviceServiceHandlers::new(
            DeviceConfig {
                name: "quickstart camera".into(),
                manufacturer: "MiBee".into(),
                model: "QS".into(),
                firmware: "0.0.1".into(),
                hardware_id: "qs-hw".into(),
                serial_number: "QS-0001".into(),
            },
            port,
            device_ip.clone(),
        )
        .expect("device identity must be configured explicitly"),
    );
    for action in [
        "GetSystemDateAndTime",
        "GetDeviceInformation",
        "GetCapabilities",
        "GetServices",
        "GetScopes",
    ] {
        soap.register_handler(action, Box::new(DeviceHandler(Arc::clone(&device))));
    }
    for action in ["GetSystemDateAndTime", "GetCapabilities", "GetServices"] {
        soap.register_anonymous_action(action);
    }

    let media = Arc::new(OnvifMediaConfig::new(
        1280, 720, 25, 2_500_000, 8554, device_ip,
    ));
    soap.register_handler("GetProfiles", Box::new(GetProfilesHandler::new(Arc::clone(&media))));
    soap.register_handler("GetStreamUri", Box::new(GetStreamUriHandler::new(Arc::clone(&media))));

    tokio::spawn(soap.start());
}
```

要点：

- 设备身份必须显式配置（`DeviceServiceHandlers::new` 会校验）；
  匿名可访问的动作逐个放行（规范要求时钟与能力匿名）。
- ONVIF 层只**播报**地址：RTSP 服务器与快照 HTTP 端点在你的宿主里
  （[媒体服务](onvif-rs-media.md)）。
- 配 `DiscoveryServer` 即可被 NVR 的 WS-Discovery 探测发现
  （[WS-Discovery](onvif-rs-discovery.md)）。
- 示例值均为文档保留段（`192.0.2.x`、占位密码）。

## 下一步

- [动作 handler 模型](onvif-rs-handlers.md)：每个 SOAP action 的注册与接线。
- [认证与加固](onvif-rs-security.md)：WS-UsernameToken 摘要与匿名面控制。
- [PTZ](onvif-rs-ptz.md) / [成像](onvif-rs-imaging.md)：可选服务。
- 仓库内置 `cargo run --example device_demo`：自检式全流程演示。
