[中文](README.zh-CN.md) | **English**

# onvif-rs

[![CI](https://github.com/mickeyzzc/onvif-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/mickeyzzc/onvif-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Language: Rust](https://img.shields.io/badge/language-Rust-dea584.svg)
![Tests](https://img.shields.io/badge/tests-157%20passing-brightgreen.svg)

**ONVIF 设备端（服务端）Rust 库** —— 通过 SOAP + WS-Discovery 把摄像头或媒体源暴露给 ONVIF 消费方（NVR、视频管理平台）。

> **命名说明**：本项目与 [lumeohq/onvif-rs](https://github.com/lumeohq/onvif-rs)（WSDL 生成的 ONVIF *客户端*）无关。crates.io 的 `onvif-rs` 名字被一个 2018 年的废弃占位仓持有，因此 crate 以 **`onvif-device-rs`** 名义发布；仓库保留原名。

## 功能

- **SOAP HTTP 服务端** —— 按动作注册处理器，覆盖 Device、Media、Imaging 与（虚拟）PTZ 服务
- **WS-Discovery 应答器** —— UDP 组播 239.255.255.250:3702 Probe/ProbeMatches，按请求回显 XAddr；scopes 与 EndpointReference UUID 均可由宿主配置
- **WS-Security** —— UsernameToken 校验，PasswordText 与 PasswordDigest（SHA-1），常数时间比较，空密码 **fail-closed** 处理
- **命名空间无关的请求解析**（客户端可用任意 XML 前缀）与显式前缀序列化（`tds:`/`trt:`/`timg:`/`tt:`），所有插值均做 XML 转义
- **虚拟 PTZ** —— 纯状态机（`ptz_state`）支撑无云台设备的 PTZ 服务
- **优雅停机** —— SOAP 服务端与 discovery 应答器均支持

代码抽取自 [mibee-eye-raspi-rs](https://github.com/Mi-Bee-Studio) 的生产实现，其响应 XML 对 **MiBee NVR 逐字节稳定**（NVR 按本地名做原始 SOAP 匹配）。元素名遵循官方 WSDL（`GetStreamUriResponse → MediaUri → Uri`）。

## 使用

```toml
[dependencies]
onvif-device-rs = "0.3.0"
# git 替代方式: onvif-device-rs = { git = "https://github.com/mickeyzzc/onvif-rs.git", tag = "v0.3.0" }
```

```rust,no_run
use std::sync::Arc;
use onvif_device_rs::config::DeviceConfig;
use onvif_device_rs::device::{DeviceHandler, DeviceServiceHandlers};
use onvif_device_rs::discovery::DiscoveryServer;
use onvif_device_rs::imaging::{register_imaging_actions, ImagingParamError, ImagingParams};
use onvif_device_rs::media::{
    GetProfilesHandler, GetSnapshotUriHandler, GetStreamUriHandler, OnvifMediaConfig,
};
use onvif_device_rs::server::{OnvifConfig, OnvifServer};

// 在你的摄像头参数管理器上实现 Imaging 接缝。
struct MyParams;
impl ImagingParams for MyParams {
    fn get_param(&self, name: &str) -> Result<f64, ImagingParamError> { todo!() }
    fn set_param(&self, name: &str, value: f64) -> Result<(), ImagingParamError> { todo!() }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let device_ip = "192.0.2.10".to_string();
    let port = 8080u16;

    // 鉴权 fail-closed：空密码且未显式 allow_no_auth = true 时，
    // start() 直接报错，而不是静默把服务端变成全开放。
    let config = OnvifConfig {
        port,
        username: "admin".to_string(),
        password: "set-a-real-password".to_string(),
        ..Default::default()
    };
    let mut server = OnvifServer::new(&config);

    // Device 服务：身份信息来自 DeviceConfig（宿主提供）。
    // 中性 "unknown" 占位会被校验拒绝——必须显式配置真实身份（issue #20）。
    let device = Arc::new(DeviceServiceHandlers::new(
        DeviceConfig {
            name: "My Camera".into(),
            manufacturer: "My Company".into(),
            model: "Cam-X".into(),
            firmware: "1.0.0".into(),
            hardware_id: "cam-x".into(),
            serial_number: "SN-001".into(),
        },
        port,
        device_ip.clone(),
    )
    .expect("explicit device identity"));
    for action in ["GetSystemDateAndTime", "GetDeviceInformation",
                   "GetCapabilities", "GetServices", "GetScopes"] {
        // 按 ONVIF 规范该动作免鉴权：
        if action == "GetSystemDateAndTime" {
            server.register_anonymous_action(action);
        }
        server.register_handler(action, Box::new(DeviceHandler(Arc::clone(&device))));
    }

    // Media 服务：token、编码（H264/H265）、流与快照 URI 全部是
    // OnvifMediaConfig 的字段。
    let media = Arc::new(OnvifMediaConfig::new(1920, 1080, 25, 2_000_000, 8554, device_ip.clone()));
    server.register_handler("GetProfiles", Box::new(GetProfilesHandler::new(Arc::clone(&media))));
    server.register_handler("GetStreamUri", Box::new(GetStreamUriHandler::new(Arc::clone(&media))));
    server.register_handler("GetSnapshotUri", Box::new(GetSnapshotUriHandler::new(media)));

    // Imaging 服务用注册辅助函数；PTZ 同理（见 examples）。
    register_imaging_actions(&mut server, Arc::new(MyParams));

    // 启动两个服务；返回的句柄支持优雅停机。
    let mut soap = server.start().await?;               // 0.0.0.0:port
    let mut discovery = DiscoveryServer::with_identity(&device_ip, port, "My Camera", "Model X")
        .start()
        .await?;                                        // udp/3702 组播

    // ... 运行你的应用 ...
    discovery.shutdown().await?;
    soap.shutdown().await?;
    Ok(())
}
```

`DiscoveryServer::with_uuid` 可固定 EndpointReference UUID，避免按它识别设备的 NVR 把每次重启当成新设备。本 crate 通过 [`log`](https://crates.io/crates/log) facade 输出日志 —— 宿主初始化 logger 后才能看到输出。

完整接线见 [`examples/device_demo.rs`](examples/device_demo.rs)（它同时是 README 式代码的编译验证参照），生产接线见 `mibee-eye-raspi-rs` 的 `main.rs`。

## 文档

专题教程在 [`docs/zh/`](docs/zh/) —— 每篇在 `docs/en/` 下有英文对照版：

| 教程 | 内容 |
|---|---|
| [配置](docs/zh/configuration.md) | `OnvifConfig` 字段、fail-closed 凭证、`DeviceConfig` 身份、`start_on` |
| [动作 handler](docs/zh/handlers.md) | 局部名路由、`RequestInfo`、匿名动作、自定义 handler |
| [媒体服务](docs/zh/media.md) | `OnvifMediaConfig` 逐字段、token、快照诚实开关、字节稳定 |
| [成像](docs/zh/imaging.md) | `ImagingParams` 接缝、错误→fault 映射、归一化取值 |
| [虚拟云台](docs/zh/ptz.md) | `PtzState` API、运动模拟、十一个动作接线 |
| [设备发现](docs/zh/discovery.md) | UDP + HTTP 双探测路径、身份/scope、按网卡回显 XAddrs |
| [安全](docs/zh/security.md) | UsernameToken 双模式、fail-closed 配置、请求体/读超时限制 |

## 库卫生（v0.3.0 加固）

v0.3.0 把本 crate 打磨为可放心嵌入的中性基础库。[`tests/library_hygiene.rs`](tests/library_hygiene.rs) 与 [`tests/server_lifecycle.rs`](tests/server_lifecycle.rs) 中的回归测试逐条锁定以下保证：

- **鉴权 fail-closed** —— 空密码不再静默关闭鉴权；除非显式设置 `allow_no_auth = true`，`start()` 直接报错。
- **中性的 discovery 身份** —— `DiscoveryServer::new` 只宣告规范 profile scope（移除了原硬件的 `PiCameraV1`/`OV5647` scope）；用 `with_identity`/`with_scopes` 自定义。scope 值做百分号编码（空格安全）。
- **UUID 可持久化** —— `with_uuid` 让 discovery 身份跨重启稳定。
- **XML 转义** —— 客户端可控值（SOAP 动作名、预置位名、Probe MessageID）与宿主配置字符串在响应中转义。
- **Media 面可配置** —— profile/源/编码器 token、编码（H.264 **或 H.265**）、GetVideoSources 名称均来自 `OnvifMediaConfig`。
- **Imaging 模式可配置** —— `ImagingParams::exposure_mode` / `white_balance_mode`（带默认实现，向后兼容）。
- **HTTP 加固** —— 头部多段读取（16 KiB 上限）、默认 1 MiB 请求体上限（超限 413 并先排空再关闭）、每连接读超时（默认 30 s）。
- **优雅停机 + 监听器注入** —— `OnvifServerHandle`/`DiscoveryHandle` 提供 `shutdown()`；`OnvifServer::start_on(listener)` 接受预先绑定的监听器。
- **`log` facade** —— 库代码零 `println!`/`eprintln!`；锁中毒做恢复而非级联 panic。

### 0.2.x → 0.3.0 破坏性变更

- `OnvifConfig` 新增 `allow_no_auth`、`max_body_bytes`、`read_timeout`（字面量请用 `..Default::default()`）。
- `OnvifServer::start` 返回 `OnvifServerHandle`（原来是 `()`）；`DiscoveryServer::start` 返回 `DiscoveryHandle`。
- `DiscoveryServer::new` 接受 `&str`，且默认不再宣告 name/hardware scope。
- `GetVideoSources` 名称默认为 `Video Source`（原来是 `Pi Camera`）。
- 库输出从 stdout/stderr 迁移到 `log` facade。

## 示例

[`examples/`](examples/) 提供可运行的自检演示：

```sh
cargo run --example device_demo [-- --port 8080] [-- --serve]
```

它启动真实 SOAP 服务端 + WS-Discovery 应答器，再像外部 ONVIF 客户端一样驱动它们：匿名 `GetSystemDateAndTime`、无凭据时 `GetDeviceInformation` 被 401 拒绝、带 WS-Security UsernameToken 摘要（演示内独立计算 SHA-1）时通过、`GetCapabilities`、`GetProfiles`/`GetStreamUri`/`GetSnapshotUri`、以及 UDP 上的 WS-Discovery Probe。全部通过后以 0 退出 —— 无需硬件的整机冒烟测试。`--serve` 保持服务运行以便手动验证（curl / ONVIF Device Manager / NVR）。
另外两个聚焦服务的演示遵循同样模式（真实服务端 + 外部客户端检查 + 成功退出 0）：

```sh
cargo run --example ptz_demo      # move/status/preset 动词 + 模拟运动
cargo run --example imaging_demo  # imaging 参数读写 + 越界错误
```

## 字节稳定性保证

MiBee NVR 这类消费方按本地元素名在原始字节流上匹配 SOAP 响应。本 crate 的序列化是承重结构：**改动响应元素名、命名空间前缀或属性顺序前必须重跑消费方互操作测试**。crate 的测试中包含锁定该性质的 golden 响应串。

## 开发

本项目严格执行 **TDD**，见 [CONTRIBUTING.md](CONTRIBUTING.md)。CI 强制 `rustfmt`、`clippy -D warnings` 与全量测试（157 个，含 golden 响应串）；`main` 分支受保护（仅 PR 合入，CI 必过）。

## 状态

v0.3.0 —— 接缝（`ImagingParams`、`DeviceConfig`、media 注册）趋于稳定但尚未冻结。在 [Mi-Bee Studio](https://github.com/Mi-Bee-Studio) 每日对 MiBee NVR 生产验证。

## 许可

MIT —— 见 [LICENSE](LICENSE)。代码抽取自 Mi-Bee Studio 摄像头项目。
