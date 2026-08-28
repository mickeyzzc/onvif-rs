[中文](README.zh-CN.md) | **English**

# onvif-rs

[![CI](https://github.com/mickeyzzc/onvif-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/mickeyzzc/onvif-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Language: Rust](https://img.shields.io/badge/language-Rust-dea584.svg)
![Tests](https://img.shields.io/badge/tests-133%20passing-brightgreen.svg)

**ONVIF 设备端（服务端）Rust 库** —— 让 NVR / 视频管理平台等 ONVIF 消费方通过 SOAP + WS-Discovery 发现并拉取你的摄像头或媒体源。

> **命名说明**：本项目与 [lumeohq/onvif-rs](https://github.com/lumeohq/onvif-rs)（WSDL 生成的 ONVIF *客户端*）无关。crates.io 上的 `onvif-rs` 名字被一个 2018 年废弃占位 crate 占据；请通过 git 依赖使用本库（若将来发布 crates.io 需换用别的包名）。

## 功能

- **SOAP HTTP 服务端**，按动作注册 handler —— Device / Media / Imaging /（虚拟）PTZ 服务
- **WS-Discovery 应答端** —— UDP 组播 239.255.255.250:3702 Probe/ProbeMatches，按请求方回显 XAddr
- **WS-Security** —— UsernameToken 校验，PasswordText 与 PasswordDigest（SHA-1），常数时间比较
- **命名空间无关的请求解析**（客户端前缀五花八门）与显式前缀序列化（`tds:`/`trt:`/`timg:`/`tt:`）
- **虚拟 PTZ** —— 纯状态机（`ptz_state`）支撑无云台设备的 PTZ 服务

代码从 [mibee-eye-raspi-rs](https://github.com/Mi-Bee-Studio) 的生产实现逐字抽取，其响应 XML 对 MiBee NVR（raw SOAP 本地名匹配）**字节稳定**。元素命名遵循官方 WSDL（`GetStreamUriResponse → MediaUri → Uri`）。

## 使用

```toml
[dependencies]
onvif-rs = { git = "https://github.com/mickeyzzc/onvif-rs.git" }
```

```rust
use onvif_rs::{DeviceConfig, OnvifConfig, OnvifServer};
use onvif_rs::imaging::{ImagingParams, ImagingParamError, register_imaging_actions};
use std::sync::Arc;

// 在相机参数管理器上实现 Imaging 接缝。
struct MyParams;
impl ImagingParams for MyParams {
    fn get_param(&self, name: &str) -> Result<f64, ImagingParamError> { /* ... */ }
    fn set_param(&self, name: &str, value: f64) -> Result<(), ImagingParamError> { /* ... */ }
}

#[tokio::main]
async fn main() {
    let device = DeviceConfig {
        name: "My Camera".into(),
        manufacturer: "Example".into(),
        model: "Model X".into(),
        ..Default::default()
    };

    let mut server = OnvifServer::new(OnvifConfig { /* port, auth, ... */ });
    onvif_rs::device::register_device_actions(&mut server, /* ... */);
    onvif_rs::media::register_media_actions(&mut server, /* ... */);
    register_imaging_actions(&mut server, Arc::new(MyParams));
    server.run().await;
}
```

完整生产接线示例（发现应答、快照 URI、流 URI、PTZ）见 `mibee-eye-raspi-rs` 的 `main.rs`。

## 字节稳定性保证

MiBee NVR 这类消费方按本地元素名对 SOAP 响应做原始字节流匹配。本 crate 的序列化是承重结构：**不要在未重跑消费方互操作测试的情况下改动响应元素名、命名空间前缀或属性顺序**。133 个测试中的黄金响应字符串锁定了这一约束。

## 开发

本项目严格执行 **TDD**，见 [CONTRIBUTING.md](CONTRIBUTING.md)。CI 强制 `rustfmt`、`clippy -D warnings` 与全量测试（133 个，含黄金响应字符串）；`main` 分支受保护（仅 PR 合入，CI 必过）。

## 状态

v0.1.0 —— 接缝（`ImagingParams`、`DeviceConfig`、media 注册）趋于稳定但尚未冻结。在 [Mi-Bee Studio](https://github.com/Mi-Bee-Studio) 每日对 MiBee NVR 生产验证。

## 许可

MIT —— 见 [LICENSE](LICENSE)。代码抽取自 Mi-Bee Studio 摄像头项目。
