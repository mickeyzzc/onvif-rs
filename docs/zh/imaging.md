# 成像服务：ImagingParams 接缝

成像参数（亮度、对比度、饱和度、聚焦……）是宿主硬件——库把一个极小
的 trait 翻译成三个 ONVIF 动作。

## 接缝

```rust
use onvif_device_rs::imaging::{ImagingParams, ImagingParamError};

struct MyCameraControls { /* v4l2 / ISP 句柄…… */ }

impl ImagingParams for MyCameraControls {
    /// 按 ONVIF 名称（如 "Brightness"）读参数。
    fn get_param(&self, name: &str) -> Result<f64, ImagingParamError> {
        // 把 ONVIF 名称翻译为你的控制项，并归一化到 [0.0, 1.0]
    }
    /// 写参数;value 已归一化到 [0.0, 1.0]。
    fn set_param(&self, name: &str, value: f64) -> Result<(), ImagingParamError> {
        // 把 [0,1] 缩放到你的硬件量程
    }
    /// 可选:GetImagingSettings 上报的曝光/白平衡模式。
    /// 默认上报 "AUTO"(历史线上值)。
}
```

线上取值统一归一化到 `[0.0, 1.0]`——你的实现负责双向映射到硬件量程。

## 错误变成语义正确的 fault

```rust
pub enum ImagingParamError {
    InvalidName(String),                    // → Sender/InvalidArg fault
    OutOfRange { value: f64, min: f64, max: f64 }, // → Sender/OutOfRange fault
    Io(String),                             // → Receiver/action fault
}
```

返回对的变体，客户端就看到对的 SOAP fault——信封不需要你构造。

## 一行注册

```rust
use std::sync::Arc;
use onvif_device_rs::imaging::register_imaging_actions;

register_imaging_actions(&mut soap, Arc::new(MyCameraControls { /* ... */ }));
```

注册 `GetImagingSettings`、`SetImagingSettings`、`GetOptions`（名称/
min/max 来自你 `get_param` 的拒绝或文档集合——见
`examples/imaging_demo.rs`，其中也演示了越界请求触发 fault）。
