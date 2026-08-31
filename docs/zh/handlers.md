# 动作 handler 模型

SOAP 服务器按**局部名**路由：SOAP body 的第一个子元素就是动作
（`GetProfiles`、`GetStreamUri`……），每个动作映射到一个 handler：

```rust
use onvif_device_rs::{OnvifServer, OnvifActionHandler, RequestInfo, OnvifError};

#[async_trait::async_trait]
impl OnvifActionHandler for MyHandler {
    async fn handle(&self, body: &str, info: &RequestInfo) -> Result<String, OnvifError> {
        // body: 原始 SOAP body 片段
        // 返回: 完整应答信封
    }
}

soap.register_handler("GetProfiles", Box::new(MyHandler));
```

`RequestInfo` 携带每请求上下文：

```rust
pub struct RequestInfo {
    pub client_ip: String,   // 对端地址（日志、访问控制）
    pub server_ip: String,   // 收到连接的本地 IP（构造 URI 用）
    pub auth_result: AuthResult, // 用户名 + 是否认证通过
}
```

`server_ip` 决定多网卡环境下的正确性：流/服务 URI 按**客户端实际
到达的网卡**构造；回环来源的请求（反向代理场景）回退到启动时的
`device_ip`。

## 匿名（免认证）动作

真机在出示凭证前就会应答一部分动作——客户端探测 GetSystemDateAndTime、
GetCapabilities、GetServices 是标准姿势。把这些注册为匿名：

```rust
for action in ["GetSystemDateAndTime", "GetCapabilities", "GetServices"] {
    soap.register_anonymous_action(action);
}
```

其余动作一律要求有效 WS-UsernameToken。

## 内置服务

crate 自带常用服务的 handler 实现——要哪个动作注册哪个：

```rust
use std::sync::Arc;
use onvif_device_rs::device::{DeviceConfig, DeviceHandler, DeviceServiceHandlers};

// Device 服务:五个动作共用一份状态
let device = Arc::new(DeviceServiceHandlers::new(device_config, port, device_ip));
for action in ["GetSystemDateAndTime", "GetDeviceInformation",
               "GetCapabilities", "GetServices", "GetScopes"] {
    soap.register_handler(action, Box::new(DeviceHandler(Arc::clone(&device))));
}
```

媒体（GetProfiles / GetStreamUri / GetSnapshotUri / GetVideoSources）、
成像（register_imaging_actions）、PTZ（PtzHandler）各有专门教程。

## 应答信封

handler 返回**完整 SOAP 信封**（不是片段）。内置构造器产出本库保证
字节稳定的规范形态；自定义 handler 应复用同样的元素名与命名空间
前缀——大量客户端做的是原始 local-name 匹配，不是完整 SOAP 解析。

## 参考接线

`examples/device_demo.rs` 是自检式接线：起服务器、断言匿名动作回
`200`、断言无 token 的认证动作回 `401`、退出码 0——把它当自己
bootstrap 的模板。
