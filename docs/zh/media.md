# 媒体服务：Profile、取流地址与快照

`OnvifMediaConfig` 描述你真实的媒体端点——RTSP 服务器与快照 HTTP
端点在**你的宿主**里；ONVIF 层负责把它们播报出去。

## 配置

```rust
use std::sync::Arc;
use onvif_device_rs::media::{OnvifMediaConfig, VideoEncoding};

let media = Arc::new(OnvifMediaConfig {
    camera_width: 1280,
    camera_height: 720,
    camera_fps: 25,
    camera_bitrate: 2_500_000,
    rtsp_port: 8554,
    device_ip: "192.0.2.10".to_string(),
    stream_path: "/stream".to_string(),
    snapshot_port: 8080,               // 0 = 如实报"不支持"
    snapshot_path: "/snapshot.jpg".to_string(),
    profile_token: "main".to_string(),
    video_source_token: "videoSrc0".to_string(),
    encoder_token: "enc0".to_string(),
    encoding: VideoEncoding::H264,     // 或 H265
    video_source_name: "Video Source".to_string(),
});
```

| 字段 | 含义 |
|---|---|
| `camera_width` / `camera_height` / `camera_fps` / `camera_bitrate` | GetProfiles 里播报的参数。 |
| `rtsp_port` + `stream_path` | GetStreamUri 返回的 RTSP 地址（`rtsp://<ip>:<rtsp_port><stream_path>`）。 |
| `device_ip` | URI 构造的兜底 IP（每请求 `server_ip` 优先；见 [handler 模型](handlers.md)）。 |
| `snapshot_port` + `snapshot_path` | GetSnapshotUri 播报的 JPEG 端点。 |
| `snapshot_port = 0` | **诚实开关**：GetSnapshotUri 如实回 "snapshot not supported" fault，不虚报能力。 |
| `profile_token` / `video_source_token` / `encoder_token` | GetProfiles/GetStreamUri 之间回显的 token 串；单次启动内保持稳定。 |
| `encoding` | `H264` 或 `H265`（`.as_str()` 给线上字符串）。 |
| `video_source_name` | GetVideoSources 里的人读名称——宿主身份，不是产品名。 |

`OnvifMediaConfig::new(w, h, fps, bitrate, rtsp_port, device_ip)` 以
历史默认 token（`main`/`videoSrc0`/`enc0`）、H.264、`/stream` 构造。

## 注册

```rust
use onvif_device_rs::media::{
    GetProfilesHandler, GetStreamUriHandler, GetSnapshotUriHandler, GetVideoSourcesHandler,
};

soap.register_handler("GetProfiles", Box::new(GetProfilesHandler::new(Arc::clone(&media))));
soap.register_handler("GetStreamUri", Box::new(GetStreamUriHandler::new(Arc::clone(&media))));
soap.register_handler("GetSnapshotUri", Box::new(GetSnapshotUriHandler::new(Arc::clone(&media))));
soap.register_handler("GetVideoSources", Box::new(GetVideoSourcesHandler::new(Arc::clone(&media))));
```

## 字节稳定

`GetStreamUriResponse → MediaUri → Uri` 元素链（以及 GetProfiles 的
字段布局）是**线上契约**：真实 NVR 做原始 local-name 匹配，大小写或
嵌套变一点就断。金串测试钉死确切字节；改序列化路径它们先红。宿主
提供的字符串（路径、token、名称）在插值前做 XML 转义。
