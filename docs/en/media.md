# Media service: profiles, stream URIs, snapshots

`OnvifMediaConfig` describes your real media endpoints — the RTSP
server and snapshot HTTP endpoint live in **your** host; the ONVIF
layer advertises them.

## Configuration

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
    snapshot_port: 8080,               // 0 = advertise "not supported"
    snapshot_path: "/snapshot.jpg".to_string(),
    profile_token: "main".to_string(),
    video_source_token: "videoSrc0".to_string(),
    encoder_token: "enc0".to_string(),
    encoding: VideoEncoding::H264,     // or H265
    video_source_name: "Video Source".to_string(),
});
```

| Field | Meaning |
|---|---|
| `camera_width` / `camera_height` / `camera_fps` / `camera_bitrate` | Advertised in GetProfiles. |
| `rtsp_port` + `stream_path` | The RTSP URL GetStreamUri returns (`rtsp://<ip>:<rtsp_port><stream_path>`). |
| `device_ip` | Fallback IP for URI building (per-request `server_ip` wins; see [handlers](handlers.md)). |
| `snapshot_port` + `snapshot_path` | JPEG endpoint advertised by GetSnapshotUri. |
| `snapshot_port = 0` | **Honesty switch**: GetSnapshotUri faults with "snapshot not supported" instead of lying. |
| `profile_token` / `video_source_token` / `encoder_token` | Token strings echoed between GetProfiles/GetStreamUri; keep them stable per boot. |
| `encoding` | `H264` or `H265` (`.as_str()` gives the wire string). |
| `video_source_name` | Human name in GetVideoSources — host identity, not a product name. |

`OnvifMediaConfig::new(w, h, fps, bitrate, rtsp_port, device_ip)`
constructs with the historical default tokens (`main`/`videoSrc0`/
`enc0`), H.264, and `/stream`.

## Registration

```rust
use onvif_device_rs::media::{
    GetProfilesHandler, GetStreamUriHandler, GetSnapshotUriHandler, GetVideoSourcesHandler,
};

soap.register_handler("GetProfiles", Box::new(GetProfilesHandler::new(Arc::clone(&media))));
soap.register_handler("GetStreamUri", Box::new(GetStreamUriHandler::new(Arc::clone(&media))));
soap.register_handler("GetSnapshotUri", Box::new(GetSnapshotUriHandler::new(Arc::clone(&media))));
soap.register_handler("GetVideoSources", Box::new(GetVideoSourcesHandler::new(Arc::clone(&media))));
```

## Byte stability

The `GetStreamUriResponse → MediaUri → Uri` element chain (and the
GetProfiles field layout) is a **wire contract**: real NVRs match raw
local names and break on any casing/nesting change. Golden tests pin
the exact bytes; changing serialization paths turns them red first.
Host-supplied strings (paths, tokens, names) are XML-escaped before
interpolation.
