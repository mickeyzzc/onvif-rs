# WS-Discovery：让设备可被发现

客户端经 WS-Discovery 探测发现 ONVIF 设备。本库应答真实客户端的两条
探测路径：**UDP 组播**（239.255.255.250:3702）与 **HTTP POST** 探测。

## 基础应答器

```rust
use onvif_device_rs::discovery::DiscoveryServer;

// 中性 scope:onvif://www.onvif.org/Profile/Streaming
let discovery = DiscoveryServer::new(&device_ip, onvif_port);
let mut handle = discovery.start().await?;
// 收工时 handle.shutdown().await?
```

## 身份与 scope

```rust
let discovery = DiscoveryServer::with_identity(&device_ip, onvif_port, "Gate Camera", "CamX-SoC")
    .with_scopes(vec!["onvif://www.onvif.org/Profile/G".to_string()])
    .with_uuid("6f3f1a2e-...");        // 有稳定设备 UUID 就传入
```

- `with_identity` 设置友好名称 + 硬件 id scope。
- `with_scopes` **整体替换** scope 列表（URI 做百分号编码；scope 文本
  里带空格也安全）。
- 否则每个 `DiscoveryServer` 生成随机 UUID。

## ProbeMatches 应答里有什么

Types 为 `tdn:NetworkVideoTransmitter`、scopes，以及**按请求来源网卡
构造的 XAddrs**——`xaddrs(host_ip)` 回显"从该客户端够得着"的地址，
多网卡宿主正需要这个。message ID 与 scope 都做了 XML 转义。

## HTTP POST 探测

有些客户端不走组播、用 HTTP 探测。把 POST body 交给：

```rust
use onvif_device_rs::discovery::handle_http_probe;

let (status, body) = handle_http_probe(&discovery, &http_body, &server_ip);
// 用这个状态码 + body 应答该 HTTP 请求
```

## 辅助

- `detect_local_ip()`——启动时不知道本机 IP 的宿主用的尽力检测。

ProbeMatches 的字节布局有金串测试——确切信封见 `src/discovery.rs`
的测试。
