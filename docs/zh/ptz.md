# PTZ 服务：虚拟云台状态机

不需要电机。`PtzState` 是一个纯状态机，让固定机位像云台机一样可被
控制——位置、速度、预置位，以及 tick 驱动的运动模拟。

## 状态机

```rust
use onvif_device_rs::ptz_state::{PtzState, Position, Velocity, Preset};

let state = std::sync::Arc::new(PtzState::new());

state.absolute_move(Position { x: 0.8, y: 0.2, zoom: 0.5 }); // 缓动趋向目标
state.continuous_move(Velocity { x: 0.1, y: 0.0, zoom: 0.0 }); // 随 tick 积分
state.stop();
state.relative_move(Velocity { x: -0.1, y: 0.05, zoom: 0.0 });
state.tick(100); // 推进模拟 dt 毫秒

let Position { x, y, zoom } = state.get_position();
let status = state.get_status();        // "IDLE" | "MOVING"
let token = state.save_preset("大门");  // 返回预置位 token
state.goto_preset(&token);
let presets: Vec<Preset> = state.list_presets();
```

- **ContinuousMove** 按 tick 积分速度；**AbsoluteMove** 最多 20 个
  tick 缓动到目标；状态为 `IDLE`/`MOVING`。
- 坐标是归一化值：水平/垂直 `[-1, 1]`、变焦 `[0, 1]`——在客户端或
  UI 侧映射为真实角度。
- tick 挂在任何你方便的循环上（定时任务、渲染循环）。

## 接线

一个 `PtzHandler` 服务全部十一个 PTZ 动作：

```rust
use onvif_device_rs::ptz::PtzHandler;

for action in [
    "ContinuousMove", "AbsoluteMove", "RelativeMove", "Stop",
    "GetStatus", "GetPresets", "SetPreset", "GotoPreset",
    "RemovePreset", "GetNodes", "GetConfigurations",
] {
    soap.register_handler(action, Box::new(PtzHandler(std::sync::Arc::clone(&state))));
}
```

`examples/ptz_demo.rs` 对活服务器跑全动词集——绝对移动精确落位、
连续移动随 tick 漂移、预置位往返——带断言，退出码 0。

## 真电机

`PtzState` 是完整的参考实现，不是硬性要求：有真实云台硬件的宿主把
同样的动作实现为自定义 [`OnvifActionHandler`]，直接驱动电机。
