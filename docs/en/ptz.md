# PTZ service: the virtual PTZ state machine

No motors required. `PtzState` is a pure state machine that makes a
fixed camera controllable like a PTZ one — positions, velocities,
presets, and a tick-driven motion simulation.

## The state machine

```rust
use onvif_device_rs::ptz_state::{PtzState, Position, Velocity, Preset};

let state = std::sync::Arc::new(PtzState::new());

state.absolute_move(Position { x: 0.8, y: 0.2, zoom: 0.5 }); // eased toward target
state.continuous_move(Velocity { x: 0.1, y: 0.0, zoom: 0.0 }); // integrates while ticking
state.stop();
state.relative_move(Velocity { x: -0.1, y: 0.05, zoom: 0.0 });
state.tick(100); // advance simulation by dt milliseconds

let Position { x, y, zoom } = state.get_position();
let status = state.get_status();        // "IDLE" | "MOVING"
let token = state.save_preset("Gate");  // returns a preset token
state.goto_preset(&token);
let presets: Vec<Preset> = state.list_presets();
```

- **ContinuousMove** integrates velocity per tick; **AbsoluteMove**
  eases to the target over up to 20 ticks; status is `IDLE`/`MOVING`.
- Coordinates are normalized `[-1, 1]` pan/tilt, `[0, 1]` zoom — map to
  real angles in your client or UI.
- Tick from any loop you like (a timer task, your render loop).

## Wiring the handler

One `PtzHandler` serves all eleven PTZ actions:

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

`examples/ptz_demo.rs` runs the whole verb set against a live server —
absolute-move landing exactly, continuous-move drifting under the tick
loop, preset round-trips — with assertions, then exits 0.

## Real motors

`PtzState` is a complete reference implementation, not a requirement:
hosts with real PTZ hardware implement the same actions as custom
[`OnvifActionHandler`]s and drive their motors directly.
