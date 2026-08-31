# Imaging service: the ImagingParams seam

Imaging (brightness, contrast, saturation, focus, …) is host hardware —
the library translates one small trait into three ONVIF actions.

## The seam

```rust
use onvif_device_rs::imaging::{ImagingParams, ImagingParamError};

struct MyCameraControls { /* v4l2 / ISP handle, ... */ }

impl ImagingParams for MyCameraControls {
    /// Read a parameter by its ONVIF name (e.g. "Brightness").
    fn get_param(&self, name: &str) -> Result<f64, ImagingParamError> {
        // translate the ONVIF name to your control and normalize to [0.0, 1.0]
    }
    /// Write a parameter; `value` is normalized to [0.0, 1.0].
    fn set_param(&self, name: &str, value: f64) -> Result<(), ImagingParamError> {
        // scale [0,1] onto your hardware range
    }
    /// Optional: exposure/white-balance modes reported by GetImagingSettings.
    /// Defaults report "AUTO" (the historical wire value).
}
```

All values are normalized to `[0.0, 1.0]` on the wire — your impl maps
that onto the hardware range in both directions.

## Errors become semantic faults

```rust
pub enum ImagingParamError {
    InvalidName(String),                    // → Sender/InvalidArg fault
    OutOfRange { value: f64, min: f64, max: f64 }, // → Sender/OutOfRange fault
    Io(String),                             // → Receiver/action fault
}
```

Return the right variant and the client sees the correct SOAP fault —
no envelope building on your side.

## One-line registration

```rust
use std::sync::Arc;
use onvif_device_rs::imaging::register_imaging_actions;

register_imaging_actions(&mut soap, Arc::new(MyCameraControls { /* ... */ }));
```

Registers `GetImagingSettings`, `SetImagingSettings`, and `GetOptions`
(name/min/max from your `get_param` rejections or the documented set —
see `examples/imaging_demo.rs`, which also demonstrates an
out-of-range request producing the fault).
