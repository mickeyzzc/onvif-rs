//! ONVIF device-IO service client family (the twin of the Go library's
//! `deviceio` package): relay outputs, digital inputs, serial ports, video
//! outputs, and the physical audio-output configuration family.
//!
//! Everything rides the client's configured device endpoint — the Go twin's
//! `getDeviceIOEndpoint` resolves `ServiceDevice` too. Two wire quirks are
//! mirrored byte-for-byte from the Go marshal: the relay-output trio
//! (`GetRelayOutputs` / `SetRelayOutputSettings` / `SetRelayOutputState`)
//! uses the `tds:` ELEMENT PREFIX bound to the deviceIO namespace, and
//! `SetRelayOutputSettings` writes its `tt:`-prefixed property children
//! without declaring `xmlns:tt` (Go never injects the declaration).
//!
//! Beyond the Go twin (both deltas field-proven by the crate's own
//! helpers): relay `DelayTime` is decoded on read (ISO 8601 duration via
//! `crate::events::parse_iso8601_duration`, ZERO when absent/unparseable —
//! Go never parses it) and formatted on write when non-zero (Go always
//! sends an empty element).

use std::time::Duration;

use super::events_pull::extract_elements_by_name;
use super::{local_name, text_content, ClientError, SoapClient};

/// tmd (device IO service) namespace.
const TMD_NS: &str = "http://www.onvif.org/ver10/deviceIO/wsdl";
/// tt (schema) namespace.
const TT_NS: &str = "http://www.onvif.org/ver10/schema";

/// Idle state of a digital input: [`DIGITAL_IDLE_OPEN`] or
/// [`DIGITAL_IDLE_CLOSED`].
pub type DigitalIdleState = String;

/// Digital input idle state: open.
pub const DIGITAL_IDLE_OPEN: &str = "open";
/// Digital input idle state: closed.
pub const DIGITAL_IDLE_CLOSED: &str = "closed";

/// Serial port type: [`SERIAL_PORT_TYPE_RS232`] etc.
pub type SerialPortType = String;

/// Serial port type constant: RS232.
pub const SERIAL_PORT_TYPE_RS232: &str = "RS232";
/// Serial port type constant: RS422.
pub const SERIAL_PORT_TYPE_RS422: &str = "RS422";
/// Serial port type constant: RS485.
pub const SERIAL_PORT_TYPE_RS485: &str = "RS485";
/// Serial port type constant: Generic.
pub const SERIAL_PORT_TYPE_GENERIC: &str = "Generic";

/// Parity bit setting: [`PARITY_NONE`], [`PARITY_ODD`], …
pub type ParityBit = String;

/// Parity bit constant: None.
pub const PARITY_NONE: &str = "None";
/// Parity bit constant: Odd.
pub const PARITY_ODD: &str = "Odd";
/// Parity bit constant: Even.
pub const PARITY_EVEN: &str = "Even";
/// Parity bit constant: Mark.
pub const PARITY_MARK: &str = "Mark";
/// Parity bit constant: Space.
pub const PARITY_SPACE: &str = "Space";

/// Relay mode: [`RELAY_MODE_MONOSTABLE`] or [`RELAY_MODE_BISTABLE`].
pub type RelayMode = String;

/// Relay mode constant: Monostable.
pub const RELAY_MODE_MONOSTABLE: &str = "Monostable";
/// Relay mode constant: Bistable.
pub const RELAY_MODE_BISTABLE: &str = "Bistable";

/// Relay idle state: [`RELAY_IDLE_STATE_OPEN`] or
/// [`RELAY_IDLE_STATE_CLOSED`].
pub type RelayIdleState = String;

/// Relay idle state constant: closed.
pub const RELAY_IDLE_STATE_CLOSED: &str = "closed";
/// Relay idle state constant: open.
pub const RELAY_IDLE_STATE_OPEN: &str = "open";

/// Relay logical (live) state: [`RELAY_LOGICAL_STATE_ACTIVE`] or
/// [`RELAY_LOGICAL_STATE_INACTIVE`] — the field NVR alarm-linkage polls.
pub type RelayLogicalState = String;

/// Relay logical state constant: active.
pub const RELAY_LOGICAL_STATE_ACTIVE: &str = "active";
/// Relay logical state constant: inactive.
pub const RELAY_LOGICAL_STATE_INACTIVE: &str = "inactive";

/// The capabilities of a device's device-IO service.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceIoServiceCapabilities {
    /// Number of video sources.
    pub video_sources: i32,
    /// Number of video outputs.
    pub video_outputs: i32,
    /// Number of audio sources.
    pub audio_sources: i32,
    /// Number of audio outputs.
    pub audio_outputs: i32,
    /// Number of relay outputs.
    pub relay_outputs: i32,
    /// Number of serial ports.
    pub serial_ports: i32,
    /// Number of digital inputs.
    pub digital_inputs: i32,
    /// Digital inputs are configurable.
    pub digital_input_options: bool,
    /// Serial ports are configurable.
    pub serial_port_configuration: bool,
}

/// A digital input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DigitalInput {
    /// Configuration token.
    pub token: String,
    /// Idle state ([`DIGITAL_IDLE_OPEN`] / [`DIGITAL_IDLE_CLOSED`]).
    pub idle_state: DigitalIdleState,
}

/// A video output.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VideoOutput {
    /// Configuration token.
    pub token: String,
    /// Pane layout, when the device reports one.
    pub layout: Option<Layout>,
    /// Output resolution, when the device reports one.
    pub resolution: Option<VideoResolution>,
    /// Refresh rate in Hz.
    pub refresh_rate: f64,
    /// Aspect ratio (e.g. `"16:9"`).
    pub aspect_ratio: String,
}

/// A video output's pane layout.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Layout {
    /// The layout's panes.
    pub pane: Vec<PaneLayout>,
}

/// One pane of a video output layout.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PaneLayout {
    /// The pane's token.
    pub pane: String,
    /// The pane's area (normalized rectangle).
    pub area: FloatRectangle,
}

/// A floating-point (normalized) rectangle.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FloatRectangle {
    /// Bottom edge.
    pub bottom: f64,
    /// Top edge.
    pub top: f64,
    /// Right edge.
    pub right: f64,
    /// Left edge.
    pub left: f64,
}

/// A video resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VideoResolution {
    /// Width in pixels.
    pub width: i32,
    /// Height in pixels.
    pub height: i32,
}

/// A serial port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SerialPort {
    /// Configuration token.
    pub token: String,
    /// Port type ([`SERIAL_PORT_TYPE_RS232`] etc.).
    pub kind: SerialPortType,
}

/// A serial port configuration.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SerialPortConfiguration {
    /// Configuration token.
    pub token: String,
    /// Port type ([`SERIAL_PORT_TYPE_RS232`] etc.).
    pub kind: SerialPortType,
    /// Baud rate in baud.
    pub baud_rate: i32,
    /// Parity ([`PARITY_NONE`] etc.).
    pub parity_bit: ParityBit,
    /// Character length in bits.
    pub character_length: i32,
    /// Stop bits (fractional values legal, e.g. 1.5).
    pub stop_bit: f64,
}

/// Valid configuration ranges of one serial port.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SerialPortConfigurationOptions {
    /// Configuration token.
    pub token: String,
    /// Selectable baud rates.
    pub baud_rate_list: Vec<i32>,
    /// Selectable parity settings.
    pub parity_bit_list: Vec<ParityBit>,
    /// Selectable character lengths.
    pub character_length_list: Vec<i32>,
    /// Selectable stop-bit values.
    pub stop_bit_list: Vec<f64>,
}

/// Valid configuration options of a digital input.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DigitalInputConfigurationOptions {
    /// Selectable idle states.
    pub idle_state_options: Vec<DigitalIdleState>,
}

/// A video output configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VideoOutputConfiguration {
    /// Configuration token.
    pub token: String,
    /// Configuration name.
    pub name: String,
    /// Use count.
    pub use_count: i32,
    /// Token of the output this configuration drives.
    pub output_token: String,
    /// Ask the device to keep the configuration across reboots (set only).
    pub force_persistence: bool,
}

/// Valid configuration options of a video output configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VideoOutputConfigurationOptions {
    /// Allowed name length range.
    pub name: StringRange,
    /// Tokens of outputs this configuration may drive.
    pub output_tokens_available: Vec<String>,
}

/// An inclusive integer range.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StringRange {
    /// Minimum value.
    pub min: i32,
    /// Maximum value.
    pub max: i32,
}

/// Valid configuration options of a relay output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayOutputOptions {
    /// Configuration token.
    pub token: String,
    /// Selectable modes ([`RELAY_MODE_MONOSTABLE`] etc.).
    pub mode: Vec<RelayMode>,
    /// Selectable delay times.
    pub delay_times: Vec<String>,
    /// Whether only discrete delay times are selectable.
    pub discrete: bool,
}

/// A relay output (the field NVR alarm-linkage drives).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayOutput {
    /// Configuration token.
    pub token: String,
    /// Live relay state ([`RELAY_LOGICAL_STATE_ACTIVE`] etc.).
    pub logical_state: RelayLogicalState,
    /// The relay's configured settings.
    pub properties: RelayOutputSettings,
}

/// A relay output's settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayOutputSettings {
    /// Relay mode ([`RELAY_MODE_MONOSTABLE`] etc.).
    pub mode: RelayMode,
    /// Monostable hold time (ZERO when the device reports none or a value
    /// this crate cannot parse — the Go twin never decodes it at all).
    pub delay_time: Duration,
    /// Idle state ([`RELAY_IDLE_STATE_OPEN`] etc.).
    pub idle_state: RelayIdleState,
}

/// `tt:AudioOutputConfiguration` — how a physical audio output renders its
/// source (level, primacy).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioOutputConfiguration {
    /// Configuration token.
    pub token: String,
    /// Configuration name.
    pub name: String,
    /// Use count.
    pub use_count: i32,
    /// Token of the audio source this output renders.
    pub source_token: String,
    /// Output volume level.
    pub output_level: i32,
    /// Send primacy mode (e.g. a duplex profile URI).
    pub send_primacy: String,
}

/// `tt:AudioOutputConfigurationOptions` — valid ranges for a physical
/// audio output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioOutputConfigurationOptions {
    /// Allowed output level range, when reported.
    pub output_levels_range: Option<IntRange>,
    /// Send-primacy modes (whitespace-split from the single wire element).
    pub send_primacy_options: Vec<String>,
}

/// An inclusive integer range (the twin of the Go `types.IntRange`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntRange {
    /// Minimum value.
    pub min: i32,
    /// Maximum value.
    pub max: i32,
}

impl SoapClient {
    /// Read the device-IO service capabilities (GetServiceCapabilities).
    pub async fn get_device_io_service_capabilities(
        &self,
    ) -> Result<DeviceIoServiceCapabilities, ClientError> {
        let body = tmd_action("tmd:GetServiceCapabilities");
        let resp = self.device_call(&body).await?;
        parse_deviceio_capabilities(&resp)
    }

    /// List the digital inputs (GetDigitalInputs).
    pub async fn get_digital_inputs(&self) -> Result<Vec<DigitalInput>, ClientError> {
        let body = tmd_action("tmd:GetDigitalInputs");
        let resp = self.device_call(&body).await?;
        parse_digital_inputs(&resp)
    }

    /// Read a digital input's configuration options
    /// (GetDigitalInputConfigurationOptions).
    pub async fn get_digital_input_configuration_options(
        &self,
        token: &str,
    ) -> Result<DigitalInputConfigurationOptions, ClientError> {
        if token.is_empty() {
            return Err(invalid_token("digital input"));
        }
        let body = tmd_token_action(
            "tmd:GetDigitalInputConfigurationOptions",
            "tmd:Token",
            token,
        );
        let resp = self.device_call(&body).await?;
        parse_digital_input_options(&resp)
    }

    /// Push digital input configurations (SetDigitalInputConfigurations).
    /// Every entry's token must be non-empty.
    pub async fn set_digital_input_configurations(
        &self,
        inputs: &[DigitalInput],
    ) -> Result<(), ClientError> {
        let body = build_set_digital_input_configurations_request(inputs)?;
        self.device_call(&body).await?;
        Ok(())
    }

    /// List the video outputs (GetVideoOutputs).
    pub async fn get_video_outputs(&self) -> Result<Vec<VideoOutput>, ClientError> {
        let body = tmd_action("tmd:GetVideoOutputs");
        let resp = self.device_call(&body).await?;
        parse_video_outputs(&resp)
    }

    /// List the serial ports (GetSerialPorts).
    pub async fn get_serial_ports(&self) -> Result<Vec<SerialPort>, ClientError> {
        let body = tmd_action("tmd:GetSerialPorts");
        let resp = self.device_call(&body).await?;
        parse_serial_ports(&resp)
    }

    /// Read a serial port's configuration (GetSerialPortConfiguration).
    pub async fn get_serial_port_configuration(
        &self,
        serial_port_token: &str,
    ) -> Result<SerialPortConfiguration, ClientError> {
        if serial_port_token.is_empty() {
            return Err(invalid_token("serial port"));
        }
        let body = tmd_token_action(
            "tmd:GetSerialPortConfiguration",
            "tmd:SerialPortToken",
            serial_port_token,
        );
        let resp = self.device_call(&body).await?;
        parse_serial_port_configuration(&resp)
    }

    /// Read a serial port's valid configuration ranges
    /// (GetSerialPortConfigurationOptions).
    pub async fn get_serial_port_configuration_options(
        &self,
        serial_port_token: &str,
    ) -> Result<SerialPortConfigurationOptions, ClientError> {
        if serial_port_token.is_empty() {
            return Err(invalid_token("serial port"));
        }
        let body = tmd_token_action(
            "tmd:GetSerialPortConfigurationOptions",
            "tmd:SerialPortToken",
            serial_port_token,
        );
        let resp = self.device_call(&body).await?;
        parse_serial_port_options(&resp)
    }

    /// Push a serial port configuration (SetSerialPortConfiguration). The
    /// token must be non-empty.
    pub async fn set_serial_port_configuration(
        &self,
        config: &SerialPortConfiguration,
    ) -> Result<(), ClientError> {
        if config.token.is_empty() {
            return Err(invalid_token("serial port"));
        }
        let body = build_set_serial_port_configuration_request(config);
        self.device_call(&body).await?;
        Ok(())
    }

    /// Send a serial command and read the reply
    /// (SendReceiveSerialCommand). `data` is carried as the request's
    /// `tt:Binary` text (the Go twin's string flavor, not base64);
    /// `timeout_seconds` becomes a `PTnS` TimeOut when positive;
    /// `data_length` (expected reply length) is omitted when zero.
    pub async fn send_receive_serial_command(
        &self,
        serial_port_token: &str,
        data: &[u8],
        timeout_seconds: u32,
        data_length: u32,
    ) -> Result<Vec<u8>, ClientError> {
        if serial_port_token.is_empty() {
            return Err(invalid_token("serial port"));
        }
        if data.is_empty() {
            return Err(ClientError::InvalidArgument(
                "invalid serial data: cannot be empty".into(),
            ));
        }
        let body = build_send_receive_serial_command_request(
            serial_port_token,
            data,
            timeout_seconds,
            data_length,
        );
        let resp = self.device_call(&body).await?;
        parse_serial_command_response(&resp)
    }

    /// Read a video output configuration (GetVideoOutputConfiguration).
    pub async fn get_video_output_configuration(
        &self,
        video_output_token: &str,
    ) -> Result<VideoOutputConfiguration, ClientError> {
        if video_output_token.is_empty() {
            return Err(invalid_token("video output"));
        }
        let body = tmd_token_action(
            "tmd:GetVideoOutputConfiguration",
            "tmd:VideoOutputToken",
            video_output_token,
        );
        let resp = self.device_call(&body).await?;
        parse_video_output_configuration(&resp)
    }

    /// Read a video output configuration's options
    /// (GetVideoOutputConfigurationOptions).
    pub async fn get_video_output_configuration_options(
        &self,
        video_output_token: &str,
    ) -> Result<VideoOutputConfigurationOptions, ClientError> {
        if video_output_token.is_empty() {
            return Err(invalid_token("video output"));
        }
        let body = tmd_token_action(
            "tmd:GetVideoOutputConfigurationOptions",
            "tmd:VideoOutputToken",
            video_output_token,
        );
        let resp = self.device_call(&body).await?;
        parse_video_output_options(&resp)
    }

    /// Push a video output configuration (SetVideoOutputConfiguration).
    /// The token must be non-empty.
    pub async fn set_video_output_configuration(
        &self,
        config: &VideoOutputConfiguration,
    ) -> Result<(), ClientError> {
        if config.token.is_empty() {
            return Err(invalid_token("video output"));
        }
        let body = build_set_video_output_configuration_request(config);
        self.device_call(&body).await?;
        Ok(())
    }

    /// Read a relay output's options (GetRelayOutputOptions).
    pub async fn get_relay_output_options(
        &self,
        relay_output_token: &str,
    ) -> Result<RelayOutputOptions, ClientError> {
        if relay_output_token.is_empty() {
            return Err(invalid_token("relay output"));
        }
        let body = tmd_token_action(
            "tmd:GetRelayOutputOptions",
            "tmd:RelayOutputToken",
            relay_output_token,
        );
        let resp = self.device_call(&body).await?;
        parse_relay_output_options(&resp)
    }

    /// List the relay outputs with their live states and settings
    /// (GetRelayOutputs). Mirrors the Go marshal quirk: the `tds:` element
    /// prefix bound to the deviceIO namespace.
    pub async fn get_relay_outputs(&self) -> Result<Vec<RelayOutput>, ClientError> {
        let body = tds_deviceio_action("tds:GetRelayOutputs");
        let resp = self.device_call(&body).await?;
        parse_relay_outputs(&resp)
    }

    /// Push a relay output's settings (SetRelayOutputSettings). Mirrors the
    /// Go marshal quirks: `tds:` prefix bound to the deviceIO namespace and
    /// `tt:` property children without an `xmlns:tt` declaration; the
    /// always-present `tt:DelayTime` element carries the formatted delay
    /// when non-zero (the Go twin sends it empty).
    pub async fn set_relay_output_settings(
        &self,
        token: &str,
        settings: &RelayOutputSettings,
    ) -> Result<(), ClientError> {
        let body = build_set_relay_output_settings_request(token, settings);
        self.device_call(&body).await?;
        Ok(())
    }

    /// Drive a relay output's live state (SetRelayOutputState) — the NVR
    /// alarm-linkage primitive.
    pub async fn set_relay_output_state(
        &self,
        token: &str,
        state: RelayLogicalState,
    ) -> Result<(), ClientError> {
        let body = build_set_relay_output_state_request(token, &state);
        self.device_call(&body).await?;
        Ok(())
    }

    /// List the physical audio output tokens (the `tmd:Get` flavor: a bare
    /// token list). Named with the `deviceio_` qualifier because the Media
    /// service exposes its own (full-entity) `GetAudioOutputs` under the
    /// same Go name — inherent methods on the shared client would collide.
    pub async fn get_deviceio_audio_outputs(&self) -> Result<Vec<String>, ClientError> {
        let body = tmd_action("tmd:GetAudioOutputs");
        let resp = self.device_call(&body).await?;
        parse_audio_output_tokens(&resp)
    }

    /// Read a physical audio output's configuration
    /// (GetAudioOutputConfiguration; `deviceio_`-qualified for the same
    /// collision reason as [`SoapClient::get_deviceio_audio_outputs`]).
    pub async fn get_deviceio_audio_output_configuration(
        &self,
        audio_output_token: &str,
    ) -> Result<AudioOutputConfiguration, ClientError> {
        let body = tmd_token_action(
            "tmd:GetAudioOutputConfiguration",
            "tmd:AudioOutputToken",
            audio_output_token,
        );
        let resp = self.device_call(&body).await?;
        parse_audio_output_configuration(&resp)
    }

    /// Read a physical audio output's valid ranges
    /// (GetAudioOutputConfigurationOptions; `deviceio_`-qualified for the
    /// same collision reason as [`SoapClient::get_deviceio_audio_outputs`]).
    pub async fn get_deviceio_audio_output_configuration_options(
        &self,
        audio_output_token: &str,
    ) -> Result<AudioOutputConfigurationOptions, ClientError> {
        let body = tmd_token_action(
            "tmd:GetAudioOutputConfigurationOptions",
            "tmd:AudioOutputToken",
            audio_output_token,
        );
        let resp = self.device_call(&body).await?;
        parse_audio_output_options(&resp)
    }

    /// Push a physical audio output configuration
    /// (SetAudioOutputConfiguration); `force_persistence` asks the device
    /// to keep it across reboots.
    pub async fn set_audio_output_configuration(
        &self,
        config: &AudioOutputConfiguration,
        force_persistence: bool,
    ) -> Result<(), ClientError> {
        let body = build_set_audio_output_configuration_request(config, force_persistence);
        self.device_call(&body).await?;
        Ok(())
    }
}

/// The Go twin's empty-token rejection, worded per its sentinels
/// (`invalid digital input token: cannot be empty` &c).
fn invalid_token(kind: &str) -> ClientError {
    ClientError::InvalidArgument(format!("invalid {kind} token: cannot be empty"))
}

// ---------------------------------------------------------------------------
// Request builders (Go-marshal byte-compatible)
// ---------------------------------------------------------------------------

/// A bare `tmd:` action element.
fn tmd_action(action: &str) -> String {
    format!("<{action} xmlns:tmd=\"{TMD_NS}\"></{action}>")
}

/// The relay trio's shape: a `tds:` PREFIX bound to the deviceIO namespace
/// (the Go marshal quirk, mirrored).
fn tds_deviceio_action(action: &str) -> String {
    format!("<{action} xmlns:tds=\"{TMD_NS}\"></{action}>")
}

/// A one-token `tmd:` action (`<tmd:X …><tmd:Child>token</tmd:Child></tmd:X>`).
fn tmd_token_action(action: &str, child: &str, token: &str) -> String {
    format!(
        "<{action} xmlns:tmd=\"{TMD_NS}\"><{child}>{}</{child}></{action}>",
        crate::types::xml_escape(token)
    )
}

/// SetDigitalInputConfigurations body: one `tmd:DigitalInputs` element per
/// input, `token` then optional `IdleState` attributes (Go marshal order).
fn build_set_digital_input_configurations_request(
    inputs: &[DigitalInput],
) -> Result<String, ClientError> {
    if inputs.is_empty() {
        return Err(ClientError::InvalidArgument(
            "digital input config cannot be nil".into(),
        ));
    }
    let mut items = String::new();
    for input in inputs {
        if input.token.is_empty() {
            return Err(invalid_token("digital input"));
        }
        let idle = if input.idle_state.is_empty() {
            String::new()
        } else {
            format!(
                " IdleState=\"{}\"",
                crate::types::xml_escape(&input.idle_state)
            )
        };
        items.push_str(&format!(
            "<tmd:DigitalInputs token=\"{}\"{idle}></tmd:DigitalInputs>",
            crate::types::xml_escape(&input.token)
        ));
    }
    Ok(format!(
        "<tmd:SetDigitalInputConfigurations xmlns:tmd=\"{TMD_NS}\">{items}\
         </tmd:SetDigitalInputConfigurations>"
    ))
}

/// SetSerialPortConfiguration body (all five child elements always present,
/// the Go marshal's no-omitempty shape).
fn build_set_serial_port_configuration_request(config: &SerialPortConfiguration) -> String {
    format!(
        "<tmd:SetSerialPortConfiguration xmlns:tmd=\"{TMD_NS}\">\
         <tmd:SerialPortConfiguration token=\"{}\">\
         <tmd:Type>{}</tmd:Type><tmd:BaudRate>{}</tmd:BaudRate>\
         <tmd:ParityBit>{}</tmd:ParityBit><tmd:CharacterLength>{}</tmd:CharacterLength>\
         <tmd:StopBit>{}</tmd:StopBit></tmd:SerialPortConfiguration>\
         </tmd:SetSerialPortConfiguration>",
        crate::types::xml_escape(&config.token),
        crate::types::xml_escape(&config.kind),
        config.baud_rate,
        crate::types::xml_escape(&config.parity_bit),
        config.character_length,
        config.stop_bit
    )
}

/// SendReceiveSerialCommand body — `TimeOut` only when positive (plain
/// `PTnS`, not the minute-factoring formatter), `DataLength` omitted at 0.
fn build_send_receive_serial_command_request(
    serial_port_token: &str,
    data: &[u8],
    timeout_seconds: u32,
    data_length: u32,
) -> String {
    let timeout_elem = if timeout_seconds > 0 {
        format!("<tmd:TimeOut>PT{timeout_seconds}S</tmd:TimeOut>")
    } else {
        String::new()
    };
    let length_elem = if data_length > 0 {
        format!("<tmd:DataLength>{data_length}</tmd:DataLength>")
    } else {
        String::new()
    };
    format!(
        "<tmd:SendReceiveSerialCommand xmlns:tmd=\"{TMD_NS}\" xmlns:tt=\"{TT_NS}\">\
         <tmd:Token>{}</tmd:Token>\
         <tmd:SerialData><tt:Binary>{}</tt:Binary></tmd:SerialData>{timeout_elem}{length_elem}\
         </tmd:SendReceiveSerialCommand>",
        crate::types::xml_escape(serial_port_token),
        crate::types::xml_escape(&String::from_utf8_lossy(data))
    )
}

/// SetVideoOutputConfiguration body.
fn build_set_video_output_configuration_request(config: &VideoOutputConfiguration) -> String {
    format!(
        "<tmd:SetVideoOutputConfiguration xmlns:tmd=\"{TMD_NS}\" xmlns:tt=\"{TT_NS}\">\
         <tmd:Configuration token=\"{}\">\
         <tt:Name>{}</tt:Name><tt:UseCount>{}</tt:UseCount><tt:OutputToken>{}</tt:OutputToken>\
         </tmd:Configuration><tmd:ForcePersistence>{}</tmd:ForcePersistence>\
         </tmd:SetVideoOutputConfiguration>",
        crate::types::xml_escape(&config.token),
        crate::types::xml_escape(&config.name),
        config.use_count,
        crate::types::xml_escape(&config.output_token),
        config.force_persistence
    )
}

/// SetRelayOutputSettings body — the Go quirks mirrored: `tds:` prefix on
/// the deviceIO namespace and `tt:` children without `xmlns:tt`; the
/// always-present `tt:DelayTime` carries the formatted delay when non-zero
/// (Go sends it empty).
fn build_set_relay_output_settings_request(token: &str, settings: &RelayOutputSettings) -> String {
    let delay = if settings.delay_time.is_zero() {
        String::new()
    } else {
        super::format_xs_duration(settings.delay_time)
    };
    format!(
        "<tds:SetRelayOutputSettings xmlns:tds=\"{TMD_NS}\">\
         <tds:RelayOutputToken>{}</tds:RelayOutputToken>\
         <tds:Properties><tt:Mode>{}</tt:Mode><tt:DelayTime>{delay}</tt:DelayTime>\
         <tt:IdleState>{}</tt:IdleState></tds:Properties></tds:SetRelayOutputSettings>",
        crate::types::xml_escape(token),
        crate::types::xml_escape(&settings.mode),
        crate::types::xml_escape(&settings.idle_state)
    )
}

/// SetRelayOutputState body (the `tds:`-on-deviceIO quirk mirrored).
fn build_set_relay_output_state_request(token: &str, state: &str) -> String {
    format!(
        "<tds:SetRelayOutputState xmlns:tds=\"{TMD_NS}\">\
         <tds:RelayOutputToken>{}</tds:RelayOutputToken><tds:LogicalState>{}</tds:LogicalState>\
         </tds:SetRelayOutputState>",
        crate::types::xml_escape(token),
        crate::types::xml_escape(state)
    )
}

/// SetAudioOutputConfiguration body — `tt:SendPrimacy` omitted when empty.
fn build_set_audio_output_configuration_request(
    config: &AudioOutputConfiguration,
    force_persistence: bool,
) -> String {
    let primacy = if config.send_primacy.is_empty() {
        String::new()
    } else {
        format!(
            "<tt:SendPrimacy>{}</tt:SendPrimacy>",
            crate::types::xml_escape(&config.send_primacy)
        )
    };
    format!(
        "<tmd:SetAudioOutputConfiguration xmlns:tmd=\"{TMD_NS}\" xmlns:tt=\"{TT_NS}\">\
         <tmd:Configuration token=\"{}\">\
         <tt:Name>{}</tt:Name><tt:UseCount>{}</tt:UseCount>\
         <tt:SourceToken>{}</tt:SourceToken><tt:OutputLevel>{}</tt:OutputLevel>{primacy}\
         </tmd:Configuration><tmd:ForcePersistence>{force_persistence}</tmd:ForcePersistence>\
         </tmd:SetAudioOutputConfiguration>",
        crate::types::xml_escape(&config.token),
        crate::types::xml_escape(&config.name),
        config.use_count,
        crate::types::xml_escape(&config.source_token),
        config.output_level
    )
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

/// Attribute value by local name (namespace-prefix tolerant).
fn attr(e: &quick_xml::events::BytesStart<'_>, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| {
            let key = String::from_utf8_lossy(a.key.as_ref());
            match key.rsplit_once(':') {
                Some((_, local)) => local == name,
                None => key == name,
            }
        })
        .map(|a| String::from_utf8_lossy(&a.value).into_owned())
}

/// Boolean attribute (`true`/`1` true, anything else false).
fn attr_bool(e: &quick_xml::events::BytesStart<'_>, name: &str) -> bool {
    matches!(attr(e, name).as_deref(), Some("true" | "1"))
}

/// Integer attribute, 0 when absent or garbage.
fn attr_i32(e: &quick_xml::events::BytesStart<'_>, name: &str) -> i32 {
    attr(e, name)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

/// Float attribute, 0.0 when absent or garbage.
fn attr_f64(e: &quick_xml::events::BytesStart<'_>, name: &str) -> f64 {
    attr(e, name)
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0.0)
}

/// Lenient integer text.
fn text_i32(text: &str) -> i32 {
    text.trim().parse().unwrap_or(0)
}

/// Lenient float text.
fn text_f64(text: &str) -> f64 {
    text.trim().parse().unwrap_or(0.0)
}

/// Lift the Capabilities element of a GetServiceCapabilitiesResponse.
fn parse_deviceio_capabilities(resp: &str) -> Result<DeviceIoServiceCapabilities, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut caps = DeviceIoServiceCapabilities::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e)) => {
                if local_name(&e) == "Capabilities" {
                    caps.video_sources = attr_i32(&e, "VideoSources");
                    caps.video_outputs = attr_i32(&e, "VideoOutputs");
                    caps.audio_sources = attr_i32(&e, "AudioSources");
                    caps.audio_outputs = attr_i32(&e, "AudioOutputs");
                    caps.relay_outputs = attr_i32(&e, "RelayOutputs");
                    caps.serial_ports = attr_i32(&e, "SerialPorts");
                    caps.digital_inputs = attr_i32(&e, "DigitalInputs");
                    caps.digital_input_options = attr_bool(&e, "DigitalInputOptions");
                    caps.serial_port_configuration = attr_bool(&e, "SerialPortConfiguration");
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetServiceCapabilitiesResponse: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(caps)
}

/// Lift the DigitalInputs rows (attribute-only elements, self-closing or
/// paired).
fn parse_digital_inputs(resp: &str) -> Result<Vec<DigitalInput>, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut buf = Vec::new();
    let mut inputs = Vec::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) | Ok(XmlEvent::Empty(e)) => {
                if local_name(&e) == "DigitalInputs" {
                    inputs.push(DigitalInput {
                        token: attr(&e, "token").unwrap_or_default(),
                        idle_state: attr(&e, "IdleState").unwrap_or_default(),
                    });
                }
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("parse GetDigitalInputs: {e}"))),
        }
        buf.clear();
    }
    Ok(inputs)
}

/// Lift the IdleState options of a GetDigitalInputConfigurationOptions
/// response.
fn parse_digital_input_options(
    resp: &str,
) -> Result<DigitalInputConfigurationOptions, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut options = DigitalInputConfigurationOptions::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                stack.push(local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                if stack.last().map(String::as_str) == Some("IdleState") {
                    options.idle_state_options.push(text_content(&t));
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetDigitalInputConfigurationOptions: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(options)
}

/// Lift the VideoOutputs rows (fragment per output: layout panes with
/// normalized areas, resolution, refresh rate, aspect ratio).
fn parse_video_outputs(resp: &str) -> Result<Vec<VideoOutput>, ClientError> {
    let fragments = extract_elements_by_name(resp, "VideoOutputs")?;
    fragments
        .iter()
        .map(|f| parse_video_output_fragment(f))
        .collect()
}

/// Decode one VideoOutput element.
fn parse_video_output_fragment(fragment: &str) -> Result<VideoOutput, ClientError> {
    let mut reader = quick_xml::Reader::from_str(fragment);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();

    let mut out = VideoOutput::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                video_output_open_element(&mut out, &e, &name);
                stack.push(name);
            }
            Ok(XmlEvent::Empty(e)) => {
                video_output_open_element(&mut out, &e, &local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                let parent = stack.last().map(String::as_str).unwrap_or("");
                let grandparent = stack.iter().rev().nth(1).map(String::as_str).unwrap_or("");
                match (grandparent, parent) {
                    (_, "RefreshRate") => out.refresh_rate = text_f64(&text),
                    (_, "AspectRatio") => out.aspect_ratio = text,
                    ("Resolution", "Width") => {
                        out.resolution
                            .get_or_insert_with(VideoResolution::default)
                            .width = text_i32(&text);
                    }
                    ("Resolution", "Height") => {
                        out.resolution
                            .get_or_insert_with(VideoResolution::default)
                            .height = text_i32(&text);
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("parse VideoOutputs: {e}"))),
        }
        buf.clear();
    }
    Ok(out)
}

/// Handle one VideoOutput child opening (shared by Start and Empty events):
/// the root token attribute, Layout/Pane/Area structure.
fn video_output_open_element(
    out: &mut VideoOutput,
    e: &quick_xml::events::BytesStart<'_>,
    name: &str,
) {
    match name {
        "VideoOutputs" => out.token = attr(e, "token").unwrap_or_default(),
        "Pane" => out
            .layout
            .get_or_insert_with(Layout::default)
            .pane
            .push(PaneLayout {
                pane: attr(e, "Pane").unwrap_or_default(),
                area: FloatRectangle::default(),
            }),
        "Area" => {
            if let Some(area_pane) = out.layout.as_mut().and_then(|l| l.pane.last_mut()) {
                area_pane.area = FloatRectangle {
                    bottom: attr_f64(e, "bottom"),
                    top: attr_f64(e, "top"),
                    right: attr_f64(e, "right"),
                    left: attr_f64(e, "left"),
                };
            }
        }
        _ => {}
    }
}

/// Lift the SerialPorts rows.
fn parse_serial_ports(resp: &str) -> Result<Vec<SerialPort>, ClientError> {
    let fragments = extract_elements_by_name(resp, "SerialPorts")?;
    let mut ports = Vec::new();
    for fragment in &fragments {
        let mut reader = quick_xml::Reader::from_str(fragment);
        reader.config_mut().trim_text(true);

        let mut stack: Vec<String> = Vec::new();
        let mut buf = Vec::new();
        let mut port = SerialPort::default();

        loop {
            use quick_xml::events::Event as XmlEvent;
            match reader.read_event_into(&mut buf) {
                Ok(XmlEvent::Start(e)) => {
                    let name = local_name(&e);
                    if name == "SerialPorts" && stack.is_empty() {
                        port.token = attr(&e, "token").unwrap_or_default();
                    }
                    stack.push(name);
                }
                Ok(XmlEvent::Text(t)) => {
                    if stack.last().map(String::as_str) == Some("Type") {
                        port.kind = text_content(&t);
                    }
                }
                Ok(XmlEvent::End(_)) => {
                    stack.pop();
                }
                Ok(XmlEvent::Eof) => break,
                Ok(_) => {}
                Err(e) => return Err(ClientError::Parse(format!("parse SerialPorts: {e}"))),
            }
            buf.clear();
        }
        ports.push(port);
    }
    Ok(ports)
}

/// Lift the SerialPortConfiguration of a GetSerialPortConfiguration
/// response.
fn parse_serial_port_configuration(resp: &str) -> Result<SerialPortConfiguration, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut config = SerialPortConfiguration::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if name == "SerialPortConfiguration" {
                    config.token = attr(&e, "token").unwrap_or_default();
                }
                stack.push(name);
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                match stack.last().map(String::as_str) {
                    Some("Type") => config.kind = text,
                    Some("BaudRate") => config.baud_rate = text_i32(&text),
                    Some("ParityBit") => config.parity_bit = text,
                    Some("CharacterLength") => config.character_length = text_i32(&text),
                    Some("StopBit") => config.stop_bit = text_f64(&text),
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetSerialPortConfiguration: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(config)
}

/// Lift the `*List>Items` ranges of a GetSerialPortConfigurationOptions
/// response.
fn parse_serial_port_options(resp: &str) -> Result<SerialPortConfigurationOptions, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut options = SerialPortConfigurationOptions::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if name == "SerialPortConfigurationOptions" {
                    options.token = attr(&e, "token").unwrap_or_default();
                }
                stack.push(name);
            }
            Ok(XmlEvent::Empty(e)) => {
                if local_name(&e) == "SerialPortConfigurationOptions" {
                    options.token = attr(&e, "token").unwrap_or_default();
                }
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                let parent = stack.last().map(String::as_str).unwrap_or("");
                let grandparent = stack.iter().rev().nth(1).map(String::as_str).unwrap_or("");
                match (grandparent, parent) {
                    ("BaudRateList", "Items") => options.baud_rate_list.push(text_i32(&text)),
                    ("ParityBitList", "Items") => options.parity_bit_list.push(text),
                    ("CharacterLengthList", "Items") => {
                        options.character_length_list.push(text_i32(&text));
                    }
                    ("StopBitList", "Items") => options.stop_bit_list.push(text_f64(&text)),
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetSerialPortConfigurationOptions: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(options)
}

/// Lift the reply bytes of a SendReceiveSerialCommand response.
fn parse_serial_command_response(resp: &str) -> Result<Vec<u8>, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut data = String::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                stack.push(local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                if stack.last().map(String::as_str) == Some("Binary") {
                    data = text_content(&t);
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse SendReceiveSerialCommandResponse: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(data.into_bytes())
}

/// Lift the VideoOutputConfiguration of a GetVideoOutputConfiguration
/// response.
fn parse_video_output_configuration(resp: &str) -> Result<VideoOutputConfiguration, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut config = VideoOutputConfiguration::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if name == "VideoOutputConfiguration" {
                    config.token = attr(&e, "token").unwrap_or_default();
                }
                stack.push(name);
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                match stack.last().map(String::as_str) {
                    Some("Name") => config.name = text,
                    Some("UseCount") => config.use_count = text_i32(&text),
                    Some("OutputToken") => config.output_token = text,
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetVideoOutputConfiguration: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(config)
}

/// Lift the options of a GetVideoOutputConfigurationOptions response.
fn parse_video_output_options(resp: &str) -> Result<VideoOutputConfigurationOptions, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut options = VideoOutputConfigurationOptions::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if name == "Name" {
                    options.name.min = attr_i32(&e, "Min");
                    options.name.max = attr_i32(&e, "Max");
                }
                stack.push(name);
            }
            Ok(XmlEvent::Empty(e)) => {
                if local_name(&e) == "Name" {
                    options.name.min = attr_i32(&e, "Min");
                    options.name.max = attr_i32(&e, "Max");
                }
            }
            Ok(XmlEvent::Text(t)) => {
                if stack.last().map(String::as_str) == Some("OutputTokensAvailable") {
                    options.output_tokens_available.push(text_content(&t));
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetVideoOutputConfigurationOptions: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(options)
}

/// Lift the RelayOutputOptions of a GetRelayOutputOptions response.
fn parse_relay_output_options(resp: &str) -> Result<RelayOutputOptions, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut options = RelayOutputOptions::default();
    let mut saw_options = false;

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if name == "RelayOutputOptions" && !saw_options {
                    saw_options = true;
                    options.token = attr(&e, "token").unwrap_or_default();
                }
                stack.push(name);
            }
            Ok(XmlEvent::Empty(e)) => {
                let name = local_name(&e);
                if name == "RelayOutputOptions" && !saw_options {
                    saw_options = true;
                    options.token = attr(&e, "token").unwrap_or_default();
                }
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                match stack.last().map(String::as_str) {
                    Some("Mode") => options.mode.push(text),
                    Some("DelayTimes") => options.delay_times.push(text),
                    Some("Discrete") => options.discrete = text == "true" || text == "1",
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetRelayOutputOptions: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(options)
}

/// Lift the RelayOutputs rows: live logical state plus the Properties
/// block (DelayTime decoded as an ISO 8601 duration, ZERO when the device
/// reports none or something unparseable — the Go twin never decodes it).
fn parse_relay_outputs(resp: &str) -> Result<Vec<RelayOutput>, ClientError> {
    let fragments = extract_elements_by_name(resp, "RelayOutputs")?;
    fragments
        .iter()
        .map(|f| parse_relay_output_fragment(f))
        .collect()
}

/// Decode one RelayOutputs element.
fn parse_relay_output_fragment(fragment: &str) -> Result<RelayOutput, ClientError> {
    let mut reader = quick_xml::Reader::from_str(fragment);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut relay = RelayOutput::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if name == "RelayOutputs" && stack.is_empty() {
                    relay.token = attr(&e, "token").unwrap_or_default();
                }
                stack.push(name);
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                let parent = stack.last().map(String::as_str).unwrap_or("");
                let grandparent = stack.iter().rev().nth(1).map(String::as_str).unwrap_or("");
                match (grandparent, parent) {
                    (_, "LogicalState") => relay.logical_state = text,
                    ("Properties", "Mode") => relay.properties.mode = text,
                    ("Properties", "DelayTime") => {
                        relay.properties.delay_time =
                            crate::events::parse_iso8601_duration(&text).unwrap_or_default();
                    }
                    ("Properties", "IdleState") => relay.properties.idle_state = text,
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("parse RelayOutputs: {e}"))),
        }
        buf.clear();
    }
    Ok(relay)
}

/// Lift the bare Token list of a GetAudioOutputs response.
fn parse_audio_output_tokens(resp: &str) -> Result<Vec<String>, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut tokens = Vec::new();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                stack.push(local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                if stack.last().map(String::as_str) == Some("Token") {
                    tokens.push(text_content(&t));
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(ClientError::Parse(format!("parse GetAudioOutputs: {e}"))),
        }
        buf.clear();
    }
    Ok(tokens)
}

/// Lift the AudioOutputConfiguration of a GetAudioOutputConfiguration
/// response.
fn parse_audio_output_configuration(resp: &str) -> Result<AudioOutputConfiguration, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut config = AudioOutputConfiguration::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                let name = local_name(&e);
                if name == "AudioOutputConfiguration" {
                    config.token = attr(&e, "token").unwrap_or_default();
                }
                stack.push(name);
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                match stack.last().map(String::as_str) {
                    Some("Name") => config.name = text,
                    Some("UseCount") => config.use_count = text_i32(&text),
                    Some("SourceToken") => config.source_token = text,
                    Some("OutputLevel") => config.output_level = text_i32(&text),
                    Some("SendPrimacy") => config.send_primacy = text,
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetAudioOutputConfiguration: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(config)
}

/// Lift the options of a GetAudioOutputConfigurationOptions response (the
/// single whitespace-joined SendPrimacyOptions element is split).
fn parse_audio_output_options(resp: &str) -> Result<AudioOutputConfigurationOptions, ClientError> {
    let mut reader = quick_xml::Reader::from_str(resp);
    reader.config_mut().trim_text(true);

    let mut stack: Vec<String> = Vec::new();
    let mut buf = Vec::new();
    let mut options = AudioOutputConfigurationOptions::default();

    loop {
        use quick_xml::events::Event as XmlEvent;
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(e)) => {
                stack.push(local_name(&e));
            }
            Ok(XmlEvent::Text(t)) => {
                let text = text_content(&t);
                let parent = stack.last().map(String::as_str).unwrap_or("");
                let grandparent = stack.iter().rev().nth(1).map(String::as_str).unwrap_or("");
                match (grandparent, parent) {
                    ("OutputLevelsRange", "Min") => {
                        options
                            .output_levels_range
                            .get_or_insert_with(IntRange::default)
                            .min = text_i32(&text);
                    }
                    ("OutputLevelsRange", "Max") => {
                        options
                            .output_levels_range
                            .get_or_insert_with(IntRange::default)
                            .max = text_i32(&text);
                    }
                    (_, "SendPrimacyOptions") => {
                        options.send_primacy_options =
                            text.split_whitespace().map(str::to_string).collect();
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::End(_)) => {
                stack.pop();
            }
            Ok(XmlEvent::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(ClientError::Parse(format!(
                    "parse GetAudioOutputConfigurationOptions: {e}"
                )))
            }
        }
        buf.clear();
    }
    Ok(options)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- fixtures lifted from the Go twin's deviceio tests ---

    const CAPS_RESP: &str = r#"<GetServiceCapabilitiesResponse>
	<Capabilities VideoSources="2" VideoOutputs="1" AudioSources="1" AudioOutputs="1" RelayOutputs="4"/>
</GetServiceCapabilitiesResponse>"#;

    const DIGITAL_INPUTS_RESP: &str = r#"<GetDigitalInputsResponse>
	<DigitalInputs token="di-1" IdleState="closed"/>
	<DigitalInputs token="di-2" IdleState="open"></DigitalInputs>
</GetDigitalInputsResponse>"#;

    const SERIAL_PORTS_RESP: &str = r#"<GetSerialPortsResponse>
	<SerialPorts token="sp-1"><Type>RS485</Type></SerialPorts>
</GetSerialPortsResponse>"#;

    const VIDEO_OUTPUTS_RESP: &str = r#"<GetVideoOutputsResponse>
	<VideoOutputs token="vo-1">
		<Layout>
			<Pane Pane="Camera_1"><Area bottom="0" top="1" right="1" left="0"/></Pane>
			<Pane Pane="Camera_2"><Area bottom="0.5" top="1" right="1" left="0.5"/></Pane>
		</Layout>
		<Resolution><Width>1920</Width><Height>1080</Height></Resolution>
		<RefreshRate>60</RefreshRate>
		<AspectRatio>16:9</AspectRatio>
	</VideoOutputs>
</GetVideoOutputsResponse>"#;

    const SERIAL_CONFIG_RESP: &str = r#"<GetSerialPortConfigurationResponse>
	<SerialPortConfiguration token="sp-1">
		<Type>RS485</Type><BaudRate>9600</BaudRate><ParityBit>None</ParityBit>
		<CharacterLength>8</CharacterLength><StopBit>1.5</StopBit>
	</SerialPortConfiguration>
</GetSerialPortConfigurationResponse>"#;

    const SERIAL_OPTIONS_RESP: &str = r#"<GetSerialPortConfigurationOptionsResponse>
	<SerialPortConfigurationOptions token="sp-1">
		<BaudRateList><Items>9600</Items><Items>19200</Items></BaudRateList>
		<ParityBitList><Items>None</Items><Items>Even</Items></ParityBitList>
		<CharacterLengthList><Items>8</Items></CharacterLengthList>
		<StopBitList><Items>1</Items><Items>1.5</Items></StopBitList>
	</SerialPortConfigurationOptions>
</GetSerialPortConfigurationOptionsResponse>"#;

    const VIDEO_OUTPUT_CONFIG_RESP: &str = r#"<GetVideoOutputConfigurationResponse>
	<VideoOutputConfiguration token="voc-1">
		<Name>HDMI out</Name><UseCount>3</UseCount><OutputToken>vo-1</OutputToken>
	</VideoOutputConfiguration>
</GetVideoOutputConfigurationResponse>"#;

    const VIDEO_OUTPUT_OPTIONS_RESP: &str = r#"<GetVideoOutputConfigurationOptionsResponse>
	<VideoOutputConfigurationOptions>
		<Name Min="1" Max="32"/>
		<OutputTokensAvailable>vo-1</OutputTokensAvailable>
		<OutputTokensAvailable>vo-2</OutputTokensAvailable>
	</VideoOutputConfigurationOptions>
</GetVideoOutputConfigurationOptionsResponse>"#;

    const RELAY_OPTIONS_RESP: &str = r#"<GetRelayOutputOptionsResponse>
	<RelayOutputOptions token="ro-1">
		<Mode>Monostable</Mode><Mode>Bistable</Mode>
		<DelayTimes>PT1S</DelayTimes><DelayTimes>PT5S</DelayTimes>
		<Discrete>true</Discrete>
	</RelayOutputOptions>
</GetRelayOutputOptionsResponse>"#;

    const RELAYS_RESP: &str = r#"<GetRelayOutputsResponse>
	<RelayOutputs token="ro-1">
		<LogicalState>inactive</LogicalState>
		<Properties><Mode>Monostable</Mode><DelayTime>PT1S</DelayTime><IdleState>closed</IdleState></Properties>
	</RelayOutputs>
	<RelayOutputs token="ro-2">
		<LogicalState>active</LogicalState>
		<Properties><Mode>Bistable</Mode><DelayTime>1</DelayTime><IdleState>open</IdleState></Properties>
	</RelayOutputs>
</GetRelayOutputsResponse>"#;

    const AUDIO_OUTPUTS_RESP: &str = r#"<GetAudioOutputsResponse>
	<Token>AudioOutput_1</Token>
	<Token>AudioOutput_2</Token>
</GetAudioOutputsResponse>"#;

    const AUDIO_CONFIG_RESP: &str = r#"<GetAudioOutputConfigurationResponse>
	<AudioOutputConfiguration token="aoc-1">
		<Name>Speaker</Name><UseCount>1</UseCount>
		<SourceToken>AudioSource_1</SourceToken>
		<OutputLevel>50</OutputLevel>
		<SendPrimacy>www.onvif.org/ver20/HalfDuplex/HTTP</SendPrimacy>
	</AudioOutputConfiguration>
</GetAudioOutputConfigurationResponse>"#;

    const AUDIO_OPTIONS_RESP: &str = r#"<GetAudioOutputConfigurationOptionsResponse>
	<AudioOutputOptions>
		<OutputLevelsRange><Min>0</Min><Max>100</Max></OutputLevelsRange>
		<SendPrimacyOptions>www.onvif.org/ver20/HalfDuplex/HTTP www.onvif.org/ver20/FullDuplex/HTTP</SendPrimacyOptions>
	</AudioOutputOptions>
</GetAudioOutputConfigurationOptionsResponse>"#;

    // --- decode tests ---

    #[test]
    fn capabilities_decode() {
        let caps = parse_deviceio_capabilities(CAPS_RESP).unwrap();
        assert_eq!(caps.video_sources, 2);
        assert_eq!(caps.video_outputs, 1);
        assert_eq!(caps.audio_sources, 1);
        assert_eq!(caps.audio_outputs, 1);
        assert_eq!(caps.relay_outputs, 4);
    }

    #[test]
    fn digital_inputs_decode() {
        let inputs = parse_digital_inputs(DIGITAL_INPUTS_RESP).unwrap();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].token, "di-1");
        assert_eq!(inputs[0].idle_state, "closed");
        assert_eq!(inputs[1].token, "di-2");
        assert_eq!(inputs[1].idle_state, "open");
    }

    #[test]
    fn digital_input_options_decode() {
        let resp = r#"<GetDigitalInputConfigurationOptionsResponse>
	<DigitalInputConfigurationOptions><IdleState>open</IdleState><IdleState>closed</IdleState></DigitalInputConfigurationOptions>
</GetDigitalInputConfigurationOptionsResponse>"#;
        let options = parse_digital_input_options(resp).unwrap();
        assert_eq!(options.idle_state_options, vec!["open", "closed"]);
    }

    #[test]
    fn video_outputs_decode() {
        let outputs = parse_video_outputs(VIDEO_OUTPUTS_RESP).unwrap();
        assert_eq!(outputs.len(), 1);
        let out = &outputs[0];
        assert_eq!(out.token, "vo-1");
        assert_eq!(out.refresh_rate, 60.0);
        assert_eq!(out.aspect_ratio, "16:9");
        assert_eq!(
            out.resolution,
            Some(VideoResolution {
                width: 1920,
                height: 1080
            })
        );
        let layout = out.layout.as_ref().unwrap();
        assert_eq!(layout.pane.len(), 2);
        assert_eq!(layout.pane[0].pane, "Camera_1");
        assert_eq!(layout.pane[0].area.top, 1.0);
        assert_eq!(layout.pane[1].area.bottom, 0.5);
        assert_eq!(layout.pane[1].area.left, 0.5);

        // The Go twin's weak fixture (layout without panes) must not break.
        let bare = parse_video_outputs(
            r#"<GetVideoOutputsResponse><VideoOutputs token="vo-1"><Layout><Name>HDMI</Name></Layout></VideoOutputs></GetVideoOutputsResponse>"#,
        )
        .unwrap();
        assert_eq!(bare.len(), 1);
        assert_eq!(bare[0].token, "vo-1");
    }

    #[test]
    fn serial_ports_decode() {
        let ports = parse_serial_ports(SERIAL_PORTS_RESP).unwrap();
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].token, "sp-1");
        assert_eq!(ports[0].kind, "RS485");
    }

    #[test]
    fn serial_configuration_decode() {
        let config = parse_serial_port_configuration(SERIAL_CONFIG_RESP).unwrap();
        assert_eq!(config.token, "sp-1");
        assert_eq!(config.kind, "RS485");
        assert_eq!(config.baud_rate, 9600);
        assert_eq!(config.parity_bit, "None");
        assert_eq!(config.character_length, 8);
        assert_eq!(config.stop_bit, 1.5);
    }

    #[test]
    fn serial_options_decode() {
        let options = parse_serial_port_options(SERIAL_OPTIONS_RESP).unwrap();
        assert_eq!(options.token, "sp-1");
        assert_eq!(options.baud_rate_list, vec![9600, 19200]);
        assert_eq!(options.parity_bit_list, vec!["None", "Even"]);
        assert_eq!(options.character_length_list, vec![8]);
        assert_eq!(options.stop_bit_list, vec![1.0, 1.5]);
    }

    #[test]
    fn serial_command_response_decode() {
        let resp = r#"<SendReceiveSerialCommandResponse>
	<SerialData><Binary>pong</Binary></SerialData>
</SendReceiveSerialCommandResponse>"#;
        assert_eq!(
            parse_serial_command_response(resp).unwrap(),
            b"pong".to_vec()
        );
    }

    #[test]
    fn video_output_configuration_decode() {
        let config = parse_video_output_configuration(VIDEO_OUTPUT_CONFIG_RESP).unwrap();
        assert_eq!(config.token, "voc-1");
        assert_eq!(config.name, "HDMI out");
        assert_eq!(config.use_count, 3);
        assert_eq!(config.output_token, "vo-1");
    }

    #[test]
    fn video_output_options_decode() {
        let options = parse_video_output_options(VIDEO_OUTPUT_OPTIONS_RESP).unwrap();
        assert_eq!(options.name.min, 1);
        assert_eq!(options.name.max, 32);
        assert_eq!(options.output_tokens_available, vec!["vo-1", "vo-2"]);
    }

    #[test]
    fn relay_options_decode() {
        let options = parse_relay_output_options(RELAY_OPTIONS_RESP).unwrap();
        assert_eq!(options.token, "ro-1");
        assert_eq!(options.mode, vec!["Monostable", "Bistable"]);
        assert_eq!(options.delay_times, vec!["PT1S", "PT5S"]);
        assert!(options.discrete);
    }

    /// ro-1 carries a proper ISO duration (decoded — beyond the Go twin,
    /// which leaves DelayTime zero); ro-2 carries the Go test fixture's
    /// bare `1`, which does not parse and stays ZERO.
    #[test]
    fn relay_outputs_decode() {
        let relays = parse_relay_outputs(RELAYS_RESP).unwrap();
        assert_eq!(relays.len(), 2);

        assert_eq!(relays[0].token, "ro-1");
        assert_eq!(relays[0].logical_state, "inactive");
        assert_eq!(relays[0].properties.mode, "Monostable");
        assert_eq!(relays[0].properties.idle_state, "closed");
        assert_eq!(relays[0].properties.delay_time, Duration::from_secs(1));

        assert_eq!(relays[1].logical_state, "active");
        assert_eq!(relays[1].properties.delay_time, Duration::ZERO);
    }

    #[test]
    fn audio_outputs_decode() {
        let tokens = parse_audio_output_tokens(AUDIO_OUTPUTS_RESP).unwrap();
        assert_eq!(tokens, vec!["AudioOutput_1", "AudioOutput_2"]);
    }

    #[test]
    fn audio_configuration_decode() {
        let config = parse_audio_output_configuration(AUDIO_CONFIG_RESP).unwrap();
        assert_eq!(config.token, "aoc-1");
        assert_eq!(config.name, "Speaker");
        assert_eq!(config.use_count, 1);
        assert_eq!(config.source_token, "AudioSource_1");
        assert_eq!(config.output_level, 50);
        assert_eq!(config.send_primacy, "www.onvif.org/ver20/HalfDuplex/HTTP");
    }

    #[test]
    fn audio_options_decode() {
        let options = parse_audio_output_options(AUDIO_OPTIONS_RESP).unwrap();
        assert_eq!(
            options.output_levels_range,
            Some(IntRange { min: 0, max: 100 })
        );
        assert_eq!(options.send_primacy_options.len(), 2);
        assert_eq!(
            options.send_primacy_options[0],
            "www.onvif.org/ver20/HalfDuplex/HTTP"
        );
    }

    // --- request goldens (Go-marshal byte shapes) ---

    #[test]
    fn getter_request_goldens() {
        assert_eq!(
            tmd_action("tmd:GetServiceCapabilities"),
            "<tmd:GetServiceCapabilities xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\"></tmd:GetServiceCapabilities>"
        );
        assert_eq!(
            tmd_token_action("tmd:GetSerialPortConfiguration", "tmd:SerialPortToken", "sp-1"),
            "<tmd:GetSerialPortConfiguration xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\"><tmd:SerialPortToken>sp-1</tmd:SerialPortToken></tmd:GetSerialPortConfiguration>"
        );
        // The relay trio's quirk: tds: prefix bound to the deviceIO ns.
        assert_eq!(
            tds_deviceio_action("tds:GetRelayOutputs"),
            "<tds:GetRelayOutputs xmlns:tds=\"http://www.onvif.org/ver10/deviceIO/wsdl\"></tds:GetRelayOutputs>"
        );
    }

    #[test]
    fn set_digital_inputs_request_golden() {
        let inputs = vec![DigitalInput {
            token: "di-1".into(),
            idle_state: "closed".into(),
        }];
        assert_eq!(
            build_set_digital_input_configurations_request(&inputs).unwrap(),
            "<tmd:SetDigitalInputConfigurations xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\">\
             <tmd:DigitalInputs token=\"di-1\" IdleState=\"closed\"></tmd:DigitalInputs>\
             </tmd:SetDigitalInputConfigurations>"
        );

        // IdleState omitted when empty (the Go omitempty); empty slice
        // rejected like the Go nil.
        let bare = vec![DigitalInput {
            token: "di-1".into(),
            idle_state: String::new(),
        }];
        let body = build_set_digital_input_configurations_request(&bare).unwrap();
        assert_eq!(
            body,
            "<tmd:SetDigitalInputConfigurations xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\">\
             <tmd:DigitalInputs token=\"di-1\"></tmd:DigitalInputs>\
             </tmd:SetDigitalInputConfigurations>"
        );
        assert!(build_set_digital_input_configurations_request(&[]).is_err());
        assert!(
            build_set_digital_input_configurations_request(&[DigitalInput::default()]).is_err()
        );
    }

    #[test]
    fn set_serial_port_request_golden() {
        let config = SerialPortConfiguration {
            token: "sp-1".into(),
            kind: "RS485".into(),
            baud_rate: 9600,
            parity_bit: "None".into(),
            character_length: 8,
            stop_bit: 1.5,
        };
        assert_eq!(
            build_set_serial_port_configuration_request(&config),
            "<tmd:SetSerialPortConfiguration xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\">\
             <tmd:SerialPortConfiguration token=\"sp-1\">\
             <tmd:Type>RS485</tmd:Type><tmd:BaudRate>9600</tmd:BaudRate>\
             <tmd:ParityBit>None</tmd:ParityBit><tmd:CharacterLength>8</tmd:CharacterLength>\
             <tmd:StopBit>1.5</tmd:StopBit></tmd:SerialPortConfiguration>\
             </tmd:SetSerialPortConfiguration>"
        );
    }

    #[test]
    fn serial_command_request_golden() {
        assert_eq!(
            build_send_receive_serial_command_request("sp-1", b"ping", 2, 4),
            "<tmd:SendReceiveSerialCommand xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">\
             <tmd:Token>sp-1</tmd:Token>\
             <tmd:SerialData><tt:Binary>ping</tt:Binary></tmd:SerialData>\
             <tmd:TimeOut>PT2S</tmd:TimeOut><tmd:DataLength>4</tmd:DataLength>\
             </tmd:SendReceiveSerialCommand>"
        );
        // Zero timeout/length are omitted (the Go omitempty).
        let bare = build_send_receive_serial_command_request("sp-1", b"x", 0, 0);
        assert!(!bare.contains("TimeOut"));
        assert!(!bare.contains("DataLength"));
    }

    #[test]
    fn set_video_output_request_golden() {
        let config = VideoOutputConfiguration {
            token: "voc-1".into(),
            name: "HDMI out".into(),
            use_count: 3,
            output_token: "vo-1".into(),
            force_persistence: true,
        };
        assert_eq!(
            build_set_video_output_configuration_request(&config),
            "<tmd:SetVideoOutputConfiguration xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">\
             <tmd:Configuration token=\"voc-1\">\
             <tt:Name>HDMI out</tt:Name><tt:UseCount>3</tt:UseCount><tt:OutputToken>vo-1</tt:OutputToken>\
             </tmd:Configuration><tmd:ForcePersistence>true</tmd:ForcePersistence>\
             </tmd:SetVideoOutputConfiguration>"
        );
    }

    /// The Go quirks pinned: `tds:` prefix on the deviceIO namespace,
    /// `tt:` children with NO xmlns:tt declaration, and the empty
    /// DelayTime element when the delay is zero (the only shape Go can
    /// produce); a non-zero delay upgrades the content (delta beyond Go).
    #[test]
    fn set_relay_settings_request_goldens() {
        let zero = RelayOutputSettings {
            mode: "Monostable".into(),
            delay_time: Duration::ZERO,
            idle_state: "closed".into(),
        };
        assert_eq!(
            build_set_relay_output_settings_request("ro-1", &zero),
            "<tds:SetRelayOutputSettings xmlns:tds=\"http://www.onvif.org/ver10/deviceIO/wsdl\">\
             <tds:RelayOutputToken>ro-1</tds:RelayOutputToken>\
             <tds:Properties><tt:Mode>Monostable</tt:Mode><tt:DelayTime></tt:DelayTime>\
             <tt:IdleState>closed</tt:IdleState></tds:Properties></tds:SetRelayOutputSettings>"
        );

        let timed = RelayOutputSettings {
            delay_time: Duration::from_secs(1),
            ..zero
        };
        assert!(build_set_relay_output_settings_request("ro-1", &timed)
            .contains("<tt:DelayTime>PT1S</tt:DelayTime>"));
    }

    #[test]
    fn set_relay_state_request_golden() {
        assert_eq!(
            build_set_relay_output_state_request("ro-1", "active"),
            "<tds:SetRelayOutputState xmlns:tds=\"http://www.onvif.org/ver10/deviceIO/wsdl\">\
             <tds:RelayOutputToken>ro-1</tds:RelayOutputToken><tds:LogicalState>active</tds:LogicalState>\
             </tds:SetRelayOutputState>"
        );
    }

    #[test]
    fn set_audio_output_request_golden() {
        let config = AudioOutputConfiguration {
            token: "aoc-1".into(),
            name: "Speaker".into(),
            source_token: "AudioSource_1".into(),
            output_level: 75,
            ..AudioOutputConfiguration::default()
        };
        assert_eq!(
            build_set_audio_output_configuration_request(&config, true),
            "<tmd:SetAudioOutputConfiguration xmlns:tmd=\"http://www.onvif.org/ver10/deviceIO/wsdl\" xmlns:tt=\"http://www.onvif.org/ver10/schema\">\
             <tmd:Configuration token=\"aoc-1\">\
             <tt:Name>Speaker</tt:Name><tt:UseCount>0</tt:UseCount>\
             <tt:SourceToken>AudioSource_1</tt:SourceToken><tt:OutputLevel>75</tt:OutputLevel>\
             </tmd:Configuration><tmd:ForcePersistence>true</tmd:ForcePersistence>\
             </tmd:SetAudioOutputConfiguration>"
        );
    }

    // --- validation (no I/O: rejected before the wire) ---

    fn client() -> SoapClient {
        SoapClient::new("http://127.0.0.1:1/onvif/device_service").unwrap()
    }

    #[tokio::test]
    async fn token_validation() {
        let c = client();
        assert!(matches!(
            c.get_digital_input_configuration_options("").await,
            Err(ClientError::InvalidArgument(m)) if m == "invalid digital input token: cannot be empty"
        ));
        assert!(c.get_serial_port_configuration("").await.is_err());
        assert!(c.get_serial_port_configuration_options("").await.is_err());
        assert!(c
            .set_serial_port_configuration(&SerialPortConfiguration::default())
            .await
            .is_err());
        assert!(c.get_video_output_configuration("").await.is_err());
        assert!(c.get_video_output_configuration_options("").await.is_err());
        assert!(c
            .set_video_output_configuration(&VideoOutputConfiguration::default())
            .await
            .is_err());
        assert!(c.get_relay_output_options("").await.is_err());
    }

    #[tokio::test]
    async fn serial_command_validation() {
        let c = client();
        assert!(matches!(
            c.send_receive_serial_command("", b"x", 1, 1).await,
            Err(ClientError::InvalidArgument(m)) if m == "invalid serial port token: cannot be empty"
        ));
        assert!(matches!(
            c.send_receive_serial_command("sp-1", b"", 1, 1).await,
            Err(ClientError::InvalidArgument(m)) if m == "invalid serial data: cannot be empty"
        ));
    }
}
