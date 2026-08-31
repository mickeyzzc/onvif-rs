//! Library-hygiene guards: source-scan regression tests so the classes of
//! problems fixed in v0.3.0 cannot silently reappear. Each guard inspects
//! only the production (pre-`#[cfg(test)]`) portion of each source file.

use std::fs;
use std::path::PathBuf;

fn production_sources() -> Vec<(String, String)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).expect("read src dir") {
        let path = entry.expect("entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let content = fs::read_to_string(&path).expect("read source");
        let prod = match content.find("#[cfg(test)]") {
            Some(idx) => content[..idx].to_string(),
            None => content,
        };
        out.push((
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("?")
                .to_string(),
            prod,
        ));
    }
    out
}

/// No direct stdout/stderr printing in library code — the `log` facade only.
#[test]
fn no_direct_print_macros_in_library_code() {
    for (name, src) in production_sources() {
        assert!(
            !src.contains("println!(") && !src.contains("eprintln!("),
            "{name} uses println!/eprintln! — use the log facade instead"
        );
    }
}

/// No origin-hardware branding hardcoded into library code outside the
/// documented DeviceConfig defaults (`config.rs` describes the origin
/// hardware as its serde default and is the deliberate exception).
#[test]
fn no_origin_hardware_branding_in_library_code() {
    const BANNED: &[&str] = &["PiCameraV1", "\"Pi Camera\"", "OV5647"];
    for (name, src) in production_sources() {
        if name == "config.rs" {
            continue; // documented origin-hardware serde defaults
        }
        for banned in BANNED {
            assert!(
                !src.contains(banned),
                "{name} contains hardcoded origin-hardware string {banned:?} — take it from configuration"
            );
        }
    }
}

/// No lab/example IPs in library code — endpoints come from configuration.
#[test]
fn no_private_lab_ips_in_library_code() {
    for (name, src) in production_sources() {
        assert!(
            !src.contains("192.168."),
            "{name} contains a 192.168.x address — take it from configuration"
        );
    }
}
