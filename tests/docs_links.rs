//! Documentation link guards.
//!
//! The README Documentation index once pointed at `docs/foo.md` while the
//! files live under `docs/en/` — GitHub renders that as a silent 404, and
//! the index had also drifted into mixing languages in one table. These
//! tests fail the build instead:
//!
//! - every relative markdown link in the READMEs and the `docs/` redirect
//!   page must resolve to an existing file;
//! - `docs/` holds exactly one redirect page pointing at the MiBee
//!   documentation hub (mibee-docs#6, single source of truth) — manuals
//!   cannot drift back into this repository;
//! - the English README must not link Chinese guides (`docs/zh/`) and the
//!   Chinese README must not link English guides (`docs/en/).

use std::fs;
use std::path::{Path, PathBuf};

fn collect_markdown(root: &Path) -> Vec<PathBuf> {
    let mut files = vec![root.join("README.md"), root.join("README.zh-CN.md")];
    // docs/ holds one flat directory per language (docs/en, docs/zh);
    // walk one level defensively.
    if let Ok(entries) = fs::read_dir(root.join("docs")) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                if let Ok(inner) = fs::read_dir(&p) {
                    for e in inner.flatten() {
                        let q = e.path();
                        if q.extension().is_some_and(|x| x == "md") {
                            files.push(q);
                        }
                    }
                }
            } else if p.extension().is_some_and(|x| x == "md") {
                files.push(p);
            }
        }
    }
    files.retain(|p| p.is_file());
    files
}

/// Extract `](target)` link targets from markdown text, keeping only
/// relative file targets (web links, mailto, and pure anchors are skipped).
fn relative_targets(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        if bytes[i] == b']' && bytes[i + 1] == b'(' {
            let start = i + 2;
            let Some(rel) = text[start..].find(')') else {
                break;
            };
            let end = start + rel;
            let target = &text[start..end];
            let path = target.split('#').next().unwrap_or("");
            let skip = target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
                || path.is_empty();
            if !skip {
                out.push(path.to_string());
            }
            i = end;
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn markdown_links_resolve() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let files = collect_markdown(&root);
    assert!(!files.is_empty(), "no markdown files found to check");

    let mut checked = 0usize;
    let mut broken = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).expect("read markdown");
        for target in relative_targets(&text) {
            let resolved = if target.starts_with('/') {
                root.join(target.trim_start_matches('/'))
            } else {
                file.parent().unwrap_or(Path::new(".")).join(&target)
            };
            checked += 1;
            if !resolved.exists() {
                broken.push(format!("{} -> {}", file.display(), target));
            }
        }
    }
    assert!(
        checked >= 3,
        "expected a meaningful number of links, checked {checked}"
    );
    assert!(
        broken.is_empty(),
        "broken documentation links ({} of {} checked):\n{}",
        broken.len(),
        checked,
        broken.join("\n")
    );
}

#[test]
fn readme_indexes_stay_single_language() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let en = fs::read_to_string(root.join("README.md")).expect("read README.md");
    for target in relative_targets(&en) {
        assert!(
            !target.starts_with("docs/zh/"),
            "README.md (English) links the Chinese guide {target} — \
             each language's index must reference only its own guides"
        );
    }
    let zh = fs::read_to_string(root.join("README.zh-CN.md")).expect("read README.zh-CN.md");
    for target in relative_targets(&zh) {
        assert!(
            !target.starts_with("docs/en/"),
            "README.zh-CN.md (Chinese) links the English guide {target} — \
             each language's index must reference only its own guides"
        );
    }
}

/// Pins the self-contained-docs contract (2026-10-24 policy): `docs/`
/// holds the bilingual manual set plus its index, and every URL under
/// `docs/` must point at an allowlisted host — the project's own hosting
/// and the standards bodies it cites; any external docs-site pointer
/// fails the build, whatever domain it uses.
#[test]
fn docs_are_in_repo() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for lang in ["en-US", "zh-CN"] {
        let pages: Vec<_> = fs::read_dir(root.join("docs").join(lang))
            .unwrap_or_else(|_| panic!("docs/{lang} must exist"))
            .flatten()
            .collect();
        assert!(!pages.is_empty(), "docs/{lang} must hold manual pages");
    }
    fn assert_links_self_contained(dir: &Path) {
        for entry in fs::read_dir(dir).expect("read docs dir").flatten() {
            let p = entry.path();
            if p.is_dir() {
                assert_links_self_contained(&p);
                continue;
            }
            let raw = fs::read_to_string(&p).unwrap_or_default();
            for host in url_hosts(&raw) {
                assert!(
                    docs_host_allowed(&host),
                    "{} links to non-allowlisted host {host:?} — docs must be self-contained",
                    p.display()
                );
            }
        }
    }
    assert_links_self_contained(&root.join("docs"));
}

/// Hosts documentation may link to (project hosting + standards bodies).
const DOCS_ALLOWED_HOSTS: &[&str] = &[
    "github.com",
    "onvif.org",
    "www.onvif.org",
    "w3.org",
    "www.w3.org",
    "pkg.go.dev",
];

/// Admits the example endpoint placeholders that appear in usage snippets
/// (LAN IPs, literal "host") — these are not real hosts.
fn docs_host_allowed(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    DOCS_ALLOWED_HOSTS.contains(&h.as_str())
        || h == "host"
        || h == "localhost"
        || h.starts_with("192.168.")
}

/// Extracts the host of every http(s) URL in the text. Other schemes
/// (`rtsp://` and friends) are not documentation pointers.
fn url_hosts(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut i = 0usize;
    while let Some(idx) = text[i..].find("://") {
        let abs = i + idx;
        let mut s = abs;
        while s > 0 && bytes[s - 1].is_ascii_alphabetic() {
            s -= 1;
        }
        let scheme = &text[s..abs];
        if scheme == "http" || scheme == "https" {
            let after = &text[abs + 3..];
            let host: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                .collect();
            if !host.is_empty() {
                out.push(host);
            }
            i = abs + 3;
        } else {
            i = abs + 1;
        }
    }
    out
}
