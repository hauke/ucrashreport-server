// SPDX-License-Identifier: GPL-2.0-only
//! Crash signature (grouping) algorithm — the reference implementation
//! of docs/protocol.md section 6. Two reports with equal signatures
//! belong to the same crash group.

use sha2::{Digest, Sha256};

/// One call-trace frame from the decoder's structured output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub symbol: String,
    pub module: Option<String>,
    /// `? symbol` frames: possibly stale entries, excluded from the
    /// signature.
    pub questionable: bool,
}

#[derive(Debug, Clone)]
pub struct CrashSignature {
    pub signature: String,
    pub title: String,
    pub modules: Vec<String>,
}

const SIGNATURE_FRAMES: usize = 5;

/// Frames belonging to the unwinder/report machinery, dropped from the
/// leading edge of the trace.
const SKIP_PREFIXES: &[&str] = &[
    "dump_backtrace",
    "show_stack",
    "dump_stack",
    "die",
    "__die",
    "oops",
    "panic",
    "__warn",
    "warn_slowpath",
    "report_bug",
    "bug_handler",
    "do_trap",
    "do_page_fault",
    "do_translation_fault",
    "do_mem_abort",
    "el1_",
    "el1h_",
    "__do_kernel_fault",
    "ret_from_",
    "handle_exception",
];

fn is_machinery(symbol: &str) -> bool {
    SKIP_PREFIXES.iter().any(|p| symbol.starts_with(p))
        || symbol.ends_with("_exception")
}

/// Strip offsets, compiler-generated suffixes and addresses from a
/// symbol name.
pub fn normalize_symbol(symbol: &str) -> String {
    let mut s = symbol.trim();

    // "+0x1a8/0x2d0" offset/size suffix
    if let Some(pos) = s.find("+0x") {
        s = &s[..pos];
    }

    // compiler suffixes: .constprop.0, .isra.5, .part.1, .cold, .lto...
    let mut out = s.to_string();
    for suffix in ["constprop", "isra", "part", "cold", "lto"] {
        if let Some(pos) = out.find(&format!(".{suffix}")) {
            out.truncate(pos);
        }
    }

    out
}

/// Normalize an exception line: strip addresses and CPU/PID/task noise
/// so the same fault on different devices matches.
pub fn normalize_exception(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.trim().split_whitespace().peekable();

    while let Some(tok) = chars.next() {
        let t = tok.trim_matches(|c: char| c == '[' || c == ']' || c == ',');

        // drop hex addresses and long hex ids
        if t.starts_with("0x") || (t.len() >= 4 && t.chars().all(|c| c.is_ascii_hexdigit())) {
            continue;
        }
        // drop "CPU: 1 PID: 1234 ..." style noise
        if matches!(t, "CPU:" | "PID:" | "Comm:" | "Tainted:" | "at") && chars.peek().is_some() {
            // keep "at" only when followed by a symbol (kernel BUG at file:line)
            if t != "at" {
                chars.next();
                continue;
            }
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(t);
    }

    out
}

/// Compute the crash signature per protocol.md section 6.
pub fn compute(kind: &str, exception_line: &str, frames: &[Frame]) -> CrashSignature {
    let exception = normalize_exception(exception_line);

    let mut sig_frames: Vec<String> = Vec::new();
    let mut modules: Vec<String> = Vec::new();
    let mut seen_real_frame = false;

    for f in frames {
        if f.questionable {
            continue;
        }

        let sym = normalize_symbol(&f.symbol);
        if sym.is_empty() {
            continue;
        }

        if let Some(m) = &f.module {
            if !modules.contains(m) {
                modules.push(m.clone());
            }
        }

        if !seen_real_frame && is_machinery(&sym) {
            continue;
        }
        seen_real_frame = true;

        if sig_frames.len() < SIGNATURE_FRAMES {
            sig_frames.push(sym);
        }
    }

    let input = format!("{kind}|{exception}|{}", sig_frames.join("|"));
    let signature = hex::encode(Sha256::digest(input.as_bytes()));

    let title = sig_frames
        .first()
        .cloned()
        .unwrap_or_else(|| exception.clone());

    CrashSignature {
        signature,
        title,
        modules,
    }
}

/// Extract the exception line and call-trace frames from a (symbolized
/// or symbol-named) kernel oops text. This is a helper for kernel-style
/// traces; the decoder may provide structured frames directly.
pub fn parse_oops(text: &str) -> Option<(String, Vec<Frame>)> {
    let mut exception: Option<String> = None;
    let mut frames = Vec::new();
    let mut in_trace = false;

    for raw in text.lines() {
        // strip syslog/printk prefixes like "[   12.345678] "
        let line = raw
            .trim_start()
            .trim_start_matches(|c: char| c == '[')
            .trim_start();
        let line = match raw.find(']') {
            Some(pos) if raw.trim_start().starts_with('[') => raw[pos + 1..].trim(),
            _ => line.trim(),
        };

        if exception.is_none() {
            for marker in [
                "Oops",
                "kernel BUG at",
                "Internal error:",
                "Unable to handle kernel",
                "Unhandled fault",
                "BUG:",
                "WARNING:",
            ] {
                if line.starts_with(marker) || line.contains(marker) {
                    exception = Some(line.to_string());
                    break;
                }
            }
        }

        if line.starts_with("Call trace:") || line.starts_with("Call Trace:") {
            in_trace = true;
            continue;
        }

        if in_trace {
            if line.contains("---[ end trace") || line.is_empty() {
                break;
            }

            let questionable = line.starts_with("? ");
            let line = line.trim_start_matches("? ").trim();

            // "symbol+0x1a8/0x2d0 [module]"
            let (sym_part, module) = match line.split_once(" [") {
                Some((s, m)) => (s, Some(m.trim_end_matches(']').to_string())),
                None => (line, None),
            };

            // frames are "symbol+0xoff/0xsize"; anything else ends the
            // trace section (register dumps etc.)
            if !sym_part.contains("+0x") {
                break;
            }

            frames.push(Frame {
                symbol: sym_part.to_string(),
                module,
                questionable,
            });
        }
    }

    exception.map(|e| (e, frames))
}

#[cfg(test)]
mod tests {
    use super::*;

    // shaped like the trace from openwrt/openwrt#24029
    const OOPS: &str = r#"[ 7136.514751] Internal error: Oops - BUG: 00000000f2000800 [#1] SMP
[ 7136.520932] Modules linked in: act_mirred cls_matchall pppoe nf_conntrack
[ 7136.601155] CPU: 3 PID: 0 Comm: swapper/3 Not tainted 6.12.94 #0
[ 7136.607246] Hardware name: GL.iNet GL-MT6000 (DT)
[ 7136.611944] pc : kfree_skb_list_reason+0x3c/0x2d0
[ 7136.616642] lr : tcf_mirred_to_dev+0x1e8/0x350 [act_mirred]
[ 7136.622209] Call trace:
[ 7136.624642]  kfree_skb_list_reason+0x3c/0x2d0
[ 7136.628993]  tcf_mirred_to_dev+0x1e8/0x350 [act_mirred]
[ 7136.634212]  tcf_mirred_act+0xc8/0x1e8 [act_mirred]
[ 7136.639078]  tcf_action_exec.part.0+0x80/0x1a8
[ 7136.643516]  mall_classify+0x54/0x78 [cls_matchall]
[ 7136.648384]  tcf_classify+0x2b0/0x3e0
[ 7136.652042]  __dev_queue_xmit+0x3a8/0xd40
[ 7136.656045] ---[ end trace 0000000000000000 ]---
"#;

    #[test]
    fn oops_parse_and_signature() {
        let (exception, frames) = parse_oops(OOPS).unwrap();

        assert!(exception.contains("Internal error: Oops"));
        assert_eq!(frames.len(), 7);
        assert_eq!(frames[1].module.as_deref(), Some("act_mirred"));

        let sig = compute("kernel_oops", &exception, &frames);

        assert_eq!(sig.title, "kfree_skb_list_reason");
        assert_eq!(sig.modules, vec!["act_mirred", "cls_matchall"]);
        assert_eq!(sig.signature.len(), 64);
    }

    #[test]
    fn signature_stable_across_addresses_and_offsets() {
        let (e1, f1) = parse_oops(OOPS).unwrap();
        // same crash, different offsets and different BUG address
        let other = OOPS
            .replace("+0x3c/0x2d0", "+0x44/0x2d0")
            .replace("00000000f2000800", "00000000deadbeef");
        let (e2, f2) = parse_oops(&other).unwrap();

        assert_eq!(
            compute("kernel_oops", &e1, &f1).signature,
            compute("kernel_oops", &e2, &f2).signature
        );
    }

    #[test]
    fn normalize() {
        assert_eq!(
            normalize_symbol("tcf_action_exec.part.0+0x80/0x1a8"),
            "tcf_action_exec"
        );
        assert_eq!(normalize_symbol("foo.isra.5.cold"), "foo");
        assert_eq!(normalize_symbol("plain_symbol"), "plain_symbol");
    }

    #[test]
    fn machinery_skipped() {
        let frames = vec![
            Frame {
                symbol: "dump_backtrace+0x0/0x1a8".into(),
                module: None,
                questionable: false,
            },
            Frame {
                symbol: "show_stack+0x14/0x20".into(),
                module: None,
                questionable: false,
            },
            Frame {
                symbol: "real_function+0x10/0x20".into(),
                module: None,
                questionable: false,
            },
        ];

        let sig = compute("kernel_oops", "Oops", &frames);
        assert_eq!(sig.title, "real_function");
    }
}
