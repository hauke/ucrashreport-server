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
        // die counter "[#1]" and timestamps
        if t.starts_with('#') || (t.contains('.') && t.chars().all(|c| c.is_ascii_digit() || c == '.'))
        {
            continue;
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

/// Strip kernel log line prefixes in their various shapes:
/// "[   12.345678] msg" (dmesg), "<7>[   59.157] msg" (pstore
/// records), "<7> 59.157 msg" (some pstore backends).
pub fn strip_printk_prefix(raw: &str) -> &str {
    let mut s = raw.trim_start();

    // syslog level "<7>"
    if let Some(rest) = s.strip_prefix('<') {
        if let Some((level, rest)) = rest.split_once('>') {
            if !level.is_empty() && level.chars().all(|c| c.is_ascii_digit()) {
                s = rest.trim_start();
            }
        }
    }

    // timestamp, bracketed or bare
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((ts, rest)) = rest.split_once(']') {
            if ts.trim().chars().all(|c| c.is_ascii_digit() || c == '.') {
                return rest.trim();
            }
        }
    } else if let Some((first, rest)) = s.split_once(' ') {
        if first.contains('.') && first.chars().all(|c| c.is_ascii_digit() || c == '.') {
            return rest.trim();
        }
    }

    s.trim()
}

/// Extract the exception line and call-trace frames from a (symbolized
/// or symbol-named) kernel oops text. This is a helper for kernel-style
/// traces; the decoder may provide structured frames directly.
///
/// A record can contain several crash sections — pstore dumps carry
/// the whole kmsg ring, so an old WARNING may precede the fatal oops.
/// The LAST section wins.
pub fn parse_oops(text: &str) -> Option<(String, Vec<Frame>)> {
    let mut exception: Option<String> = None;
    let mut frames = Vec::new();
    let mut in_trace = false;

    for raw in text.lines() {
        let line = strip_printk_prefix(raw);

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
                if !frames.is_empty() {
                    // a new crash section starts — discard the
                    // previous one, the last crash is the fatal one
                    frames.clear();
                    exception = Some(line.to_string());
                } else if exception.is_none() {
                    exception = Some(line.to_string());
                }
                break;
            }
        }

        if line.starts_with("Call trace:") || line.starts_with("Call Trace:") {
            in_trace = true;
            continue;
        }

        if in_trace {
            if line.contains("---[ end trace") || line.is_empty() {
                in_trace = false;
                continue;
            }

            let questionable = line.starts_with("? ");
            let mut line = line.trim_start_matches("? ").trim();

            // arm64 marks the faulting frame with a trailing "(P)"
            // (pt_regs) or "(K)" marker
            while line.ends_with(')') {
                match line.rsplit_once(" (") {
                    Some((rest, marker)) if marker.len() <= 3 => line = rest.trim_end(),
                    _ => break,
                }
            }

            // "symbol+0x1a8/0x2d0 [module]"
            let (sym_part, module) = match line.split_once(" [") {
                Some((s, m)) => (s, Some(m.trim_end_matches(']').to_string())),
                None => (line, None),
            };

            // frames are "symbol+0xoff/0xsize"; anything else ends the
            // trace section (register dumps etc.)
            if !sym_part.contains("+0x") {
                in_trace = false;
                continue;
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

    // real pstore (ramoops) record from an OpenWrt One, lkdtm
    // EXCEPTION panic: "<level>[timestamp]" prefixes and the arm64
    // "(P)" faulting-frame marker
    const PSTORE: &str = r#"Panic#2 Part1
<1>[   58.909947] Unable to handle kernel access to user memory outside uaccess routines at virtual address 0000000000000000
<0>[   58.979398] Internal error: Oops: 0000000096000045 [#1]  SMP
<7>[   58.985050] Modules linked in: pppoe lkdtm compat(O)
<7>[   59.070784] pc : lkdtm_EXCEPTION+0x4/0xc [lkdtm]
<7>[   59.154787] Call trace:
<7>[   59.157223]  lkdtm_EXCEPTION+0x4/0xc [lkdtm] (P)
<7>[   59.161846]  direct_entry+0x1a8/0x1e0 [lkdtm]
<7>[   59.166207]  full_proxy_write+0x60/0x98
<7>[   59.170212]  vfs_write+0xac/0x3c4
<7>[   59.176829]  __arm64_sys_write+0x18/0x20
<7>[   59.191795]  el0t_64_sync_handler+0x98/0xdc
<0>[   59.199627] Code: d503201f d503201f d503201f d2800000 (b900001f)
<4>[   59.205707] ---[ end trace 0000000000000000 ]---
"#;

    #[test]
    fn pstore_record_parse_and_signature() {
        let (exception, frames) = parse_oops(PSTORE).unwrap();

        assert!(exception.starts_with("Unable to handle kernel"));
        assert_eq!(frames[0].symbol, "lkdtm_EXCEPTION+0x4/0xc");
        assert_eq!(frames[0].module.as_deref(), Some("lkdtm"));

        let sig = compute("pstore", &exception, &frames);
        assert_eq!(sig.title, "lkdtm_EXCEPTION");
        assert_eq!(sig.modules, vec!["lkdtm"]);
    }

    // pstore dumps the whole kmsg ring: an earlier WARNING must not
    // hijack the signature of the fatal crash that follows it
    #[test]
    fn last_crash_section_wins() {
        let mixed = r#"<4>[  675.75] WARNING: CPU: 0 PID: 3157 at lkdtm_WARNING+0x1c/0x24 [lkdtm]
<7>[  675.92] Call trace:
<7>[  675.93]  lkdtm_WARNING+0x1c/0x24 [lkdtm] (P)
<7>[  675.94]  direct_entry+0x1a8/0x1e0 [lkdtm]
<4>[  675.97] ---[ end trace 0000000000000000 ]---
<1>[  723.31] Unable to handle kernel access to user memory outside uaccess routines at virtual address 0000000000000000
<0>[  723.40] Internal error: Oops: 0000000096000045 [#1]  SMP
<7>[  723.58] Call trace:
<7>[  723.59]  lkdtm_EXCEPTION+0x4/0xc [lkdtm] (P)
<7>[  723.60]  direct_entry+0x1a8/0x1e0 [lkdtm]
<4>[  723.65] ---[ end trace 0000000000000000 ]---
"#;

        let (exception, frames) = parse_oops(mixed).unwrap();
        assert!(exception.starts_with("Unable to handle kernel"));

        let sig = compute("pstore", &exception, &frames);
        assert_eq!(sig.title, "lkdtm_EXCEPTION");
    }

    #[test]
    fn printk_prefixes_stripped() {
        assert_eq!(strip_printk_prefix("<7>[   59.15]  vfs_write+0xac/0x3c4"),
                   "vfs_write+0xac/0x3c4");
        assert_eq!(strip_printk_prefix("[   12.34] msg"), "msg");
        assert_eq!(strip_printk_prefix("<1> 58.909947 Unable to handle"),
                   "Unable to handle");
        assert_eq!(strip_printk_prefix("plain line"), "plain line");
    }

    #[test]
    fn exception_normalized_without_counters() {
        assert_eq!(
            normalize_exception("Internal error: Oops: 0000000096000045 [#1]  SMP"),
            "Internal error: Oops: SMP"
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
