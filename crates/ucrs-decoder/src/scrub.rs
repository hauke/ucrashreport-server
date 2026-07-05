// SPDX-License-Identifier: GPL-2.0-only
//! Scrub potentially identifying data from decoded traces before they
//! are stored: MAC addresses (NIC part masked, OUI kept — it is useful
//! for grouping by chipset vendor and not device-identifying) and IP
//! addresses. Runs on the *decoded* text only; raw payloads are never
//! retained after decoding.

use std::sync::OnceLock;

use regex::Regex;

fn mac_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}):[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}\b")
            .unwrap()
    })
}

fn ipv4_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\.(25[0-5]|2[0-4]\d|1?\d?\d)\b")
            .unwrap()
    })
}

fn ipv6_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // full form with >= 5 groups, or any "::"-compressed form — chosen
    // to not match hex offset/register output from kernel traces
    RE.get_or_init(|| {
        Regex::new(r"\b(?:[0-9A-Fa-f]{1,4}:){5,7}[0-9A-Fa-f]{1,4}\b|\b[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:)*:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4})*)?\b")
            .unwrap()
    })
}

pub fn scrub(text: &str) -> String {
    let out = mac_re().replace_all(text, "$1:xx:xx:xx");

    let out = ipv4_re().replace_all(&out, |c: &regex::Captures| {
        let ip = &c[0];
        // loopback/any are not identifying and often meaningful
        if ip == "0.0.0.0" || ip.starts_with("127.") || ip == "255.255.255.255" {
            ip.to_string()
        } else {
            "x.x.x.x".to_string()
        }
    });

    let out = ipv6_re().replace_all(&out, |c: &regex::Captures| {
        let ip = &c[0];
        if ip == "::" || ip == "::1" {
            ip.to_string()
        } else {
            "x:x::x".to_string()
        }
    });

    out.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_keeps_oui() {
        assert_eq!(
            scrub("dev eth0 addr 94:83:c4:12:34:56 up"),
            "dev eth0 addr 94:83:c4:xx:xx:xx up"
        );
    }

    #[test]
    fn ipv4_masked_but_loopback_kept() {
        assert_eq!(
            scrub("from 192.168.1.42 to 127.0.0.1 and 0.0.0.0"),
            "from x.x.x.x to 127.0.0.1 and 0.0.0.0"
        );
    }

    #[test]
    fn ipv6_masked() {
        assert_eq!(scrub("src fe80::1a2b:3c4d"), "src x:x::x");
        assert_eq!(
            scrub("addr 2001:0db8:0000:0000:0000:ff00:0042:8329"),
            "addr x:x::x"
        );
    }

    #[test]
    fn trace_content_untouched() {
        let line = "[ 7136.62]  tcf_mirred_to_dev+0x1e8/0x350 [act_mirred]";
        assert_eq!(scrub(line), line);
        // register dumps must survive
        let regs = "x1 : ffff800011223344 x0 : 0000000000000000";
        assert_eq!(scrub(regs), regs);
    }
}
