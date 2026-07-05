// SPDX-License-Identifier: GPL-2.0-only
//! Payload decompression. Payloads are untrusted: every decoder is
//! bounded by MAX_DECODED_SIZE to defuse decompression bombs.

use std::io::Read;

use anyhow::{bail, Context};
use ucrs_common::types::PayloadEncoding;

/// 4 MiB of decompressed crash text is far beyond any real report.
pub const MAX_DECODED_SIZE: u64 = 4 * 1024 * 1024;

fn read_capped(mut r: impl Read) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    r.by_ref()
        .take(MAX_DECODED_SIZE + 1)
        .read_to_end(&mut buf)
        .context("decompressing payload")?;

    if buf.len() as u64 > MAX_DECODED_SIZE {
        bail!("decompressed payload exceeds {MAX_DECODED_SIZE} bytes");
    }

    Ok(buf)
}

/// Decompress a raw payload and return it as (lossy) UTF-8 text.
pub fn decode(raw: &[u8], encoding: PayloadEncoding) -> anyhow::Result<String> {
    let data = match encoding {
        PayloadEncoding::None => read_capped(raw)?,
        PayloadEncoding::Gzip => read_capped(flate2::read::GzDecoder::new(raw))?,
        PayloadEncoding::Zlib => read_capped(flate2::read::ZlibDecoder::new(raw))?,
        PayloadEncoding::Zstd => read_capped(zstd::stream::read::Decoder::new(raw)?)?,
    };

    Ok(String::from_utf8_lossy(&data).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn gzip_roundtrip() {
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(b"Oops text").unwrap();
        let raw = enc.finish().unwrap();

        assert_eq!(decode(&raw, PayloadEncoding::Gzip).unwrap(), "Oops text");
    }

    #[test]
    fn zlib_roundtrip() {
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        enc.write_all(b"pstore record").unwrap();
        let raw = enc.finish().unwrap();

        assert_eq!(decode(&raw, PayloadEncoding::Zlib).unwrap(), "pstore record");
    }

    #[test]
    fn plain_passthrough() {
        assert_eq!(decode(b"text", PayloadEncoding::None).unwrap(), "text");
    }

    #[test]
    fn bomb_rejected() {
        // ~100 MiB of zeros compresses to a few hundred bytes
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let chunk = vec![0u8; 1024 * 1024];
        for _ in 0..100 {
            enc.write_all(&chunk).unwrap();
        }
        let raw = enc.finish().unwrap();

        assert!(decode(&raw, PayloadEncoding::Gzip).is_err());
    }
}
