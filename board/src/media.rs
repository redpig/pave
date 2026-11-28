//! Image metadata: what a picture carries, and a copy without it.
//!
//! Redaction is the app's job: stripping metadata, blurring faces and
//! number plates. This is the part a prototype can do without decoding a
//! pixel: drop the metadata segments of a JPEG or the metadata chunks of a
//! PNG, and say which kinds a file carries (Exif, XMP, IPTC, C2PA). The
//! original isn't lost: whoever posts a stripped copy commits to the
//! original with a salt it keeps, and can reveal it to a panel, provenance
//! and all, if that helps (see [`crate::evidence`]).

/// The kinds of metadata an image carries, as far as its structure shows.
pub fn metadata_kinds(bytes: &[u8]) -> Vec<String> {
    let mut out = vec![];
    let mut add = |k: &str| {
        if !out.iter().any(|x| x == k) {
            out.push(k.to_string());
        }
    };
    if is_jpeg(bytes) {
        for (marker, payload) in jpeg_segments(bytes) {
            match marker {
                0xE1 if payload.starts_with(b"Exif\0") => add("Exif"),
                0xE1 if payload.starts_with(b"http://ns.adobe.com/xap/") => add("XMP"),
                0xE1 => add("APP1"),
                0xEB => add("C2PA (JUMBF)"),
                0xED => add("IPTC"),
                0xE2..=0xEF => add("APP"),
                0xFE => add("comment"),
                _ => {}
            }
        }
    } else if is_png(bytes) {
        for (kind, data) in png_chunks(bytes) {
            match &kind {
                b"eXIf" => add("Exif"),
                b"iTXt" if data.starts_with(b"XML:com.adobe.xmp") => add("XMP"),
                b"caBX" => add("C2PA (JUMBF)"),
                b"tEXt" | b"zTXt" | b"iTXt" => add("text"),
                _ => {}
            }
        }
    }
    out
}

/// A copy without metadata: a JPEG without its APP1 to APP15 segments and
/// comments (APP0, the JFIF header, stays), or a PNG without its text,
/// Exif and C2PA chunks. Anything else comes back as it was, and
/// [`can_strip`] says so.
pub fn strip_metadata(bytes: &[u8]) -> Vec<u8> {
    if is_jpeg(bytes) {
        let mut out = vec![0xFF, 0xD8];
        let mut i = 2;
        while i + 4 <= bytes.len() && bytes[i] == 0xFF {
            let marker = bytes[i + 1];
            if marker == 0xDA {
                // Start of scan: the image data follows, to the end.
                out.extend_from_slice(&bytes[i..]);
                return out;
            }
            let len = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]) as usize;
            let end = (i + 2 + len).min(bytes.len());
            let drop = (0xE1..=0xEF).contains(&marker) || marker == 0xFE;
            if !drop {
                out.extend_from_slice(&bytes[i..end]);
            }
            i = end;
        }
        out.extend_from_slice(&bytes[i.min(bytes.len())..]);
        out
    } else if is_png(bytes) {
        let mut out = bytes[..8].to_vec();
        let mut i = 8;
        while i + 12 <= bytes.len() {
            let len =
                u32::from_be_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
            let end = (i + 12 + len).min(bytes.len());
            let kind = &bytes[i + 4..i + 8];
            if !matches!(kind, b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"caBX") {
                out.extend_from_slice(&bytes[i..end]);
            }
            i = end;
        }
        out
    } else {
        bytes.to_vec()
    }
}

/// Whether [`strip_metadata`] knows this format.
pub fn can_strip(bytes: &[u8]) -> bool {
    is_jpeg(bytes) || is_png(bytes)
}

fn is_jpeg(b: &[u8]) -> bool {
    b.len() >= 4 && b[0] == 0xFF && b[1] == 0xD8
}

fn is_png(b: &[u8]) -> bool {
    b.len() >= 8 && b[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
}

fn jpeg_segments(b: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = vec![];
    let mut i = 2;
    while i + 4 <= b.len() && b[i] == 0xFF {
        let marker = b[i + 1];
        if marker == 0xDA {
            break;
        }
        let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        let end = (i + 2 + len).min(b.len());
        out.push((marker, &b[(i + 4).min(end)..end]));
        i = end;
    }
    out
}

fn png_chunks(b: &[u8]) -> Vec<([u8; 4], &[u8])> {
    let mut out = vec![];
    let mut i = 8;
    while i + 12 <= b.len() {
        let len = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize;
        let end = (i + 12 + len).min(b.len());
        let mut kind = [0u8; 4];
        kind.copy_from_slice(&b[i + 4..i + 8]);
        out.push((kind, &b[(i + 8).min(end)..(i + 8 + len).min(end)]));
        i = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0xFF, marker];
        v.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    /// A JPEG's structure with Exif, XMP and a C2PA manifest.
    pub fn sample_jpeg() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8];
        v.extend(seg(0xE0, b"JFIF\0\x01\x01"));
        v.extend(seg(0xE1, b"Exif\0\0GPS 36.16,-86.78 2026-11-24T14:02"));
        v.extend(seg(0xE1, b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta/>"));
        v.extend(seg(
            0xEB,
            b"JP\0\x01jumb c2pa manifest: captured by camera app",
        ));
        v.extend(seg(0xFE, b"comment"));
        v.extend(seg(0xDB, b"quant tables"));
        v.extend(seg(0xDA, b"scan header"));
        v.extend_from_slice(b"pixel data \xFF\x00 more");
        v.extend_from_slice(&[0xFF, 0xD9]);
        v
    }

    #[test]
    fn jpeg() {
        let j = sample_jpeg();
        assert_eq!(
            metadata_kinds(&j),
            ["Exif", "XMP", "C2PA (JUMBF)", "comment"]
        );
        let s = strip_metadata(&j);
        assert!(metadata_kinds(&s).is_empty());
        assert!(s.windows(4).any(|w| w == b"JFIF"), "keeps the JFIF header");
        assert!(
            s.ends_with(b"pixel data \xFF\x00 more\xFF\xD9"),
            "keeps the image data"
        );
        assert!(!s.windows(3).any(|w| w == b"GPS"));
    }

    #[test]
    fn png() {
        let chunk = |k: &[u8], d: &[u8]| {
            let mut v = (d.len() as u32).to_be_bytes().to_vec();
            v.extend_from_slice(k);
            v.extend_from_slice(d);
            v.extend_from_slice(&[0, 0, 0, 0]);
            v
        };
        let mut p = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        p.extend(chunk(b"IHDR", b"header"));
        p.extend(chunk(b"eXIf", b"GPS"));
        p.extend(chunk(b"caBX", b"c2pa"));
        p.extend(chunk(b"IDAT", b"pixels"));
        p.extend(chunk(b"IEND", b""));
        assert_eq!(metadata_kinds(&p), ["Exif", "C2PA (JUMBF)"]);
        let s = strip_metadata(&p);
        assert!(metadata_kinds(&s).is_empty());
        assert!(s.windows(6).any(|w| w == b"pixels"));
    }

    #[test]
    fn other() {
        assert!(!can_strip(b"PHOTO: not an image format"));
        assert_eq!(strip_metadata(b"abc"), b"abc");
    }
}
