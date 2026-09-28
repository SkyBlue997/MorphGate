//! A zero-copy parser of the TLS ClientHello message body (RFC 8446
//! §4.1.2; RFC 5246 §7.4.1.2) for the JA4 spike (docs/impl/phase1-spec.md
//! §15 WP-J1).
//!
//! BoringSSL's select-certificate callback hands over the ClientHello
//! *body*: `ClientHello::as_bytes()` starts at `legacy_version`, after the
//! 4-byte handshake header, and is the reassembled message whatever the
//! record fragmentation. [`ClientHello::parse`] takes exactly that;
//! [`body_from_record`] strips the record and handshake headers of a
//! ClientHello captured on the wire (tests, tooling).
//!
//! The parser never panics, never allocates and runs in time linear in its
//! input. [`ClientHello::parse`] validates the framing: the fixed fields,
//! the length-prefixed vectors (`legacy_session_id` at most 32 bytes,
//! `cipher_suites` of even length) and the optional extension block, which
//! must tile the rest of the message exactly. Extension bodies are checked
//! only by the accessors that read them ([`supported_versions`],
//! [`first_alpn`], [`signature_algorithms`]).

use std::fmt;

/// `server_name` (RFC 6066).
pub const EXT_SERVER_NAME: u16 = 0x0000;
/// `signature_algorithms` (RFC 8446 §4.2.3).
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
/// `application_layer_protocol_negotiation` (RFC 7301).
pub const EXT_ALPN: u16 = 0x0010;
/// `supported_versions` (RFC 8446 §4.2.1).
pub const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
/// `pre_shared_key` (RFC 8446 §4.2.11): only in resumption attempts.
pub const EXT_PRE_SHARED_KEY: u16 = 0x0029;

/// Why a ClientHello (or one of the extensions JA4 reads) did not parse.
/// Carries a fixed description only, never input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError(&'static str);

impl ParseError {
    /// The field that was truncated or inconsistent.
    pub fn what(&self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "malformed ClientHello: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// A cursor over a byte slice; every read is bounds-checked.
#[derive(Debug, Clone, Copy)]
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], ParseError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(ParseError(what))?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], ParseError> {
        self.take(N, what)?.try_into().map_err(|_| ParseError(what))
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, ParseError> {
        Ok(u16::from_be_bytes(self.array(what)?))
    }

    /// A vector with a one-byte length prefix.
    fn vec8(&mut self, what: &'static str) -> Result<&'a [u8], ParseError> {
        let [n] = self.array::<1>(what)?;
        self.take(usize::from(n), what)
    }

    /// A vector with a two-byte length prefix.
    fn vec16(&mut self, what: &'static str) -> Result<&'a [u8], ParseError> {
        let n = self.u16(what)?;
        self.take(usize::from(n), what)
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Fails unless the whole input was read.
    fn finish(&self, what: &'static str) -> Result<(), ParseError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(ParseError(what))
        }
    }
}

/// Big-endian `u16` values of `bytes` (a trailing odd byte is ignored; the
/// parsers only hand over even-length lists).
pub fn u16s(bytes: &[u8]) -> impl Iterator<Item = u16> + '_ {
    bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
}

/// A parsed ClientHello body; borrows the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello<'a> {
    /// `legacy_version` (`client_version` before TLS 1.3).
    pub legacy_version: u16,
    cipher_suites: &'a [u8],
    /// The extension block without its length prefix; `None` when the
    /// message ends after `legacy_compression_methods`.
    extensions: Option<&'a [u8]>,
}

impl<'a> ClientHello<'a> {
    /// Parses a ClientHello body (starting at `legacy_version`).
    pub fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        let mut r = Reader(body);
        let legacy_version = r.u16("legacy_version")?;
        r.take(32, "random")?;
        if r.vec8("legacy_session_id")?.len() > 32 {
            return Err(ParseError("legacy_session_id longer than 32 bytes"));
        }
        let cipher_suites = r.vec16("cipher_suites")?;
        if !cipher_suites.len().is_multiple_of(2) {
            return Err(ParseError("cipher_suites of odd length"));
        }
        r.vec8("legacy_compression_methods")?;
        let extensions = if r.is_empty() {
            None
        } else {
            let block = r.vec16("extensions")?;
            r.finish("data after the extensions")?;
            let mut e = Reader(block);
            while !e.is_empty() {
                e.u16("extension type")?;
                e.vec16("extension data")?;
            }
            Some(block)
        };
        Ok(Self {
            legacy_version,
            cipher_suites,
            extensions,
        })
    }

    /// The offered cipher suites, in order (GREASE included).
    pub fn cipher_suites(&self) -> impl Iterator<Item = u16> + 'a {
        u16s(self.cipher_suites)
    }

    /// Whether the message has an extension block (possibly empty).
    pub fn has_extensions(&self) -> bool {
        self.extensions.is_some()
    }

    /// The extensions as `(type, data)`, in order (GREASE included).
    pub fn extensions(&self) -> Extensions<'a> {
        Extensions(Reader(self.extensions.unwrap_or_default()))
    }
}

/// Iterator over a validated extension block.
#[derive(Debug, Clone)]
pub struct Extensions<'a>(Reader<'a>);

impl<'a> Iterator for Extensions<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        // The block was validated by `ClientHello::parse`; an error only ends
        // the iteration.
        let ty = self.0.u16("extension type").ok()?;
        let data = self.0.vec16("extension data").ok()?;
        Some((ty, data))
    }
}

/// The version list of a ClientHello `supported_versions` body (one-byte
/// length, then `u16` versions; read it with [`u16s`]).
pub fn supported_versions(data: &[u8]) -> Result<&[u8], ParseError> {
    let mut r = Reader(data);
    let list = r.vec8("supported_versions")?;
    r.finish("data after supported_versions")?;
    if !list.len().is_multiple_of(2) {
        return Err(ParseError("supported_versions of odd length"));
    }
    Ok(list)
}

/// The algorithm list of a `signature_algorithms` body (two-byte length,
/// then `u16` schemes in the client's preference order; read it with
/// [`u16s`]).
pub fn signature_algorithms(data: &[u8]) -> Result<&[u8], ParseError> {
    let mut r = Reader(data);
    let list = r.vec16("signature_algorithms")?;
    r.finish("data after signature_algorithms")?;
    if !list.len().is_multiple_of(2) {
        return Err(ParseError("signature_algorithms of odd length"));
    }
    Ok(list)
}

/// The first protocol name of an ALPN body (RFC 7301 §3.1); `None` for an
/// empty list. The whole list must be well formed; an empty name is
/// returned as is (RFC 7301 forbids it, BoringSSL rejects it later).
pub fn first_alpn(data: &[u8]) -> Result<Option<&[u8]>, ParseError> {
    let mut r = Reader(data);
    let mut list = Reader(r.vec16("alpn list")?);
    r.finish("data after the alpn list")?;
    let mut first = None;
    while !list.is_empty() {
        let name = list.vec8("alpn protocol name")?;
        first = first.or(Some(name));
    }
    Ok(first)
}

/// The ClientHello body inside one TLS record captured on the wire: record
/// header (content type 22, version, length), then the handshake header
/// (type 1, 24-bit length). The record must hold the whole message (a
/// ClientHello fragmented over several records is refused); bytes after the
/// record are ignored.
pub fn body_from_record(wire: &[u8]) -> Result<&[u8], ParseError> {
    let mut r = Reader(wire);
    let [content_type] = r.array::<1>("record header")?;
    if content_type != 22 {
        return Err(ParseError("not a handshake record"));
    }
    r.u16("record header")?;
    let mut h = Reader(r.vec16("record")?);
    let [msg_type] = h.array::<1>("handshake header")?;
    if msg_type != 1 {
        return Err(ParseError("not a ClientHello"));
    }
    let [a, b, c] = h.array::<3>("handshake header")?;
    let len = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
    h.take(len, "ClientHello longer than its record")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal well-formed body: TLS 1.2, one cipher, null compression,
    /// with `exts` as the extension block (`None`: no block at all).
    fn body(exts: Option<&[u8]>) -> Vec<u8> {
        let mut b = vec![0x03, 0x03];
        b.extend_from_slice(&[7; 32]);
        b.push(0);
        b.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        if let Some(e) = exts {
            b.extend_from_slice(&u16::try_from(e.len()).unwrap().to_be_bytes());
            b.extend_from_slice(e);
        }
        b
    }

    #[test]
    fn parses_the_fields_and_extensions() {
        let exts = [0x00, 0x2b, 0, 3, 2, 3, 4, 0xff, 0x01, 0, 1, 0];
        let raw = body(Some(&exts));
        let h = ClientHello::parse(&raw).unwrap();
        assert_eq!(h.legacy_version, 0x0303);
        assert_eq!(h.cipher_suites().collect::<Vec<_>>(), [0x1301]);
        assert!(h.has_extensions());
        let e: Vec<_> = h.extensions().collect();
        assert_eq!(e, [(0x002b, &[2, 3, 4][..]), (0xff01, &[0][..])]);
        assert_eq!(
            u16s(supported_versions(e[0].1).unwrap()).collect::<Vec<_>>(),
            [0x0304]
        );

        let none = body(None);
        let h = ClientHello::parse(&none).unwrap();
        assert!(!h.has_extensions());
        assert_eq!(h.extensions().count(), 0);
        let empty = body(Some(&[]));
        assert!(ClientHello::parse(&empty).unwrap().has_extensions());
    }

    #[test]
    fn framing_errors_are_reported() {
        let mut long_sid = body(None);
        long_sid[34] = 33;
        long_sid.splice(35..35, [0; 33]);
        assert_eq!(
            ClientHello::parse(&long_sid).unwrap_err().what(),
            "legacy_session_id longer than 32 bytes"
        );
        let mut odd = body(None);
        odd.splice(35..39, [0, 3, 0x13, 0x01, 0x02]);
        assert_eq!(
            ClientHello::parse(&odd).unwrap_err().what(),
            "cipher_suites of odd length"
        );
        let mut trailing = body(Some(&[0xff, 0x01, 0, 1, 0]));
        trailing.push(0);
        assert_eq!(
            ClientHello::parse(&trailing).unwrap_err().what(),
            "data after the extensions"
        );
        // An extension whose length runs past the block.
        let overrun = body(Some(&[0xff, 0x01, 0, 2, 0]));
        assert_eq!(
            ClientHello::parse(&overrun).unwrap_err().what(),
            "extension data"
        );
        // A lone byte of an extension type.
        let half = body(Some(&[0xff]));
        assert_eq!(
            ClientHello::parse(&half).unwrap_err().what(),
            "extension type"
        );
        assert!(
            ParseError("x")
                .to_string()
                .contains("malformed ClientHello"),
            "Display"
        );
    }

    #[test]
    fn every_truncation_fails_except_at_the_optional_extension_block() {
        let raw = body(Some(&[0x00, 0x2b, 0, 3, 2, 3, 4, 0xff, 0x01, 0, 1, 0]));
        let no_exts = body(None).len();
        for n in 0..raw.len() {
            let r = ClientHello::parse(&raw[..n]);
            if n == no_exts {
                assert!(!r.unwrap().has_extensions(), "{n}");
            } else {
                assert!(r.is_err(), "prefix of {n} bytes parsed");
            }
        }
        assert!(ClientHello::parse(&raw).is_ok());
    }

    #[test]
    fn extension_accessors_check_their_bodies() {
        assert!(supported_versions(&[2, 3, 4]).is_ok());
        assert!(supported_versions(&[3, 3, 4, 3]).is_err(), "odd list");
        assert!(supported_versions(&[2, 3, 4, 0]).is_err(), "trailing");
        assert!(supported_versions(&[4, 3, 4]).is_err(), "short");
        assert!(signature_algorithms(&[0, 2, 4, 3]).is_ok());
        assert!(signature_algorithms(&[0, 3, 4, 3, 1]).is_err());
        assert!(signature_algorithms(&[0, 2, 4]).is_err());
        assert_eq!(
            first_alpn(&[
                0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1'
            ])
            .unwrap(),
            Some(&b"h2"[..])
        );
        assert_eq!(first_alpn(&[0, 0]).unwrap(), None);
        assert_eq!(first_alpn(&[0, 1, 0]).unwrap(), Some(&b""[..]));
        assert!(
            first_alpn(&[0, 2, 2, b'h']).is_err(),
            "name overruns the list"
        );
        assert!(
            first_alpn(&[0, 3, 2, b'h']).is_err(),
            "list overruns the body"
        );
        assert!(
            first_alpn(&[0, 3, 1, b'h', 1]).is_err(),
            "second name truncated"
        );
        assert!(first_alpn(&[0, 2, 1, b'h', 0]).is_err(), "trailing");
    }

    #[test]
    fn record_and_handshake_headers_are_stripped() {
        let b = body(None);
        let mut hs = vec![1, 0, 0, u8::try_from(b.len()).unwrap()];
        hs.extend_from_slice(&b);
        let mut rec = vec![22, 3, 1];
        rec.extend_from_slice(&u16::try_from(hs.len()).unwrap().to_be_bytes());
        rec.extend_from_slice(&hs);
        rec.extend_from_slice(b"next record");
        assert_eq!(body_from_record(&rec).unwrap(), &b[..]);
        let mut not_hs = rec.clone();
        not_hs[0] = 23;
        assert!(body_from_record(&not_hs).is_err());
        let mut not_ch = rec.clone();
        not_ch[5] = 2;
        assert!(body_from_record(&not_ch).is_err());
        // A handshake length beyond the record (fragmented) is refused.
        let mut frag = rec.clone();
        frag[8] = frag[8].wrapping_add(1);
        assert!(body_from_record(&frag).is_err());
        for n in 0..rec.len() - b"next record".len() {
            assert!(body_from_record(&rec[..n]).is_err(), "{n}");
        }
    }
}
