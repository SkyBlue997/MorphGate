//! The JA4 TLS client fingerprint of a ClientHello (docs/impl/phase1-spec.md
//! §15 WP-J1; ADR-0002 decision 4, ADR-0009).
//!
//! JA4 is by FoxIO (<https://github.com/FoxIO-LLC/ja4>) and published under
//! the BSD 3-Clause license (`LICENSE-JA4` in that repository). This module
//! is an independent implementation of the JA4 specification
//! (`technical_details/JA4.md`); no FoxIO code is copied. Only JA4, the TLS
//! client method, is implemented: the JA4+ methods (JA4S, JA4H, JA4L, JA4X,
//! JA4T, JA4SSH and the others) are under the FoxIO License 1.1 and are
//! never implemented here (ADR-0009).
//!
//! `JA4 = a_b_c`, 36 ASCII characters:
//!
//! | Part | Content |
//! |---|---|
//! | `a` (10) | `t` (TLS over TCP; the Edge never sees QUIC `q` or DTLS `d`), the version (2), `d` if the `server_name` extension is present else `i`, the cipher count (2), the extension count (2, `server_name` and ALPN included), the ALPN pair (2) |
//! | `b` (12) | first 12 hex digits of SHA-256 over the cipher suites, sorted, as 4-digit lower-case hex joined by `,`; `000000000000` when there is none |
//! | `c` (12) | the same over the extension types, sorted, without `server_name` (`0000`) and ALPN (`0010`), then `_` and the `signature_algorithms` values in the client's order (no `_` without them); `000000000000` when the sorted list is empty |
//!
//! * **GREASE** (RFC 8701, `0x?a?a` with equal bytes) values are ignored
//!   everywhere: cipher suites, extension types, `supported_versions` and
//!   signature algorithms. Counts are capped at 99.
//! * **Version**: the numerically highest `supported_versions` entry, else
//!   `legacy_version`; `13`, `12`, `11`, `10`, `s3`, `s2`, `d1`, `d2`, `d3`,
//!   otherwise `00`.
//! * **ALPN**: the first and last character of the first protocol name
//!   (`h2`, `http/1.1` → `h1`, one character twice); if either byte is not an
//!   ASCII letter or digit, the first and last hex digit of the name instead
//!   (`0xAB` → `ab`, `0x30 0xAB` → `3b`); `00` without ALPN or with an empty
//!   first name. This is the rule of the specification; FoxIO's own Python
//!   and Rust tools differ from it (they print a non-alphanumeric ASCII byte
//!   as is and a byte ≥ 0x80 as `9`, e.g. `99` for the capture
//!   `tls-non-ascii-alpn.pcapng` in their test data), so for such a client a
//!   JA4 from this module does not match one from those tools.
//!
//! Where the specification is silent this implementation chooses:
//! `supported_versions` without a non-GREASE entry falls back to
//! `legacy_version`; a repeated extension (BoringSSL refuses these before the
//! callback runs) is counted each time and its first occurrence is read;
//! a malformed body of an extension JA4 reads (`supported_versions`, ALPN,
//! `signature_algorithms`) is an error, as it is for BoringSSL.
//!
//! [`ja4`] allocates nothing on the heap for up to 128 cipher suites and 128
//! extensions (more spill into a `Vec`); the result is a `Copy` value.
//! [`ja4_r`] gives the raw (unhashed) form `JA4_r` for tests and debugging.

use super::client_hello::{
    ClientHello, EXT_ALPN, EXT_SERVER_NAME, EXT_SIGNATURE_ALGORITHMS, EXT_SUPPORTED_VERSIONS,
    ParseError, first_alpn, signature_algorithms, supported_versions, u16s,
};
use sha2::{Digest as _, Sha256};
use std::fmt;

/// Length of a JA4 fingerprint.
pub const LEN: usize = 36;

/// `b` / `c` of a part without values.
const EMPTY_HASH: [u8; 12] = *b"000000000000";

const HEX: &[u8; 16] = b"0123456789abcdef";

/// A JA4 fingerprint (`t13d1516h2_8daaf6152771_e5627efa2ab1`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ja4([u8; LEN]);

impl Ja4 {
    /// The fingerprint text (always ASCII).
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).unwrap_or_default()
    }
}

impl fmt::Display for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Ja4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ja4({})", self.as_str())
    }
}

/// Whether `v` is a GREASE value (RFC 8701 §2).
pub fn is_grease(v: u16) -> bool {
    v & 0x0f0f == 0x0a0a && v >> 8 == v & 0xff
}

/// The JA4 of a ClientHello body (from `legacy_version` on, as BoringSSL's
/// `ClientHello::as_bytes()` gives it).
pub fn ja4(body: &[u8]) -> Result<Ja4, ParseError> {
    Ok(Fields::parse(body)?.ja4())
}

/// `JA4_r`: the JA4 inputs before hashing, `a_ciphers_extensions[_sigalgs]`.
pub fn ja4_r(body: &[u8]) -> Result<String, ParseError> {
    Ok(Fields::parse(body)?.raw())
}

/// A `u16` list kept on the stack; a longer list spills to the heap
/// (`Vec::new` does not allocate until then).
#[derive(Debug, Clone)]
struct U16List {
    inline: [u16; Self::INLINE],
    len: usize,
    /// Empty until the list outgrows `inline`, then the whole list.
    spill: Vec<u16>,
}

impl U16List {
    const INLINE: usize = 128;

    fn new() -> Self {
        Self {
            inline: [0; Self::INLINE],
            len: 0,
            spill: Vec::new(),
        }
    }

    fn push(&mut self, v: u16) {
        if self.spill.is_empty() {
            if let Some(slot) = self.inline.get_mut(self.len) {
                *slot = v;
                self.len += 1;
                return;
            }
            self.spill.reserve(Self::INLINE * 2);
            self.spill.extend_from_slice(&self.inline);
        }
        self.spill.push(v);
    }

    fn as_mut_slice(&mut self) -> &mut [u16] {
        if self.spill.is_empty() {
            self.inline.get_mut(..self.len).unwrap_or_default()
        } else {
            &mut self.spill
        }
    }

    fn as_slice(&self) -> &[u16] {
        if self.spill.is_empty() {
            self.inline.get(..self.len).unwrap_or_default()
        } else {
            &self.spill
        }
    }
}

/// The JA4 inputs of one ClientHello.
#[derive(Debug)]
struct Fields<'a> {
    a: [u8; 10],
    /// Sorted, without GREASE.
    ciphers: U16List,
    /// Sorted, without GREASE, `server_name` and ALPN.
    extensions: U16List,
    /// The `signature_algorithms` list in the client's order (GREASE is
    /// skipped when it is written).
    sigalgs: &'a [u8],
}

impl<'a> Fields<'a> {
    fn parse(body: &'a [u8]) -> Result<Self, ParseError> {
        let hello = ClientHello::parse(body)?;
        let mut ciphers = U16List::new();
        for c in hello.cipher_suites().filter(|c| !is_grease(*c)) {
            ciphers.push(c);
        }
        let mut extensions = U16List::new();
        let mut count = 0usize;
        let mut sni = false;
        let mut alpn: Option<Option<&[u8]>> = None;
        let mut versions: Option<&[u8]> = None;
        let mut sigalgs: Option<&[u8]> = None;
        for (ty, data) in hello.extensions() {
            if is_grease(ty) {
                continue;
            }
            count += 1;
            match ty {
                EXT_SERVER_NAME => sni = true,
                EXT_ALPN => {
                    let first = first_alpn(data)?;
                    alpn = alpn.or(Some(first));
                }
                EXT_SUPPORTED_VERSIONS => {
                    let list = supported_versions(data)?;
                    versions = versions.or(Some(list));
                }
                EXT_SIGNATURE_ALGORITHMS => {
                    let list = signature_algorithms(data)?;
                    sigalgs = sigalgs.or(Some(list));
                }
                _ => {}
            }
            if ty != EXT_SERVER_NAME && ty != EXT_ALPN {
                extensions.push(ty);
            }
        }
        ciphers.as_mut_slice().sort_unstable();
        extensions.as_mut_slice().sort_unstable();

        let version = versions
            .and_then(|l| u16s(l).filter(|v| !is_grease(*v)).max())
            .unwrap_or(hello.legacy_version);
        let [v0, v1] = version_code(version);
        let [c0, c1] = two_digits(ciphers.as_slice().len());
        let [e0, e1] = two_digits(count);
        let [a0, a1] = alpn_code(alpn.flatten());
        Ok(Self {
            a: [
                b't',
                v0,
                v1,
                if sni { b'd' } else { b'i' },
                c0,
                c1,
                e0,
                e1,
                a0,
                a1,
            ],
            ciphers,
            extensions,
            sigalgs: sigalgs.unwrap_or_default(),
        })
    }

    fn sigalgs(&self) -> impl Iterator<Item = u16> + '_ {
        u16s(self.sigalgs).filter(|v| !is_grease(*v))
    }

    fn ja4(&self) -> Ja4 {
        let b = match self.ciphers.as_slice() {
            [] => EMPTY_HASH,
            list => hash12(|h| write_list(h, list.iter().copied())),
        };
        let c = match self.extensions.as_slice() {
            [] => EMPTY_HASH,
            list => hash12(|h| {
                write_list(h, list.iter().copied());
                if self.sigalgs().next().is_some() {
                    h.update(b"_");
                    write_list(h, self.sigalgs());
                }
            }),
        };
        let mut out = [b'_'; LEN];
        let (a_out, rest) = out.split_at_mut(10);
        a_out.copy_from_slice(&self.a);
        let (b_out, c_out) = rest.split_at_mut(13);
        b_out[1..].copy_from_slice(&b);
        c_out[1..].copy_from_slice(&c);
        Ja4(out)
    }

    fn raw(&self) -> String {
        let mut s: String = self.a.iter().copied().map(char::from).collect();
        s.push('_');
        s.push_str(&join(self.ciphers.as_slice().iter().copied()));
        s.push('_');
        s.push_str(&join(self.extensions.as_slice().iter().copied()));
        if self.sigalgs().next().is_some() {
            s.push('_');
            s.push_str(&join(self.sigalgs()));
        }
        s
    }
}

/// The two-character version code.
fn version_code(v: u16) -> [u8; 2] {
    match v {
        0x0304 => *b"13",
        0x0303 => *b"12",
        0x0302 => *b"11",
        0x0301 => *b"10",
        0x0300 => *b"s3",
        0x0002 => *b"s2",
        0xfeff => *b"d1",
        0xfefd => *b"d2",
        0xfefc => *b"d3",
        _ => *b"00",
    }
}

/// `n` as two decimal digits, capped at 99.
fn two_digits(n: usize) -> [u8; 2] {
    let n = u8::try_from(n.min(99)).unwrap_or(99);
    [b'0' + n / 10, b'0' + n % 10]
}

/// The ALPN pair of the first protocol name.
fn alpn_code(first: Option<&[u8]>) -> [u8; 2] {
    let first = first.unwrap_or_default();
    let (Some(&head), Some(&tail)) = (first.first(), first.last()) else {
        return *b"00";
    };
    if head.is_ascii_alphanumeric() && tail.is_ascii_alphanumeric() {
        [head, tail]
    } else {
        [HEX[usize::from(head >> 4)], HEX[usize::from(tail & 0x0f)]]
    }
}

/// `list` as comma-separated 4-digit hex (`JA4_r`).
fn join(list: impl Iterator<Item = u16>) -> String {
    let mut s = String::new();
    for (i, v) in list.enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.extend(hex4(v).map(char::from));
    }
    s
}

fn hex4(v: u16) -> [u8; 4] {
    let [hi, lo] = v.to_be_bytes();
    [
        HEX[usize::from(hi >> 4)],
        HEX[usize::from(hi & 0x0f)],
        HEX[usize::from(lo >> 4)],
        HEX[usize::from(lo & 0x0f)],
    ]
}

/// Writes `list` as comma-separated 4-digit hex.
fn write_list(h: &mut Sha256, list: impl Iterator<Item = u16>) {
    for (i, v) in list.enumerate() {
        if i > 0 {
            h.update(b",");
        }
        h.update(hex4(v));
    }
}

/// The first 12 hex digits of the SHA-256 of what `write` feeds in.
fn hash12(write: impl FnOnce(&mut Sha256)) -> [u8; 12] {
    let mut h = Sha256::new();
    write(&mut h);
    let digest = h.finalize();
    let mut out = [0u8; 12];
    for (pair, byte) in out.chunks_exact_mut(2).zip(digest.iter()) {
        pair.copy_from_slice(&[HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0x0f)]]);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A ClientHello builder for tests: fields are written exactly as given
    /// (GREASE, order and duplicates included).
    #[derive(Debug, Clone)]
    pub(crate) struct Hello {
        pub legacy_version: u16,
        pub ciphers: Vec<u16>,
        /// `None`: no extension block at all.
        pub extensions: Option<Vec<(u16, Vec<u8>)>>,
    }

    pub(crate) fn vec8(body: &[u8]) -> Vec<u8> {
        let mut v = vec![u8::try_from(body.len()).unwrap()];
        v.extend_from_slice(body);
        v
    }

    pub(crate) fn vec16(body: &[u8]) -> Vec<u8> {
        let mut v = u16::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    pub(crate) fn be(list: &[u16]) -> Vec<u8> {
        list.iter().flat_map(|v| v.to_be_bytes()).collect()
    }

    /// `server_name` with one host name.
    pub(crate) fn sni(host: &str) -> (u16, Vec<u8>) {
        let mut entry = vec![0];
        entry.extend(vec16(host.as_bytes()));
        (0x0000, vec16(&entry))
    }

    pub(crate) fn alpn(names: &[&[u8]]) -> (u16, Vec<u8>) {
        let list: Vec<u8> = names.iter().flat_map(|n| vec8(n)).collect();
        (0x0010, vec16(&list))
    }

    pub(crate) fn versions(list: &[u16]) -> (u16, Vec<u8>) {
        (0x002b, vec8(&be(list)))
    }

    pub(crate) fn sigalgs(list: &[u16]) -> (u16, Vec<u8>) {
        (0x000d, vec16(&be(list)))
    }

    /// An extension whose body JA4 does not read.
    pub(crate) fn ext(ty: u16) -> (u16, Vec<u8>) {
        (ty, vec![0])
    }

    impl Hello {
        pub(crate) fn body(&self) -> Vec<u8> {
            let mut b = self.legacy_version.to_be_bytes().to_vec();
            b.extend_from_slice(&[0x5a; 32]);
            b.extend(vec8(&[0x11; 32]));
            b.extend(vec16(&be(&self.ciphers)));
            b.extend(vec8(&[0]));
            if let Some(exts) = &self.extensions {
                let block: Vec<u8> = exts
                    .iter()
                    .flat_map(|(ty, data)| {
                        let mut e = ty.to_be_bytes().to_vec();
                        e.extend(vec16(data));
                        e
                    })
                    .collect();
                b.extend(vec16(&block));
            }
            b
        }

        pub(crate) fn ja4(&self) -> String {
            ja4(&self.body()).unwrap().to_string()
        }

        pub(crate) fn ja4_r(&self) -> String {
            ja4_r(&self.body()).unwrap()
        }

        fn without_grease(&self) -> Self {
            let mut h = self.clone();
            h.ciphers.retain(|c| !is_grease(*c));
            if let Some(exts) = &mut h.extensions {
                exts.retain(|(ty, _)| !is_grease(*ty));
                for (ty, data) in exts.iter_mut() {
                    let strip = |list: &[u8]| -> Vec<u8> {
                        u16s(list)
                            .filter(|v| !is_grease(*v))
                            .flat_map(u16::to_be_bytes)
                            .collect()
                    };
                    match *ty {
                        0x002b => *data = vec8(&strip(&data[1..])),
                        0x000d => *data = vec16(&strip(&data[2..])),
                        _ => {}
                    }
                }
            }
            h
        }
    }

    /// JA4 from `JA4_r` by the definition (hash the `b` and `c` parts of the
    /// raw form), independent of the fingerprint code path.
    pub(crate) fn from_raw(raw: &str) -> String {
        let (a, rest) = raw.split_at(10);
        let (b, c) = rest[1..].split_once('_').unwrap();
        let h = |s: &str| {
            if s.is_empty() {
                "000000000000".to_owned()
            } else {
                let d = Sha256::digest(s.as_bytes());
                d.iter().take(6).map(|x| format!("{x:02x}")).collect()
            }
        };
        let c_list = c.split('_').next().unwrap();
        format!(
            "{a}_{}_{}",
            h(b),
            if c_list.is_empty() { h("") } else { h(c) }
        )
    }

    const G: [u16; 4] = [0x0a0a, 0x5a5a, 0xbaba, 0xfafa];

    /// Chrome's 15 cipher suites in its order, after one GREASE value.
    fn chrome_ciphers() -> Vec<u16> {
        vec![
            G[0], 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013,
            0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
        ]
    }

    const CHROME_SIGALGS: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];

    /// A Chrome ClientHello with GREASE and a shuffled extension order;
    /// `extra` are the extension types beyond Chrome's common set.
    fn chrome(extra: &[u16]) -> Hello {
        let mut exts = vec![
            (G[1], vec![]),
            ext(0x001b),
            sni("example.com"),
            ext(0x0023),
            versions(&[G[2], 0x0304, 0x0303]),
            ext(0x000b),
            alpn(&[b"h2", b"http/1.1"]),
            ext(0x0033),
            sigalgs(&CHROME_SIGALGS),
            ext(0x0017),
            ext(0x4469),
            ext(0x000a),
            ext(0x002d),
            ext(0x0005),
            ext(0xff01),
            ext(0x0012),
            (G[3], vec![0]),
        ];
        exts.extend(extra.iter().map(|t| ext(*t)));
        Hello {
            legacy_version: 0x0303,
            ciphers: chrome_ciphers(),
            extensions: Some(exts),
        }
    }

    /// Firefox: 17 cipher suites, no GREASE.
    fn firefox() -> Hello {
        Hello {
            legacy_version: 0x0303,
            ciphers: vec![
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: Some(vec![
                sni("example.com"),
                ext(0x0017),
                ext(0xff01),
                ext(0x000a),
                ext(0x000b),
                ext(0x0023),
                alpn(&[b"h2", b"http/1.1"]),
                ext(0x0005),
                ext(0x0022),
                ext(0x0033),
                versions(&[0x0304, 0x0303]),
                sigalgs(&[
                    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                    0x0201,
                ]),
                ext(0x002d),
                ext(0x001c),
                ext(0x0015),
            ]),
        }
    }

    /// FoxIO's published JA4 examples (`technical_details/JA4.md`; the
    /// Chrome examples of the JA4 README from 2023-10 to 2026-08; the
    /// expected output of FoxIO's test capture `tls12.pcap` for Firefox).
    /// The inputs are those clients' cipher, extension and
    /// signature-algorithm lists: their SHA-256 prefixes reproduce the
    /// published `b` and `c` parts (checked independently with Python's
    /// `hashlib`, not with this module).
    #[test]
    fn published_foxio_vectors() {
        // technical_details/JA4.md: Chrome, with the padding extension.
        let h = chrome(&[0x0015]);
        assert_eq!(
            h.ja4_r(),
            "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_\
             0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_\
             0403,0804,0401,0503,0805,0501,0806,0601"
        );
        assert_eq!(h.ja4(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
        // README (until 2026-08): Chromium, with ECH GREASE (fe0d) instead
        // of padding.
        assert_eq!(
            chrome(&[0xfe0d]).ja4(),
            "t13d1516h2_8daaf6152771_02713d6af862"
        );
        // README (until 2026-08): Chromium resuming a session
        // (pre_shared_key 0029, last).
        assert_eq!(
            chrome(&[0xfe0d, 0x0029]).ja4(),
            "t13d1517h2_8daaf6152771_b0da82dd1658"
        );
        // FoxIO test data `tls12.pcap` (python/test/testdata, Rust insta
        // snapshot): Firefox to contile.services.mozilla.com.
        assert_eq!(firefox().ja4(), "t13d1715h2_5b57614c22b0_3d5424432f57");
        // README (Chromium over QUIC, `q13d0312h3_55b375c5d22e_...`): the
        // cipher part of the three TLS 1.3 suites.
        let quic = Hello {
            legacy_version: 0x0303,
            ciphers: vec![G[0], 0x1301, 0x1302, 0x1303],
            extensions: Some(vec![versions(&[0x0304])]),
        };
        assert_eq!(&quic.ja4()[..23], "t13i030100_55b375c5d22e");
    }

    /// More expected outputs of FoxIO's own test captures (the `JA4.1` /
    /// `JA4_ro.1` fields of `python/test/testdata/*.json`, identical in the
    /// Rust insta snapshots). The hellos below use those captures' original
    /// (`JA4_ro`) cipher, extension and signature-algorithm orders.
    /// `JA4_ro` leaves GREASE out, so GREASE values are added back,
    /// including the signature algorithm `sigalg-grease` is named after.
    #[test]
    fn foxio_test_capture_vectors() {
        // `sigalg-grease.pcapng`: Chrome with a GREASE signature algorithm,
        // ML-DSA schemes (0904-0906), ALPS 44cd, ECH GREASE fe0d and ca34.
        // Also the Chrome example of the current JA4 README (since 2026-08).
        let sigalg_grease = Hello {
            legacy_version: 0x0303,
            ciphers: [&[G[2]][..], &chrome_ciphers()[1..]].concat(),
            extensions: Some(vec![
                (G[0], vec![]),
                ext(0xfe0d),
                alpn(&[b"h2", b"http/1.1"]),
                ext(0x0017),
                ext(0x0033),
                ext(0x44cd),
                ext(0xff01),
                ext(0x000a),
                sigalgs(&[
                    G[3], 0x0904, 0x0905, 0x0906, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
                    0x0806, 0x0601,
                ]),
                ext(0x0023),
                versions(&[G[1], 0x0304, 0x0303]),
                ext(0x000b),
                ext(0xca34),
                ext(0x002d),
                sni("optimizationguide-pa.googleapis.com"),
                ext(0x0005),
                ext(0x001b),
                ext(0x0012),
                (G[1], vec![0]),
            ]),
        };
        assert_eq!(
            sigalg_grease.ja4_r(),
            "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_\
             0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01_\
             0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
        );
        assert_eq!(sigalg_grease.ja4(), "t13d1517h2_8daaf6152771_cb7bf5808d99");
        // `badcurveball.pcap`: 16 suites (3DES 000a last) and a SHA-1
        // signature algorithm (0201), 15 extensions.
        let badcurveball = Hello {
            legacy_version: 0x0303,
            ciphers: [&chrome_ciphers()[1..], &[0x000a][..]].concat(),
            extensions: Some(vec![
                sni("bad.curveballtest.com"),
                ext(0x0017),
                ext(0xff01),
                ext(0x000a),
                ext(0x000b),
                ext(0x0023),
                alpn(&[b"h2", b"http/1.1"]),
                ext(0x0005),
                sigalgs(&[
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
                ]),
                ext(0x0012),
                ext(0x0033),
                ext(0x002d),
                versions(&[0x0304, 0x0303]),
                ext(0x001b),
                ext(0x0015),
            ]),
        };
        assert_eq!(badcurveball.ja4(), "t13d1615h2_46e7e9700bed_45f260be83e2");
        // technical_details/JA4.md: the extension list without signature
        // algorithms hashes without a trailing `_`.
        let mut no_sigalgs = chrome(&[0x0015]).without_grease();
        for (ty, data) in no_sigalgs.extensions.as_mut().unwrap() {
            if *ty == 0x000d {
                *data = sigalgs(&[]).1;
            }
        }
        assert_eq!(&no_sigalgs.ja4()[24..], "6d807ffa2a79");
    }

    #[test]
    fn grease_is_ignored_everywhere() {
        let h = chrome(&[0x0015]);
        assert!(h.ciphers.iter().any(|c| is_grease(*c)));
        let clean = h.without_grease();
        assert_eq!(
            clean.extensions.as_ref().unwrap().len() + 2,
            h.extensions.as_ref().unwrap().len()
        );
        assert_eq!(h.ja4(), clean.ja4());
        assert_eq!(h.ja4_r(), clean.ja4_r());
        // A GREASE signature algorithm (no client sends one) is skipped too.
        let mut g = clean.clone();
        for (ty, data) in g.extensions.as_mut().unwrap() {
            if *ty == 0x000d {
                *data = sigalgs(&[
                    0x1a1a, 0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
                ])
                .1;
            }
        }
        assert_eq!(g.ja4(), h.ja4());
        // Every RFC 8701 value, and nothing else.
        let grease: Vec<u16> = (0..=u16::MAX).filter(|v| is_grease(*v)).collect();
        assert_eq!(grease.len(), 16);
        assert!(grease.iter().all(|v| v & 0x0f0f == 0x0a0a));
        assert!(!is_grease(0x0a1a) && !is_grease(0x1a0a) && !is_grease(0x0a0b));
        // Only GREASE ciphers: count 00 and an empty `b`; a GREASE extension
        // is not counted, and a GREASE-only supported_versions falls back to
        // legacy_version.
        let only = Hello {
            legacy_version: 0x0303,
            ciphers: G.to_vec(),
            extensions: Some(vec![versions(&[G[0]]), (G[1], vec![])]),
        };
        assert_eq!(only.ja4_r(), "t12i000100__002b");
        assert_eq!(&only.ja4()[..23], "t12i000100_000000000000");
        assert_eq!(only.ja4(), from_raw(&only.ja4_r()));
    }

    #[test]
    fn extension_order_does_not_matter_but_signature_order_does() {
        let h = chrome(&[0x0015]);
        let want = h.ja4();
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..200 {
            let mut p = h.clone();
            let exts = p.extensions.as_mut().unwrap();
            for i in (1..exts.len()).rev() {
                let j = usize::try_from(xorshift(&mut seed) % (i as u64 + 1)).unwrap();
                exts.swap(i, j);
            }
            p.ciphers.reverse();
            assert_eq!(p.ja4(), want);
        }
        let mut swapped = h.clone();
        for (ty, data) in swapped.extensions.as_mut().unwrap() {
            if *ty == 0x000d {
                let mut s = CHROME_SIGALGS;
                s.swap(0, 1);
                *data = sigalgs(&s).1;
            }
        }
        assert_eq!(swapped.ja4()[..23], want[..23]);
        assert_ne!(swapped.ja4()[24..], want[24..]);
    }

    #[test]
    fn alpn_pairs() {
        fn n(s: &[u8]) -> &[u8] {
            s
        }
        let cases: Vec<(Option<Vec<&[u8]>>, &str)> = vec![
            (None, "00"),
            (Some(vec![]), "00"),
            (Some(vec![n(b"")]), "00"),
            (Some(vec![n(b"h2")]), "h2"),
            (Some(vec![n(b"http/1.1"), n(b"h2")]), "h1"),
            (Some(vec![n(b"h")]), "hh"),
            (Some(vec![n(b"h3"), n(b"h2")]), "h3"),
            // The examples of the specification.
            (Some(vec![n(&[0xab])]), "ab"),
            (Some(vec![n(&[0x20])]), "20"),
            (Some(vec![n(&[0xab, 0xcd])]), "ad"),
            (Some(vec![n(&[0x20, 0x61])]), "21"),
            (Some(vec![n(&[0x30, 0xab])]), "3b"),
            (Some(vec![n(&[0x61, 0x20])]), "60"),
            (Some(vec![n(&[0x30, 0x31, 0xab, 0xcd])]), "3d"),
            (Some(vec![n(&[0x30, 0xab, 0xcd, 0x31])]), "01"),
            // Non-ASCII UTF-8 ("é" = c3 a9): hex digits.
            (Some(vec!["é".as_bytes()]), "c9"),
        ];
        for (names, want) in cases {
            let mut exts = vec![versions(&[0x0304])];
            if let Some(n) = &names {
                exts.push(alpn(n));
            }
            let h = Hello {
                legacy_version: 0x0303,
                ciphers: vec![0x1301],
                extensions: Some(exts),
            };
            assert_eq!(&h.ja4()[8..10], want, "{names:?}");
            assert_eq!(h.ja4(), from_raw(&h.ja4_r()));
        }
        // Printable but not alphanumeric.
        assert_eq!(alpn_code(Some(n(b"h/"))), *b"6f");
        assert_eq!(alpn_code(Some(n(b"-2"))), *b"22");
    }

    #[test]
    fn sni_absent_changes_only_the_marker_and_the_count() {
        let with = chrome(&[0x0015]);
        let mut without = with.clone();
        without
            .extensions
            .as_mut()
            .unwrap()
            .retain(|(ty, _)| *ty != 0x0000);
        assert_eq!(without.ja4(), "t13i1515h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(with.ja4()[11..], without.ja4()[11..]);
    }

    #[test]
    fn versions_tls12_and_tls13() {
        let base = |legacy: u16, exts: Option<Vec<(u16, Vec<u8>)>>| Hello {
            legacy_version: legacy,
            ciphers: vec![0xc02f, 0xc02b, 0x009c],
            extensions: exts,
        };
        // TLS 1.2 without supported_versions.
        let tls12 = base(
            0x0303,
            Some(vec![
                sni("example.com"),
                ext(0x000a),
                ext(0x000b),
                sigalgs(&[0x0401, 0x0403]),
                ext(0x0017),
            ]),
        );
        assert_eq!(
            tls12.ja4_r(),
            "t12d030500_009c,c02b,c02f_000a,000b,000d,0017_0401,0403"
        );
        assert_eq!(tls12.ja4(), from_raw(&tls12.ja4_r()));
        // TLS 1.3 through supported_versions, in any order, GREASE first.
        for list in [
            vec![G[0], 0x0304, 0x0303],
            vec![0x0303, 0x0304],
            vec![0x0302, 0x0304, 0x0303, G[1]],
        ] {
            let h = base(0x0303, Some(vec![versions(&list)]));
            assert_eq!(&h.ja4()[..3], "t13", "{list:x?}");
        }
        // supported_versions without a usable entry: legacy_version.
        assert_eq!(
            &base(0x0303, Some(vec![versions(&[G[0]])])).ja4()[..3],
            "t12"
        );
        assert_eq!(&base(0x0303, Some(vec![versions(&[])])).ja4()[..3], "t12");
        // Legacy versions and an unknown one.
        for (legacy, want) in [
            (0x0303, "t12"),
            (0x0302, "t11"),
            (0x0301, "t10"),
            (0x0300, "ts3"),
            (0x0002, "ts2"),
            (0x0305, "t00"),
            (0xfefd, "td2"),
        ] {
            assert_eq!(&base(legacy, Some(vec![])).ja4()[..3], want);
        }
        // No extension block at all (a valid pre-TLS 1.2 message).
        let bare = base(0x0301, None);
        assert_eq!(bare.ja4(), from_raw(&bare.ja4_r()));
        assert!(bare.ja4().starts_with("t10i030000_") && bare.ja4().ends_with("_000000000000"));
    }

    #[test]
    fn empty_parts_and_caps() {
        // No cipher suites; only SNI and ALPN: `b` and `c` are zeros.
        let h = Hello {
            legacy_version: 0x0303,
            ciphers: vec![],
            extensions: Some(vec![sni("a.test"), alpn(&[b"h2"])]),
        };
        assert_eq!(h.ja4(), "t12d0002h2_000000000000_000000000000");
        // signature_algorithms present but empty: no `_` in `c`.
        let e = Hello {
            legacy_version: 0x0303,
            ciphers: vec![0x1301],
            extensions: Some(vec![sigalgs(&[]), ext(0x0017)]),
        };
        assert_eq!(e.ja4_r(), "t12i010200_1301_000d,0017");
        assert_eq!(e.ja4(), from_raw(&e.ja4_r()));
        // More than 99 (and more than the 128 kept inline): capped counts.
        let many = Hello {
            legacy_version: 0x0303,
            ciphers: (0x0100..0x0100 + 300).collect(),
            extensions: Some((0xe000..0xe000 + 150).map(ext).collect()),
        };
        let v = many.ja4();
        assert_eq!(&v[..10], "t12i999900");
        assert_eq!(v, from_raw(&many.ja4_r()));
        // Sorted after spilling to the heap.
        let mut rev = many.clone();
        rev.ciphers.reverse();
        rev.extensions.as_mut().unwrap().reverse();
        assert_eq!(rev.ja4(), v);
    }

    #[test]
    fn repeated_extensions_count_each_time_and_the_first_is_read() {
        let h = Hello {
            legacy_version: 0x0303,
            ciphers: vec![0x1301],
            extensions: Some(vec![
                alpn(&[b"h2"]),
                alpn(&[b"http/1.1"]),
                versions(&[0x0304]),
                versions(&[0x0302]),
            ]),
        };
        assert_eq!(h.ja4_r(), "t13i0104h2_1301_002b,002b");
    }

    #[test]
    fn malformed_extension_bodies_are_errors() {
        for bad in [
            (0x0010, vec![0, 3, 2, b'h']),
            (0x0010, vec![0]),
            (0x002b, vec![3, 3, 4, 3]),
            (0x002b, vec![]),
            (0x000d, vec![0, 1, 4]),
            (0x000d, vec![0, 2, 4, 3, 0]),
        ] {
            let h = Hello {
                legacy_version: 0x0303,
                ciphers: vec![0x1301],
                extensions: Some(vec![bad.clone()]),
            };
            assert!(ja4(&h.body()).is_err(), "{bad:x?}");
            assert!(ja4_r(&h.body()).is_err(), "{bad:x?}");
        }
        // A malformed body of an extension JA4 does not read is fine.
        let h = Hello {
            legacy_version: 0x0303,
            ciphers: vec![0x1301],
            extensions: Some(vec![(0x000a, vec![0, 9])]),
        };
        assert!(ja4(&h.body()).is_ok());
    }

    #[test]
    fn every_truncation_of_a_real_hello_fails_cleanly() {
        let hello = chrome(&[0x0015]);
        let body = hello.body();
        // The one valid prefix: the message without its extension block.
        let bare = Hello {
            extensions: None,
            ..hello
        }
        .body()
        .len();
        for n in 0..body.len() {
            match ja4(&body[..n]) {
                Ok(v) => assert_eq!((n, &v.as_str()[..10]), (bare, "t12i150000")),
                Err(_) => assert_ne!(n, bare),
            }
        }
    }

    fn xorshift(s: &mut u64) -> u64 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    fn assert_shape(v: &Ja4) {
        let s = v.as_str();
        assert_eq!(s.len(), LEN);
        assert!(s.is_ascii());
        assert!(s.starts_with('t'));
        assert_eq!((&s[10..11], &s[23..24]), ("_", "_"));
        assert!(
            s[11..23]
                .bytes()
                .chain(s[24..].bytes())
                .all(|b| HEX.contains(&b))
        );
    }

    /// §2.4 item 3: ≥ 10,000 deterministic random inputs never panic.
    /// Random bytes (mostly rejected early), random bytes behind a valid
    /// header, and bit flips, byte changes and cuts of a real ClientHello
    /// (which reach the extension parsers).
    #[test]
    fn random_inputs_never_panic() {
        let real = chrome(&[0x0015, 0xfe0d]).body();
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let (mut ok, mut err) = (0u32, 0u32);
        for i in 0..30_000u32 {
            let r = xorshift(&mut seed);
            let input: Vec<u8> = match i % 3 {
                0 => {
                    let len = usize::try_from(r % 700).unwrap();
                    (0..len).map(|_| xorshift(&mut seed) as u8).collect()
                }
                1 => {
                    let mut v = real[..35].to_vec();
                    let len = usize::try_from(r % 400).unwrap();
                    v.extend((0..len).map(|_| xorshift(&mut seed) as u8));
                    v
                }
                _ => {
                    let mut v = real.clone();
                    for _ in 0..1 + r % 6 {
                        let x = xorshift(&mut seed);
                        let at = usize::try_from(x % v.len() as u64).unwrap();
                        match x >> 60 {
                            0..=7 => v[at] ^= 1 << ((x >> 32) & 7),
                            8..=13 => v[at] = (x >> 40) as u8,
                            _ => v.truncate(at),
                        }
                        if v.is_empty() {
                            break;
                        }
                    }
                    v
                }
            };
            match ja4(&input) {
                Ok(v) => {
                    assert_shape(&v);
                    assert_eq!(v.to_string(), from_raw(&ja4_r(&input).unwrap()));
                    ok += 1;
                }
                Err(e) => {
                    assert!(ja4_r(&input).is_err());
                    assert!(!e.what().is_empty());
                    err += 1;
                }
            }
        }
        // Both outcomes are exercised.
        assert!(ok > 200 && err > 1000, "ok {ok}, err {err}");
    }

    /// The allocation claim of the module docs, without a counting
    /// allocator (the workspace forbids `unsafe`): the lists stay inline up
    /// to 128 entries and only then reserve heap memory.
    #[test]
    fn lists_stay_inline_up_to_128_entries() {
        let body = chrome(&[0x0015, 0xfe0d]).body();
        let f = Fields::parse(&body).unwrap();
        assert_eq!(
            (f.ciphers.spill.capacity(), f.extensions.spill.capacity()),
            (0, 0)
        );
        let at_limit = Hello {
            legacy_version: 0x0303,
            ciphers: (0x0100..0x0100 + 128).collect(),
            extensions: Some((0xe000..0xe000 + 128).map(ext).collect()),
        }
        .body();
        let f = Fields::parse(&at_limit).unwrap();
        assert_eq!(
            (f.ciphers.spill.capacity(), f.extensions.spill.capacity()),
            (0, 0)
        );
        let over = Hello {
            legacy_version: 0x0303,
            ciphers: (0x0100..0x0100 + 129).collect(),
            extensions: Some(vec![ext(0x0017)]),
        }
        .body();
        let f = Fields::parse(&over).unwrap();
        assert_eq!(f.ciphers.as_slice().len(), 129);
        assert!(f.ciphers.spill.capacity() >= 129);
        assert_eq!(f.extensions.spill.capacity(), 0);
    }

    #[test]
    fn display_and_debug() {
        let v = ja4(&firefox().body()).unwrap();
        assert_eq!(format!("{v}"), "t13d1715h2_5b57614c22b0_3d5424432f57");
        assert_eq!(
            format!("{v:?}"),
            "Ja4(t13d1715h2_5b57614c22b0_3d5424432f57)"
        );
    }
}
