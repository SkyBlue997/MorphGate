//! Sealed challenge `C` (spec §6.2, §6.8): round trips, tampering, epoch
//! boundaries, every length / presence check of open steps 1 and 4, two
//! Edges sharing a root, root rotation and RNG failure.
//!
//! Malformed challenges are built here directly with the documented
//! construction (HKDF epoch key, XChaCha20-Poly1305, prost envelope), which
//! is also an independent check of the format.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use common::{DAY_START_MS, FailingRng, MIDDAY_MS, TestRng, pow_claims, seal_root, sealer};
use mg_challenge::{
    MAX_C_LEN, OpenError, SealError, aad, check_challenge_bind, derive_epoch_key, epoch_kid,
    epoch_no, random_nonce,
};
use mg_core::{BindResult, ChallengeType, ClaimsError, SealedChallengeClaims};
use mg_proto::v1::sealed_challenge_claims::{Bind, Pow};
use mg_proto::v1::{SealedChallenge, SealedChallengeClaims as ProtoClaims};
use prost::Message;

const HOST: &str = "example.com";

/// Edits wire claims before they are sealed by hand.
type Mutation = dyn Fn(&mut ProtoClaims);
/// Edits the raw bytes of an envelope.
type RawEdit = dyn Fn(&mut Vec<u8>);
const EPOCH: u64 = 20_736; // epoch_no(DAY_START_MS)

/// Native claims → wire claims, written independently of the crate.
fn proto_of(c: &SealedChallengeClaims) -> ProtoClaims {
    ProtoClaims {
        v: c.v,
        kid: c.kid.clone(),
        nonce: c.nonce.to_vec(),
        site: c.site.clone(),
        route_class: c.route_class.clone(),
        r#type: c.challenge_type.to_proto(),
        providers: c.providers.iter().map(|p| p.to_string()).collect(),
        risk_band: c.risk_band.to_string(),
        attempt_no: c.attempt_no,
        iat: c.iat_ms,
        exp: c.exp_ms,
        ui_seed: c.ui_seed,
        pow: c.pow.as_ref().map(|p| Pow {
            alg: p.alg.clone(),
            difficulty: p.difficulty,
        }),
        ret: c.ret_hash.clone(),
        bind: Some(Bind {
            uah: c.bind.uah.clone(),
            ipp: c.bind.ipp.clone(),
            jkt: c.bind.jkt.clone(),
            ctp: c.bind.ctp.clone(),
            tfp: c.bind.tfp.clone(),
            ipa: c.bind.ipa.clone(),
        }),
    }
}

/// Builds `C` by hand: `plaintext` sealed under root `root` of site `site`
/// for the epoch of `kid`, with the aad of (`HOST`, `aad_type`, `kid`); the
/// envelope carries `v`, `kid`, `xnonce` (the first 24 bytes are the real
/// nonce) and the ciphertext cut to `ct_len` bytes if given.
struct Craft {
    root: u8,
    site: &'static str,
    kid: String,
    aad_type: ChallengeType,
    v: u32,
    xnonce: Vec<u8>,
    ct_len: Option<usize>,
}

impl Craft {
    fn new(kid: &str) -> Self {
        Self {
            root: 1,
            site: "blog",
            kid: kid.to_owned(),
            aad_type: ChallengeType::Pow,
            v: 1,
            xnonce: vec![7; 24],
            ct_len: None,
        }
    }

    fn seal(&self, plaintext: &[u8]) -> String {
        let epoch = mg_challenge::parse_epoch_kid(&self.kid).unwrap_or(EPOCH);
        let key = derive_epoch_key(&seal_root(self.root), self.site, epoch);
        let mut nonce = [0u8; 24];
        let n = self.xnonce.len().min(24);
        nonce[..n].copy_from_slice(&self.xnonce[..n]);
        let mut ct = XChaCha20Poly1305::new(&Key::from(key))
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad(HOST, self.aad_type, &self.kid),
                },
            )
            .unwrap();
        if let Some(len) = self.ct_len {
            ct.truncate(len);
        }
        envelope(self.v, &self.kid, self.xnonce.clone(), ct)
    }

    fn seal_claims(&self, claims: &ProtoClaims) -> String {
        self.seal(&claims.encode_to_vec())
    }
}

fn envelope(v: u32, kid: &str, xnonce: Vec<u8>, ct: Vec<u8>) -> String {
    let env = SealedChallenge {
        v,
        kid: kid.to_owned(),
        xnonce,
        ct,
    };
    URL_SAFE_NO_PAD.encode(env.encode_to_vec())
}

fn open(c: &str, now_ms: i64) -> Result<SealedChallengeClaims, OpenError> {
    sealer("blog", &[1]).open(c, HOST, ChallengeType::Pow, now_ms)
}

#[test]
fn seal_open_round_trip() {
    let s = sealer("blog", &[1]);
    let rng = TestRng::new(1);
    let claims = pow_claims(MIDDAY_MS);
    let c = s.seal(&claims, HOST, &rng).unwrap();
    assert!(c.len() <= MAX_C_LEN);
    assert!(
        c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "unpadded base64url"
    );
    for now in [MIDDAY_MS, MIDDAY_MS + 60_000, claims.exp_ms - 1] {
        assert_eq!(
            s.open(&c, HOST, ChallengeType::Pow, now),
            Ok(claims.clone())
        );
    }
    // Invisible challenges seal and open the same way.
    let mut inv = pow_claims(MIDDAY_MS);
    inv.challenge_type = ChallengeType::Invisible;
    let c = s.seal(&inv, HOST, &rng).unwrap();
    assert_eq!(
        s.open(&c, HOST, ChallengeType::Invisible, MIDDAY_MS),
        Ok(inv)
    );
    // A fresh xnonce every time.
    let a = s.seal(&claims, HOST, &rng).unwrap();
    let b = s.seal(&claims, HOST, &rng).unwrap();
    assert_ne!(a, b);
    // The hand-built construction opens too (independent format check).
    let crafted = Craft::new(&claims.kid).seal_claims(&proto_of(&claims));
    assert_eq!(open(&crafted, MIDDAY_MS), Ok(claims));
}

#[test]
fn opened_bindings_match_the_issuing_request() {
    let s = sealer("blog", &[1]);
    let c = s
        .seal(&pow_claims(MIDDAY_MS), HOST, &TestRng::new(2))
        .unwrap();
    let opened = s.open(&c, HOST, ChallengeType::Pow, MIDDAY_MS).unwrap();
    let check = check_challenge_bind(&opened.bind, &common::bindings());
    assert_eq!(
        (check.uah, check.ipp, check.ctp),
        (BindResult::Match, BindResult::Match, None)
    );
    assert!(!check.hard_failure());
}

#[test]
fn any_changed_byte_is_rejected() {
    let s = sealer("blog", &[1]);
    let c = s
        .seal(&pow_claims(MIDDAY_MS), HOST, &TestRng::new(3))
        .unwrap();
    let raw = URL_SAFE_NO_PAD.decode(&c).unwrap();
    for i in 0..raw.len() {
        for bit in [0x01, 0x80] {
            let mut t = raw.clone();
            t[i] ^= bit;
            let tampered = URL_SAFE_NO_PAD.encode(&t);
            assert!(open(&tampered, MIDDAY_MS).is_err(), "byte {i} ^ {bit:#x}");
        }
    }
    // Every character of the text form, and every truncation.
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for i in 0..c.len() {
        let mut t = c.clone().into_bytes();
        t[i] = *alphabet.iter().find(|&&a| a != t[i]).unwrap();
        let t = String::from_utf8(t).unwrap();
        assert!(open(&t, MIDDAY_MS).is_err(), "char {i}");
        assert!(open(&c[..i], MIDDAY_MS).is_err(), "prefix {i}");
    }
    assert!(open(&format!("{c}A"), MIDDAY_MS).is_err());
}

#[test]
fn other_host_type_site_or_time() {
    let s = sealer("blog", &[1]);
    let claims = pow_claims(MIDDAY_MS);
    let c = s.seal(&claims, HOST, &TestRng::new(4)).unwrap();
    let at = MIDDAY_MS + 1;
    assert_eq!(
        s.open(&c, "www.example.com", ChallengeType::Pow, at),
        Err(OpenError::Aead)
    );
    assert_eq!(
        s.open(&c, "Example.com", ChallengeType::Pow, at),
        Err(OpenError::Aead)
    );
    assert_eq!(s.open(&c, "", ChallengeType::Pow, at), Err(OpenError::Aead));
    assert_eq!(
        s.open(&c, HOST, ChallengeType::Invisible, at),
        Err(OpenError::Aead)
    );
    assert_eq!(
        s.open(&c, HOST, ChallengeType::Interactive, at),
        Err(OpenError::Aead)
    );
    // Another site derives another epoch key from the same root.
    assert_eq!(
        sealer("shop", &[1]).open(&c, HOST, ChallengeType::Pow, at),
        Err(OpenError::Aead)
    );
    // Another root.
    assert_eq!(
        sealer("blog", &[9]).open(&c, HOST, ChallengeType::Pow, at),
        Err(OpenError::Aead)
    );
    // Expiry: valid until exp_ms - 1.
    assert!(
        s.open(&c, HOST, ChallengeType::Pow, claims.exp_ms - 1)
            .is_ok()
    );
    let expired = s.open(&c, HOST, ChallengeType::Pow, claims.exp_ms);
    assert_eq!(expired, Err(OpenError::Expired));
    assert_eq!(expired.unwrap_err().reason_code(), "ic.c_expired");
}

#[test]
fn claims_must_match_envelope_and_request() {
    let claims = pow_claims(MIDDAY_MS);
    // Sealed under blog's key but naming another site.
    let mut p = proto_of(&claims);
    p.site = "shop".into();
    assert_eq!(
        open(&Craft::new(&claims.kid).seal_claims(&p), MIDDAY_MS),
        Err(OpenError::Mismatch)
    );
    // Claims kid differs from the envelope kid.
    let mut p = proto_of(&claims);
    p.kid = epoch_kid(EPOCH - 1);
    assert_eq!(
        open(&Craft::new(&claims.kid).seal_claims(&p), MIDDAY_MS),
        Err(OpenError::Mismatch)
    );
    // Claims type differs from the (authenticated) submitted type.
    let mut craft = Craft::new(&claims.kid);
    craft.aad_type = ChallengeType::Invisible;
    let c = craft.seal_claims(&proto_of(&claims));
    assert_eq!(
        sealer("blog", &[1]).open(&c, HOST, ChallengeType::Invisible, MIDDAY_MS),
        Err(OpenError::Mismatch)
    );
}

/// Step 1: size, encoding and envelope checks.
#[test]
fn envelope_checks() {
    let claims = pow_claims(MIDDAY_MS);
    let kid = claims.kid.clone();
    let good = Craft::new(&kid).seal_claims(&proto_of(&claims));
    assert!(open(&good, MIDDAY_MS).is_ok());

    assert_eq!(
        open(&"A".repeat(MAX_C_LEN + 1), MIDDAY_MS),
        Err(OpenError::TooLong)
    );
    assert_eq!(
        open(&format!("{good}="), MIDDAY_MS),
        Err(OpenError::Encoding)
    );
    assert_eq!(open("a+b/", MIDDAY_MS), Err(OpenError::Encoding));
    assert_eq!(open("é", MIDDAY_MS), Err(OpenError::Encoding));
    // Not a protobuf message (field 0 is invalid).
    assert_eq!(open("AAAA", MIDDAY_MS), Err(OpenError::Envelope));
    // Empty input and an empty envelope: v = 0.
    assert_eq!(open("", MIDDAY_MS), Err(OpenError::Envelope));

    let pt = proto_of(&claims).encode_to_vec();
    let mut v2 = Craft::new(&kid);
    v2.v = 2;
    assert_eq!(open(&v2.seal(&pt), MIDDAY_MS), Err(OpenError::Envelope));
    for len in [0, 12, 23, 25, 32] {
        let mut c = Craft::new(&kid);
        c.xnonce = vec![7; len];
        assert_eq!(
            open(&c.seal(&pt), MIDDAY_MS),
            Err(OpenError::Envelope),
            "xnonce of {len} bytes"
        );
    }
    for len in [0, 1, 15] {
        let mut c = Craft::new(&kid);
        c.ct_len = Some(len);
        assert_eq!(
            open(&c.seal(&pt), MIDDAY_MS),
            Err(OpenError::Envelope),
            "ct of {len} bytes"
        );
    }
    // Exactly the tag (an empty plaintext) passes step 1 and fails later.
    let empty = Craft::new(&kid).seal(&[]);
    assert!(matches!(
        open(&empty, MIDDAY_MS),
        Err(OpenError::Claims | OpenError::Mismatch)
    ));
    // A truncated tag of 16+ bytes fails authentication.
    let mut short = Craft::new(&kid);
    short.ct_len = Some(16);
    assert_eq!(open(&short.seal(&pt), MIDDAY_MS), Err(OpenError::Aead));

    // Exactly MAX_C_LEN characters passes the length check (and fails later).
    let at_limit = "A".repeat(MAX_C_LEN);
    assert_ne!(open(&at_limit, MIDDAY_MS), Err(OpenError::TooLong));
}

/// §6.2 step 1, §6.8 "any change to C fails": the envelope must be the one
/// canonical prost encoding `seal` produces. prost itself accepts unknown
/// fields, repeated fields (last one wins) and non-minimal varints, which
/// would give one challenge many spellings; the PoW prefix and (Phase 2) the
/// SDK signature cover the text of `C`, so every accepted `C` is exactly the
/// issued one.
#[test]
fn envelope_is_canonical() {
    let s = sealer("blog", &[1]);
    let c = s
        .seal(&pow_claims(MIDDAY_MS), HOST, &TestRng::new(13))
        .unwrap();
    assert!(open(&c, MIDDAY_MS).is_ok());
    let raw = URL_SAFE_NO_PAD.decode(&c).unwrap();
    let with = |edit: &RawEdit| {
        let mut r = raw.clone();
        edit(&mut r);
        open(&URL_SAFE_NO_PAD.encode(&r), MIDDAY_MS)
    };
    let cases: [(&str, &RawEdit); 5] = [
        ("unknown varint field appended", &|r| {
            r.extend_from_slice(&[0x78, 0x01])
        }),
        ("unknown bytes field appended", &|r| {
            r.extend_from_slice(&[0x2a, 0x02, 0xaa, 0xbb])
        }),
        ("v repeated at the end", &|r| {
            r.extend_from_slice(&[0x08, 0x01])
        }),
        ("unknown field prepended", &|r| {
            r.splice(0..0, [0x78, 0x00]);
        }),
        // v = 1 as a two-byte varint (0x81 0x00) instead of 0x01.
        ("non-minimal varint", &|r| {
            assert_eq!(&r[..2], &[0x08, 0x01]);
            r.splice(0..2, [0x08, 0x81, 0x00]);
        }),
    ];
    for (name, edit) in cases {
        assert_eq!(with(edit), Err(OpenError::Envelope), "{name}");
    }
    // Fields in another order, each exactly once.
    let env = SealedChallenge::decode(raw.as_slice()).unwrap();
    let mut reordered = Vec::new();
    SealedChallenge {
        v: 0,
        kid: String::new(),
        ..env.clone()
    }
    .encode(&mut reordered)
    .unwrap();
    SealedChallenge {
        v: env.v,
        kid: env.kid.clone(),
        xnonce: vec![],
        ct: vec![],
    }
    .encode(&mut reordered)
    .unwrap();
    assert_eq!(
        SealedChallenge::decode(reordered.as_slice()).unwrap(),
        env,
        "prost reads the reordered form as the same envelope"
    );
    assert_eq!(
        open(&URL_SAFE_NO_PAD.encode(&reordered), MIDDAY_MS),
        Err(OpenError::Envelope)
    );
}

/// Step 2: kid syntax and accepted epochs.
#[test]
fn kid_checks() {
    let pt = proto_of(&pow_claims(MIDDAY_MS)).encode_to_vec();
    for kid in ["", "e", "20736", "e020736", "E20736", "e20736x", "k-e20736"] {
        let c = envelope(1, kid, vec![7; 24], vec![0; 64]);
        let r = open(&c, MIDDAY_MS);
        assert_eq!(r, Err(OpenError::Kid), "{kid:?}");
        assert_eq!(r.unwrap_err().reason_code(), "ic.c_kid");
    }
    // A well-formed kid of an epoch that is not accepted.
    for epoch in [EPOCH - 2, EPOCH + 1, EPOCH + 2, 0, u64::MAX] {
        let c = Craft::new(&epoch_kid(epoch)).seal(&pt);
        assert_eq!(open(&c, MIDDAY_MS), Err(OpenError::Kid), "epoch {epoch}");
    }
}

/// Step 4: decoding and every length / presence check.
#[test]
fn claims_shape_checks() {
    let claims = pow_claims(MIDDAY_MS);
    let kid = claims.kid.clone();
    let craft = Craft::new(&kid);
    let seal_with = |mutate: &Mutation| {
        let mut p = proto_of(&claims);
        mutate(&mut p);
        open(&craft.seal_claims(&p), MIDDAY_MS)
    };

    // Undecodable plaintext and values this build does not know.
    assert_eq!(
        open(&craft.seal(&[0xff, 0xff, 0xff]), MIDDAY_MS),
        Err(OpenError::Claims)
    );
    assert_eq!(seal_with(&|p| p.r#type = 99), Err(OpenError::Claims));
    assert_eq!(
        seal_with(&|p| p.risk_band = "extreme".into()),
        Err(OpenError::Claims)
    );
    assert_eq!(
        seal_with(&|p| p.providers = vec!["captcha-farm".into()]),
        Err(OpenError::Claims)
    );

    let shape_cases: [(&str, &Mutation); 13] = [
        ("15-byte nonce", &|p| p.nonce.truncate(15)),
        ("17-byte nonce", &|p| p.nonce.push(0)),
        ("missing pow", &|p| p.pow = None),
        ("difficulty 33", &|p| {
            p.pow.as_mut().unwrap().difficulty = 33
        }),
        ("other pow alg", &|p| {
            p.pow.as_mut().unwrap().alg = "sha1".into()
        }),
        ("15-byte ret", &|p| p.ret.truncate(15)),
        ("empty ret", &|p| p.ret.clear()),
        ("missing bind", &|p| p.bind = None),
        ("missing bind.ipp", &|p| p.bind.as_mut().unwrap().ipp = None),
        ("missing bind.uah", &|p| p.bind.as_mut().unwrap().uah = None),
        ("15-byte bind.ipp", &|p| {
            p.bind.as_mut().unwrap().ipp.as_mut().unwrap().truncate(15)
        }),
        ("empty bind.ipa", &|p| {
            p.bind.as_mut().unwrap().ipa = Some(vec![])
        }),
        ("32-byte bind.ctp", &|p| {
            p.bind.as_mut().unwrap().ctp = Some(vec![1; 32])
        }),
    ];
    for (name, mutate) in shape_cases {
        let r = seal_with(mutate);
        assert_eq!(r, Err(OpenError::Shape), "{name}");
        assert_eq!(r.unwrap_err().reason_code(), "ic.c_invalid", "{name}");
    }
    // Difficulty 32 is the protocol maximum and still opens.
    assert!(seal_with(&|p| p.pow.as_mut().unwrap().difficulty = 32).is_ok());
    // Optional bindings present with 16 bytes are fine.
    assert!(seal_with(&|p| p.bind.as_mut().unwrap().ctp = Some(vec![1; 16])).is_ok());
}

/// Step 5: `SealedChallengeClaims::check`.
#[test]
fn claims_structure_checks() {
    let claims = pow_claims(MIDDAY_MS);
    let craft = Craft::new(&claims.kid);
    let seal_with = |mutate: &Mutation| {
        let mut p = proto_of(&claims);
        mutate(&mut p);
        open(&craft.seal_claims(&p), MIDDAY_MS)
    };
    let cases: [(ClaimsError, &Mutation); 6] = [
        (ClaimsError::UnsupportedVersion(2), &|p| p.v = 2),
        (ClaimsError::InvalidRouteClass, &|p| {
            p.route_class = "Login".into()
        }),
        (ClaimsError::InvalidAttempt, &|p| p.attempt_no = 1),
        (ClaimsError::InvalidProviders, &|p| {
            p.providers = vec!["self_hold".into()]
        }),
        (ClaimsError::InvalidLifetime, &|p| p.exp = p.iat + 120_001),
        (ClaimsError::NotYetValid, &|p| {
            p.iat = MIDDAY_MS + 5_001;
            p.exp = p.iat + 60_000;
        }),
    ];
    for (want, mutate) in cases {
        let r = seal_with(mutate);
        assert_eq!(r, Err(OpenError::Invalid(want.clone())), "{want:?}");
        assert_eq!(r.unwrap_err().reason_code(), "ic.c_invalid");
    }
    // Clock skew: iat up to 5 s ahead is accepted.
    assert!(
        seal_with(&|p| {
            p.iat = MIDDAY_MS + 5_000;
            p.exp = p.iat + 60_000;
        })
        .is_ok()
    );
}

/// §6.1 / §6.8: `e − 1` opens up to 125 s after the day boundary and not
/// from 125.001 s; `e − 2` never; `e + 1` only in the last 5 s of the day.
#[test]
fn epoch_boundaries() {
    let s = sealer("blog", &[1]);
    let open_at = |c: &str, now| s.open(c, HOST, ChallengeType::Pow, now);

    // Claims of the previous epoch's kid that are still live at `now`
    // (built by hand: seal() insists on kid = epoch of iat).
    let prev_kid_live_at = |now: i64| {
        let mut claims = pow_claims(now - 1_000);
        claims.kid = epoch_kid(EPOCH - 1);
        Craft::new(&claims.kid).seal_claims(&proto_of(&claims))
    };
    let at = DAY_START_MS + 125_000;
    assert!(open_at(&prev_kid_live_at(at), at).is_ok());
    let at = DAY_START_MS + 125_001;
    assert_eq!(open_at(&prev_kid_live_at(at), at), Err(OpenError::Kid));

    // The natural case: sealed a second before midnight, opened after it.
    let late = pow_claims(DAY_START_MS - 1_000);
    assert_eq!(epoch_no(late.iat_ms), EPOCH - 1);
    let c = s.seal(&late, HOST, &TestRng::new(5)).unwrap();
    assert!(open_at(&c, DAY_START_MS + 118_999).is_ok());
    assert_eq!(open_at(&c, DAY_START_MS + 119_000), Err(OpenError::Expired));

    // e − 2 never opens, whatever its claims say.
    for now in [
        DAY_START_MS,
        DAY_START_MS + 1,
        DAY_START_MS + 60_000,
        MIDDAY_MS,
    ] {
        let mut claims = pow_claims(now);
        claims.kid = epoch_kid(epoch_no(now) - 2);
        let c = Craft::new(&claims.kid).seal_claims(&proto_of(&claims));
        assert_eq!(open_at(&c, now), Err(OpenError::Kid), "now {now}");
    }

    // e + 1: an Edge whose clock already passed midnight seals at exactly
    // DAY_START_MS; an Edge still in the previous day opens it only in the
    // last 5 s of that day.
    let early = pow_claims(DAY_START_MS);
    assert_eq!(epoch_no(early.iat_ms), EPOCH);
    let c = s.seal(&early, HOST, &TestRng::new(6)).unwrap();
    assert!(open_at(&c, DAY_START_MS - 5_000).is_ok());
    assert!(open_at(&c, DAY_START_MS - 1).is_ok());
    assert_eq!(open_at(&c, DAY_START_MS - 5_001), Err(OpenError::Kid));
    assert_eq!(open_at(&c, DAY_START_MS - 43_200_000), Err(OpenError::Kid));
}

/// Two Edges with the same root open each other's challenges.
#[test]
fn two_edges_share_a_root() {
    let a = sealer("blog", &[1]);
    let b = sealer("blog", &[1]);
    let claims = pow_claims(MIDDAY_MS);
    let from_a = a.seal(&claims, HOST, &TestRng::new(7)).unwrap();
    let from_b = b.seal(&claims, HOST, &TestRng::new(8)).unwrap();
    assert_eq!(
        b.open(&from_a, HOST, ChallengeType::Pow, MIDDAY_MS),
        Ok(claims.clone())
    );
    assert_eq!(
        a.open(&from_b, HOST, ChallengeType::Pow, MIDDAY_MS),
        Ok(claims)
    );
}

/// D-30 rotation: add (new second), promote (new first), retire (old gone).
#[test]
fn root_rotation() {
    let (old, new) = (1u8, 2u8);
    let claims = pow_claims(MIDDAY_MS);
    let rng = TestRng::new(9);
    let by_old = sealer("blog", &[old]).seal(&claims, HOST, &rng).unwrap();
    let by_new_old = sealer("blog", &[new, old])
        .seal(&claims, HOST, &rng)
        .unwrap();
    let by_old_new = sealer("blog", &[old, new])
        .seal(&claims, HOST, &rng)
        .unwrap();

    for (name, opener) in [
        ("[new, old]", sealer("blog", &[new, old])),
        ("[old, new]", sealer("blog", &[old, new])),
    ] {
        assert!(
            opener
                .open(&by_old, HOST, ChallengeType::Pow, MIDDAY_MS)
                .is_ok(),
            "[old] sealed, {name} opens"
        );
    }
    assert!(
        sealer("blog", &[old, new])
            .open(&by_new_old, HOST, ChallengeType::Pow, MIDDAY_MS)
            .is_ok(),
        "[new, old] sealed, [old, new] opens"
    );
    // roots[0] seals: [old, new] seals with old, so [old] alone opens it...
    assert!(
        sealer("blog", &[old])
            .open(&by_old_new, HOST, ChallengeType::Pow, MIDDAY_MS)
            .is_ok()
    );
    // ...but an Edge that never added the new root cannot open [new, old]'s.
    assert_eq!(
        sealer("blog", &[old]).open(&by_new_old, HOST, ChallengeType::Pow, MIDDAY_MS),
        Err(OpenError::Aead)
    );
}

/// The Edge keeps one `Sealer` and `TokenKeySet` per site in a shared site
/// runtime (`ArcSwap<SiteRuntime>`, spec §9.10) used by every worker thread.
#[test]
fn edge_held_types_are_send_and_sync() {
    fn shared<T: Send + Sync + 'static>() {}
    shared::<mg_challenge::Sealer>();
    shared::<mg_challenge::SealKeys>();
    shared::<mg_challenge::SealRoot>();
    shared::<mg_challenge::TokenKeySet>();
    shared::<mg_challenge::ClearanceClaims>();
    shared::<mg_challenge::OpenError>();
    shared::<mg_challenge::TokenError>();
    // A sealer used from several threads at once keeps working.
    let s = std::sync::Arc::new(sealer("blog", &[1, 2]));
    let c = s
        .seal(&pow_claims(MIDDAY_MS), HOST, &TestRng::new(14))
        .unwrap();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            let (s, c) = (&s, &c);
            scope.spawn(move || {
                for _ in 0..50 {
                    assert!(s.open(c, HOST, ChallengeType::Pow, MIDDAY_MS).is_ok());
                }
            });
        }
    });
}

#[test]
fn rng_failure_is_an_error() {
    let s = sealer("blog", &[1]);
    assert_eq!(
        s.seal(&pow_claims(MIDDAY_MS), HOST, &FailingRng),
        Err(SealError::Rng)
    );
    assert!(random_nonce(&FailingRng).is_err());
    let a = random_nonce(&TestRng::new(10)).unwrap();
    let b = random_nonce(&TestRng::new(11)).unwrap();
    assert_ne!(a, b);
}

#[test]
fn seal_rejects_malformed_claims() {
    let s = sealer("blog", &[1]);
    let rng = TestRng::new(12);
    // kid must be the epoch of iat.
    let mut c = pow_claims(MIDDAY_MS);
    c.kid = epoch_kid(EPOCH + 1);
    assert_eq!(s.seal(&c, HOST, &rng), Err(SealError::Kid));
    // No challenge without the ipp binding (unknown client IP, D-23).
    let mut c = pow_claims(MIDDAY_MS);
    c.bind.ipp = None;
    assert_eq!(s.seal(&c, HOST, &rng), Err(SealError::Shape));
    // Structural checks run at iat.
    let mut c = pow_claims(MIDDAY_MS);
    c.bind.uah = None;
    assert_eq!(
        s.seal(&c, HOST, &rng),
        Err(SealError::Invalid(ClaimsError::MissingUahBinding))
    );
    // Claims of another site.
    let mut c = pow_claims(MIDDAY_MS);
    c.site = "shop".into();
    assert_eq!(s.seal(&c, HOST, &rng), Err(SealError::Shape));
    // Nothing lives longer than the epoch window allows, not even a
    // (Phase 2) interactive challenge whose own limit is 10 minutes.
    let mut c = pow_claims(MIDDAY_MS);
    c.challenge_type = ChallengeType::Interactive;
    c.providers = vec![mg_core::challenge::ProviderId::SelfHold];
    c.attempt_no = 1;
    c.exp_ms = c.iat_ms + 600_000;
    assert_eq!(
        s.seal(&c, HOST, &rng),
        Err(SealError::Invalid(ClaimsError::InvalidLifetime))
    );
    c.exp_ms = c.iat_ms + 120_000;
    let sealed = s.seal(&c, HOST, &rng).unwrap();
    assert_eq!(
        s.open(&sealed, HOST, ChallengeType::Interactive, MIDDAY_MS),
        Ok(c)
    );
}
