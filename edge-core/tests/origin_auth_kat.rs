//! `kat.json` `origin_auth` (spec I-38): the Edge's signing input and header
//! value for fixed requests, with the key of `keys/origin-keys.json`. The
//! JavaScript reference check (`adapters/origin`) reads the same vectors.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mg_edge_core::origin_auth::{VerifyError, message, sign, timestamp, verify};
use serde_json::Value;

fn read(rel: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../testdata/phase1")
        .join(rel);
    serde_json::from_slice(&std::fs::read(&p).unwrap()).unwrap()
}

#[test]
fn origin_auth_known_answers() {
    let kat = read("kat.json")["origin_auth"].clone();
    let file = read(kat["key_file"].as_str().unwrap());
    assert_eq!(file["kind"], "mg-origin-keys");
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(file["values"][0].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let cases = kat["cases"].as_array().unwrap();
    assert!(cases.len() >= 2);
    for case in cases {
        let t = case["t"].as_u64().unwrap();
        let headers = case["headers"].as_object().unwrap();
        let msg = message(
            t,
            case["method"].as_str().unwrap(),
            case["target"].as_str().unwrap().as_bytes(),
            |name| headers.get(name).and_then(Value::as_str),
        );
        assert_eq!(std::str::from_utf8(&msg).unwrap(), case["message"]);
        let value = sign(&key, t, &msg);
        assert_eq!(value, case["header"].as_str().unwrap());
        assert_eq!(timestamp(&value), Ok(t));
        assert_eq!(verify(&[key], &value, &msg, t + 30), Ok(()));
        assert_eq!(
            verify(&[[0; 32]], &value, &msg, t),
            Err(VerifyError::BadSignature)
        );
    }
}
