//! Strict JSON helpers.
//!
//! serde's derived `Deserialize` for a struct also accepts the struct
//! written as a JSON array of its field values (`["blog-t-20260927"]` for
//! `{"kid": …}`). Every JSON format of this crate (key files, token claims,
//! token footers) is an object with named fields, so parsers wrap their
//! structs in [`ObjectOnly`], which accepts a JSON object and nothing else.
//! Parsing stays single-pass, so error positions are kept.

use serde::de::value::MapAccessDeserializer;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use std::fmt;
use std::marker::PhantomData;

/// `T`, deserialized only from a JSON object.
pub(crate) struct ObjectOnly<T>(pub(crate) T);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for ObjectOnly<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ObjectVisitor<T>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>> Visitor<'de> for ObjectVisitor<T> {
            type Value = T;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<T, A::Error> {
                T::deserialize(MapAccessDeserializer::new(map))
            }
        }

        deserializer
            .deserialize_map(ObjectVisitor(PhantomData))
            .map(ObjectOnly)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Kid {
        kid: String,
    }

    #[test]
    fn objects_only() {
        let ok: ObjectOnly<Kid> = serde_json::from_str(r#"{"kid":"a"}"#).unwrap();
        assert_eq!(ok.0, Kid { kid: "a".into() });
        // Plain derive accepts the array form; the wrapper does not.
        assert!(serde_json::from_str::<Kid>(r#"["a"]"#).is_ok());
        for bad in [
            r#"["a"]"#,
            "null",
            "1",
            r#""a""#,
            r#"{"kid":"a","x":1}"#,
            "{}",
        ] {
            assert!(
                serde_json::from_str::<ObjectOnly<Kid>>(bad).is_err(),
                "{bad}"
            );
        }
        // Duplicate keys are still rejected.
        assert!(serde_json::from_str::<ObjectOnly<Kid>>(r#"{"kid":"a","kid":"b"}"#).is_err());
        // Error positions survive.
        let err = serde_json::from_str::<ObjectOnly<Kid>>("\n\n  [1]")
            .err()
            .unwrap();
        assert_eq!(err.line(), 3);
    }
}
