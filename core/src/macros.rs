//! Declarative helpers for closed, wire-stable enums.
//!
//! Every variant carries its snake_case wire name exactly once; serde, `Display`,
//! `FromStr` and `as_str` are all derived from it so they cannot drift apart.

/// A closed enum whose variants have a stable snake_case wire name.
///
/// Generates: the enum (with `serde(rename = ...)` per variant), `ALL`,
/// `as_str`, `Display` and `FromStr` (error: [`crate::enums::UnknownVariant`]).
macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $wire:literal ),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord,
            serde::Serialize, serde::Deserialize,
        )]
        $vis enum $name {
            $( $(#[$vmeta])* #[serde(rename = $wire)] $variant ),+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The snake_case wire name (identical to the serde representation).
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(self.as_str())
            }
        }

        impl core::str::FromStr for $name {
            type Err = $crate::enums::UnknownVariant;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                match s {
                    $($wire => Ok(Self::$variant),)+
                    _ => Err($crate::enums::UnknownVariant {
                        type_name: stringify!($name),
                        value: s.into(),
                    }),
                }
            }
        }
    };
}

/// Like [`wire_enum!`], for enums that mirror a `morphgate.v1` protobuf enum.
///
/// Each variant also carries its protobuf number; `$prefix` is the protobuf
/// value prefix (`CHANNEL` for `CHANNEL_WEB`). The generated `proto_name`
/// returns the full protobuf value name, which `mg-proto`'s contract test
/// compares against the generated code.
macro_rules! proto_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident : $prefix:literal {
            $( $(#[$vmeta:meta])* $variant:ident = $num:literal => $wire:literal ),+ $(,)?
        }
    ) => {
        wire_enum! {
            $(#[$meta])*
            #[derive(Default)]
            $vis enum $name {
                $( $(#[$vmeta])* $variant => $wire ),+
            }
        }

        impl $name {
            /// Prefix of the protobuf value names, e.g. `CHANNEL`.
            pub const PROTO_PREFIX: &'static str = $prefix;

            /// The protobuf enum number.
            pub const fn to_proto(self) -> i32 {
                match self { $(Self::$variant => $num),+ }
            }

            /// Maps a protobuf enum number back; `None` for numbers this build does not know.
            pub const fn from_proto(value: i32) -> Option<Self> {
                match value {
                    $($num => Some(Self::$variant),)+
                    _ => None,
                }
            }

            /// The protobuf value name, e.g. `CHANNEL_WEB`.
            pub fn proto_name(self) -> String {
                format!("{}_{}", Self::PROTO_PREFIX, self.as_str().to_ascii_uppercase())
            }
        }
    };
}
