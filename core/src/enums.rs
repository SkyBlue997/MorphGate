//! Enums shared with `proto/morphgate/v1/common.proto`.
//!
//! Numbers and names match the protobuf definitions exactly (checked by the
//! contract test in `mg-proto`). The JSON form is the lower-case value name
//! without its prefix: `UPSTREAM_PROFILE_KIND_DIRECT_TLS` <-> `"direct_tls"`.

use std::fmt;

/// Error returned by `FromStr` for a string that names no variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownVariant {
    /// Name of the enum type that rejected the value.
    pub type_name: &'static str,
    /// The rejected input.
    pub value: String,
}

impl fmt::Display for UnknownVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown {} value {:?}", self.type_name, self.value)
    }
}

impl std::error::Error for UnknownVariant {}

proto_enum! {
    /// Traffic channel of a route.
    pub enum Channel: "CHANNEL" {
        #[default]
        Unspecified = 0 => "unspecified",
        Web = 1 => "web",
        Api = 2 => "api",
        Mobile = 3 => "mobile",
    }
}

proto_enum! {
    /// What sits between the visitor and the Edge (docs/08). Determines how the
    /// upstream is authenticated, which headers are trusted and which signal
    /// families can be expected. Phase 1 implements `Cloudflare` and `DirectTls`.
    pub enum UpstreamProfileKind: "UPSTREAM_PROFILE_KIND" {
        #[default]
        Unspecified = 0 => "unspecified",
        /// The Edge terminates the visitor's TLS itself.
        DirectTls = 1 => "direct_tls",
        /// Behind Cloudflare (Tunnel or Authenticated Origin Pulls).
        Cloudflare = 2 => "cloudflare",
        /// Behind an L4 load balancer that sends PROXY protocol v1/v2.
        ProxyProtocol = 3 => "proxy_protocol",
        Cloudfront = 4 => "cloudfront",
        GcpAlb = 5 => "gcp_alb",
        Esa = 6 => "esa",
        Edgeone = 7 => "edgeone",
        Alicdn = 8 => "alicdn",
        TencentCdn = 9 => "tencent_cdn",
        Envoy = 10 => "envoy",
        Openresty = 11 => "openresty",
    }
}

proto_enum! {
    /// Provenance of a signal or of a protocol-layer value such as JA4.
    ///
    /// Values computed by the Edge itself outrank the same value forwarded by
    /// a CDN, and a CDN-forwarded value only counts when the upstream was
    /// authenticated (`UpstreamInfo::authenticated`).
    pub enum SignalSource: "SIGNAL_SOURCE" {
        #[default]
        Unspecified = 0 => "unspecified",
        /// Computed by the MorphGate Edge (`SIGNAL_SOURCE_SELF`).
        SelfComputed = 1 => "self",
        Cloudflare = 2 => "cloudflare",
        Cloudfront = 3 => "cloudfront",
        GcpAlb = 4 => "gcp_alb",
        Esa = 5 => "esa",
        Envoy = 6 => "envoy",
        Openresty = 7 => "openresty",
        Sdk = 8 => "sdk",
    }
}

proto_enum! {
    /// Evidence state of a signal (docs/03 §3.1). Only `Present` signals carry
    /// evidence; neither state of "no value" is ever human evidence.
    pub enum SignalState: "SIGNAL_STATE" {
        #[default]
        Unspecified = 0 => "unspecified",
        /// The detector had its input and produced a result.
        Present = 1 => "present",
        /// The profile can supply the input but this request lacks it (e.g. no
        /// SDK telemetry yet, no token). Value 0; counted in the confidence
        /// denominator but not the numerator, so confidence drops.
        Absent = 2 => "absent",
        /// The profile cannot supply the input (outside its expected set, e.g.
        /// JA4 behind Cloudflare), or an upstream-injected header did not arrive
        /// or has no confirmed source. Not counted at all; a missing Tier 0
        /// header additionally raises a configuration alarm.
        Missing = 3 => "missing",
    }
}

impl SignalState {
    /// Whether the signal counts toward confidence coverage (`Present` and `Absent`).
    pub const fn counts_toward_coverage(self) -> bool {
        matches!(self, Self::Present | Self::Absent)
    }
}

proto_enum! {
    /// Signal family. Scoring caps the contribution of each family so that
    /// correlated signals are not counted twice (docs/03 §4.1).
    ///
    /// The numeric value doubles as the bit index in [`crate::FamilyMask`].
    pub enum SignalFamily: "SIGNAL_FAMILY" {
        #[default]
        Unspecified = 0 => "unspecified",
        Network = 1 => "network",
        Tls = 2 => "tls",
        Http = 3 => "http",
        Client = 4 => "client",
        Behavior = 5 => "behavior",
        Reputation = 6 => "reputation",
        Rate = 7 => "rate",
        Identity = 8 => "identity",
        /// Coarse TLS profile forwarded by a CDN (`x-mg-cf-tls-*`). Weak, capped low, shadow first.
        EdgeTls = 9 => "edge_tls",
        /// Upstream verdicts (e.g. Cloudflare verified-bot flag), corroboration only.
        External = 10 => "external",
    }
}

proto_enum! {
    /// Request classification (docs/03 §2).
    pub enum BotClass: "BOT_CLASS" {
        #[default]
        Unspecified = 0 => "unspecified",
        AuthorizedAgent = 1 => "authorized_agent",
        VerifiedCrawler = 2 => "verified_crawler",
        ApiPartner = 3 => "api_partner",
        SignedAgent = 4 => "signed_agent",
        DeclaredAgent = 5 => "declared_agent",
        Impersonator = 6 => "impersonator",
        Scanner = 7 => "scanner",
        AutomationLikely = 8 => "automation_likely",
        HumanLikely = 9 => "human_likely",
        Unknown = 10 => "unknown",
    }
}

proto_enum! {
    /// Enforcement action (docs/03 §5.2).
    pub enum Action: "ACTION" {
        #[default]
        Unspecified = 0 => "unspecified",
        Allow = 1 => "allow",
        Log = 2 => "log",
        Tag = 3 => "tag",
        RateLimit = 4 => "rate_limit",
        Challenge = 5 => "challenge",
        Tarpit = 6 => "tarpit",
        Block = 7 => "block",
    }
}

impl Action {
    /// Whether the visitor's request is served by the origin under this action
    /// (as opposed to being answered or delayed by the Edge).
    pub const fn reaches_origin(self) -> bool {
        matches!(self, Self::Allow | Self::Log | Self::Tag)
    }
}

proto_enum! {
    /// Challenge type (docs/04 §2).
    pub enum ChallengeType: "CHALLENGE_TYPE" {
        #[default]
        Unspecified = 0 => "unspecified",
        Invisible = 1 => "invisible",
        Pow = 2 => "pow",
        Interactive = 3 => "interactive",
        Attestation = 4 => "attestation",
        StepUp = 5 => "step_up",
    }
}

proto_enum! {
    /// Kind of entity an [`crate::EntityVerdict`] is about.
    pub enum EntityType: "ENTITY_TYPE" {
        #[default]
        Unspecified = 0 => "unspecified",
        Ip = 1 => "ip",
        Prefix = 2 => "prefix",
        Asn = 3 => "asn",
        Session = 4 => "session",
        Device = 5 => "device",
        Account = 6 => "account",
        FpCluster = 7 => "fp_cluster",
        Agent = 8 => "agent",
    }
}

proto_enum! {
    /// Route sensitivity; `Critical` covers login / sign-up / payment / SMS.
    pub enum RouteSensitivity: "ROUTE_SENSITIVITY" {
        #[default]
        Unspecified = 0 => "unspecified",
        Low = 1 => "low",
        Medium = 2 => "medium",
        High = 3 => "high",
        Critical = 4 => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    /// Every variant: serde name == as_str, FromStr inverts it, proto number round-trips.
    macro_rules! check_enum {
        ($ty:ty) => {{
            for &v in <$ty>::ALL {
                let json = serde_json::to_string(&v).unwrap();
                assert_eq!(json, format!("\"{}\"", v.as_str()), "{v:?}");
                assert_eq!(serde_json::from_str::<$ty>(&json).unwrap(), v);
                assert_eq!(<$ty>::from_str(v.as_str()).unwrap(), v);
                assert_eq!(<$ty>::from_proto(v.to_proto()), Some(v));
            }
            assert_eq!(
                <$ty>::default().to_proto(),
                0,
                "default must be the zero value"
            );
            assert!(<$ty>::from_proto(-1).is_none());
            assert!(<$ty>::from_str("NOT_A_VARIANT").is_err());
        }};
    }

    #[test]
    fn enums_are_consistent() {
        check_enum!(Channel);
        check_enum!(UpstreamProfileKind);
        check_enum!(SignalSource);
        check_enum!(SignalState);
        check_enum!(SignalFamily);
        check_enum!(BotClass);
        check_enum!(Action);
        check_enum!(ChallengeType);
        check_enum!(EntityType);
        check_enum!(RouteSensitivity);
    }

    #[test]
    fn proto_names_follow_buf_style() {
        assert_eq!(Channel::Web.proto_name(), "CHANNEL_WEB");
        assert_eq!(
            UpstreamProfileKind::DirectTls.proto_name(),
            "UPSTREAM_PROFILE_KIND_DIRECT_TLS"
        );
        assert_eq!(
            SignalSource::SelfComputed.proto_name(),
            "SIGNAL_SOURCE_SELF"
        );
        assert_eq!(SignalFamily::EdgeTls.proto_name(), "SIGNAL_FAMILY_EDGE_TLS");
        assert_eq!(SignalState::Missing.proto_name(), "SIGNAL_STATE_MISSING");
    }

    #[test]
    fn only_present_and_absent_count_toward_coverage() {
        let counted: Vec<_> = SignalState::ALL
            .iter()
            .copied()
            .filter(|s| s.counts_toward_coverage())
            .collect();
        assert_eq!(counted, [SignalState::Present, SignalState::Absent]);
    }

    #[test]
    fn unknown_variant_error_names_the_type() {
        let err = UpstreamProfileKind::from_str("akamai").unwrap_err();
        assert_eq!(
            err.to_string(),
            "unknown UpstreamProfileKind value \"akamai\""
        );
        assert!(serde_json::from_str::<UpstreamProfileKind>("\"akamai\"").is_err());
    }

    #[test]
    fn only_pass_through_actions_reach_origin() {
        let reaching: Vec<_> = Action::ALL
            .iter()
            .copied()
            .filter(|a| a.reaches_origin())
            .collect();
        assert_eq!(reaching, [Action::Allow, Action::Log, Action::Tag]);
    }
}
