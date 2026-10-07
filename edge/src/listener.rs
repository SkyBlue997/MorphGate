//! Listeners (docs/impl/phase1-spec.md §9.2): what each `[[listeners]]`
//! entry means at request time, and the optional Cloudflare IP filter of
//! `origin_mtls` listeners.

use crate::config::{ListenerAuth, ListenerConfig, ListenerProfile};
use crate::creds::UpstreamKeys;
use crate::metrics::metrics;
use crate::sites::Sites;
use async_trait::async_trait;
use pingora::listeners::ConnectionFilter;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

/// One listener as the proxy sees it.
pub struct ListenerRuntime {
    pub name: String,
    pub bind: SocketAddr,
    pub profile: ListenerProfile,
    pub auth: ListenerAuth,
    /// `upstream_keys` (cloudflare only): every request needs a matching
    /// `x-mg-upstream-key`.
    pub upstream_keys: Option<UpstreamKeys>,
}

impl fmt::Debug for ListenerRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerRuntime")
            .field("name", &self.name)
            .field("bind", &self.bind)
            .field("profile", &self.profile)
            .field("auth", &self.auth)
            .field("upstream_keys", &self.upstream_keys.is_some())
            .finish()
    }
}

impl ListenerRuntime {
    pub fn new(cfg: &ListenerConfig, upstream_keys: Option<UpstreamKeys>) -> Self {
        Self {
            name: cfg.name.clone(),
            bind: cfg.bind,
            profile: cfg.profile,
            auth: cfg.auth(),
            upstream_keys,
        }
    }

    /// The §9.2 transport check for a TCP peer: a `cloudflare` + `loopback`
    /// listener only accepts loopback peers (cloudflared on this host).
    /// `origin_mtls` peers were authenticated by the TLS handshake.
    pub fn peer_allowed(&self, peer: Option<IpAddr>) -> bool {
        match self.auth {
            ListenerAuth::Loopback => peer.is_some_and(|ip| ip.to_canonical().is_loopback()),
            ListenerAuth::OriginMtls | ListenerAuth::None => true,
        }
    }

    /// Counts `mg_upstream_auth_failures_total{listener, profile, reason}`.
    pub fn auth_failure(&self, reason: &str) {
        metrics()
            .upstream_auth_failures
            .with_label_values(&[self.name.as_str(), self.profile.as_str(), reason])
            .inc();
    }
}

/// `cloudflare_ip_filter` (§9.2): drops TCP peers outside the union of every
/// site's current `cloudflare-ips` artifact before the TLS handshake. While
/// no site has the artifact the filter accepts everything and
/// `mg_cf_ip_filter_active{listener}` is 0 (the mTLS handshake still
/// authenticates every connection). The gauge is set when the filter is
/// built (from the start-up runtimes) and on every connection it checks.
pub struct CloudflareIpFilter {
    listener: String,
    sites: Arc<Sites>,
}

impl fmt::Debug for CloudflareIpFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflareIpFilter")
            .field("listener", &self.listener)
            .finish_non_exhaustive()
    }
}

impl CloudflareIpFilter {
    pub fn new(listener: &str, sites: Arc<Sites>) -> Self {
        let filter = Self {
            listener: listener.to_owned(),
            sites,
        };
        filter.lookup(None);
        filter
    }

    /// Whether a TCP peer may proceed to the TLS handshake (`None`: not an
    /// IP peer, never inside the ranges).
    pub fn accepts(&self, ip: Option<IpAddr>) -> bool {
        let (any_ranges, inside) = self.lookup(ip);
        !any_ranges || inside
    }

    /// `(any site has ranges, ip is inside one of them)`; publishes the
    /// `mg_cf_ip_filter_active` gauge.
    fn lookup(&self, ip: Option<IpAddr>) -> (bool, bool) {
        let mut any_ranges = false;
        let mut inside = false;
        for site in self.sites.iter() {
            let rt = site.runtime();
            if let Some(set) = rt
                .bundle
                .as_ref()
                .and_then(|b| b.intel.cloudflare_ips.as_ref())
            {
                any_ranges = true;
                if ip.is_some_and(|ip| set.contains(ip)) {
                    inside = true;
                    break;
                }
            }
        }
        metrics()
            .cf_ip_filter_active
            .with_label_values(&[self.listener.as_str()])
            .set(i64::from(any_ranges));
        (any_ranges, inside)
    }
}

#[async_trait]
impl ConnectionFilter for CloudflareIpFilter {
    async fn should_accept(&self, addr: Option<&SocketAddr>) -> bool {
        self.accepts(addr.map(SocketAddr::ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EdgeConfig;

    fn listener(auth: &str) -> ListenerRuntime {
        let text = crate::config::tests_support::minimal_with_listener(auth);
        let cfg = EdgeConfig::from_toml_str(&text).unwrap();
        ListenerRuntime::new(&cfg.listeners[0], None)
    }

    #[test]
    fn loopback_listeners_accept_only_loopback_peers() {
        let l = listener("loopback");
        assert!(l.peer_allowed(Some("127.0.0.1".parse().unwrap())));
        assert!(l.peer_allowed(Some("::1".parse().unwrap())));
        assert!(l.peer_allowed(Some("::ffff:127.0.0.1".parse().unwrap())));
        assert!(!l.peer_allowed(Some("10.0.0.1".parse().unwrap())));
        assert!(!l.peer_allowed(Some("::ffff:10.0.0.1".parse().unwrap())));
        assert!(
            !l.peer_allowed(None),
            "a unix socket peer is not loopback TCP"
        );
        let m = listener("origin_mtls");
        assert!(m.peer_allowed(Some("203.0.113.1".parse().unwrap())));
        assert!(!format!("{m:?}").contains("Some("));
    }

    #[test]
    fn ip_filter_without_ranges_accepts_everything() {
        let f = CloudflareIpFilter::new("aop", Arc::new(Sites::default()));
        assert!(f.accepts(Some("203.0.113.1".parse().unwrap())));
        assert!(f.accepts(None));
    }
}
