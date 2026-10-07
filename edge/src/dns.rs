//! DNS for crawler verification (docs/impl/phase1-spec.md §9.6, §7.4, I-17;
//! WP-E1b): `mg_intel::DnsResolver` over hickory's tokio resolver with the
//! system configuration (`/etc/resolv.conf`), or the static resolver of
//! `[intel] dns_resolver = "static:<path>"` (tests, the Validation Lab).
//!
//! * One attempt per query (`ResolverOpts { timeout: dns_timeout_ms,
//!   attempts: 1 }`), and every `reverse` / `forward` call is wrapped in
//!   `tokio::time::timeout(dns_timeout_ms)` as well (→ `DnsError::Timeout`).
//! * `/etc/hosts` is never consulted: a local hosts entry must not verify a
//!   crawler. Forward lookups use the `Ipv6AndIpv4` default (A and AAAA).
//! * Error mapping: `NoRecordsFound` with `NXDOMAIN` or `NOERROR` →
//!   `NoRecords`; any other `NoRecordsFound`, `ResponseCode(_)` (SERVFAIL,
//!   REFUSED, ...) and every other error → `Server`, never `NoRecords`
//!   (a transient failure would otherwise be cached as a verification
//!   failure for an hour).
//! * `DnsError::Server` carries a fixed text (the response code number at
//!   most): hickory's `Display` contains the query name, and a PTR name
//!   spells out the client IP (D-31).
//!
//! The resolver must be built on the runtime that uses it (the `mg-rdns`
//! background service, §9.1.1).

use crate::config::{DnsResolverConfig, IntelConfig};
use hickory_resolver::config::{LookupIpStrategy, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError as HickoryDnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{ResolverBuilder, TokioResolver};
use mg_core::BoxFuture;
use mg_intel::{DnsError, DnsResolver, StaticResolver};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// The whole-job deadline of one rDNS verification: one PTR query plus the
/// forward queries, `2 × dns_timeout_ms + 1 s` (§7.3, §9.6).
pub fn job_deadline(dns_timeout_ms: u64) -> Duration {
    Duration::from_millis(dns_timeout_ms.saturating_mul(2).saturating_add(1_000))
}

/// Maps a hickory error (see the module documentation). The result never
/// contains the queried name or address.
pub fn map_error(e: &NetError) -> DnsError {
    match e {
        NetError::Timeout => DnsError::Timeout,
        NetError::Dns(HickoryDnsError::NoRecordsFound(n))
            if matches!(
                n.response_code,
                ResponseCode::NXDomain | ResponseCode::NoError
            ) =>
        {
            DnsError::NoRecords
        }
        NetError::Dns(HickoryDnsError::NoRecordsFound(n)) => {
            DnsError::Server(format!("no records, rcode {}", u16::from(n.response_code)))
        }
        NetError::Dns(HickoryDnsError::ResponseCode(code)) => {
            DnsError::Server(format!("rcode {}", u16::from(*code)))
        }
        _ => DnsError::Server("resolver error".into()),
    }
}

/// `DnsResolver` over hickory with the system configuration.
pub struct HickoryResolver {
    inner: TokioResolver,
    timeout: Duration,
}

impl fmt::Debug for HickoryResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HickoryResolver")
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

impl HickoryResolver {
    /// Reads the system configuration; must run on the runtime that will
    /// use the resolver.
    pub fn from_system(timeout: Duration) -> Result<Self, String> {
        let builder =
            TokioResolver::builder_tokio().map_err(|e| format!("system DNS configuration: {e}"))?;
        Self::build(builder, timeout)
    }

    /// With explicit name servers (tests: a loopback fake server).
    pub fn with_config(config: ResolverConfig, timeout: Duration) -> Result<Self, String> {
        Self::build(
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default()),
            timeout,
        )
    }

    /// One attempt per query, `timeout` per query, never `/etc/hosts`, and
    /// forward lookups for AAAA and A together (§9.6; hickory 0.26's
    /// default, pinned so a crawler on IPv6 is always forward-confirmed).
    fn build(
        mut builder: ResolverBuilder<TokioRuntimeProvider>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 1;
        opts.use_hosts_file = ResolveHosts::Never;
        opts.ip_strategy = LookupIpStrategy::Ipv6AndIpv4;
        let inner = builder.build().map_err(|e| format!("DNS resolver: {e}"))?;
        Ok(Self { inner, timeout })
    }

    async fn reverse_now(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        let lookup = tokio::time::timeout(self.timeout, self.inner.reverse_lookup(ip))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| map_error(&e))?;
        Ok(lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::PTR(ptr) => Some(ptr.0.to_ascii()),
                _ => None,
            })
            .collect())
    }

    async fn forward_now(&self, name: &str) -> Result<Vec<IpAddr>, DnsError> {
        let lookup = tokio::time::timeout(self.timeout, self.inner.lookup_ip(name))
            .await
            .map_err(|_| DnsError::Timeout)?
            .map_err(|e| map_error(&e))?;
        Ok(lookup.iter().collect())
    }
}

impl DnsResolver for HickoryResolver {
    fn reverse(&self, ip: IpAddr) -> BoxFuture<'_, Result<Vec<String>, DnsError>> {
        Box::pin(self.reverse_now(ip))
    }

    fn forward(&self, name: &str) -> BoxFuture<'_, Result<Vec<IpAddr>, DnsError>> {
        let name = name.to_owned();
        Box::pin(async move { self.forward_now(&name).await })
    }
}

/// What `mg-rdns` resolves with, prepared in `main()`: the static table is
/// parsed at start-up (it needs no runtime); hickory is built later, on the
/// service's runtime.
#[derive(Clone)]
pub enum ResolverSetup {
    /// hickory with `/etc/resolv.conf` and this per-query timeout.
    System { timeout: Duration },
    /// `static:<path>` (a start-up warning says so).
    Static(Arc<StaticResolver>),
}

impl fmt::Debug for ResolverSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System { timeout } => f.debug_struct("System").field("timeout", timeout).finish(),
            Self::Static(r) => f.debug_tuple("Static").field(r).finish(),
        }
    }
}

impl ResolverSetup {
    /// From `[intel]`; reads and parses a static table.
    pub fn from_config(cfg: &IntelConfig) -> Result<Self, String> {
        Ok(match &cfg.dns_resolver {
            DnsResolverConfig::System => Self::System {
                timeout: Duration::from_millis(cfg.dns_timeout_ms),
            },
            DnsResolverConfig::Static(path) => {
                let json = std::fs::read(path)
                    .map_err(|e| format!("[intel] dns_resolver {}: {e}", path.display()))?;
                let r = StaticResolver::from_json(&json)
                    .map_err(|e| format!("[intel] dns_resolver {}: {e}", path.display()))?;
                Self::Static(Arc::new(r))
            }
        })
    }

    /// The resolver; call on the runtime that will use it.
    pub fn build(&self) -> Result<Arc<dyn DnsResolver>, String> {
        Ok(match self {
            Self::System { timeout } => Arc::new(HickoryResolver::from_system(*timeout)?),
            Self::Static(r) => Arc::clone(r) as Arc<dyn DnsResolver>,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::net::NoRecords;
    use hickory_resolver::proto::op::Query;
    use hickory_resolver::proto::rr::{Name, RecordType};

    fn no_records(code: ResponseCode) -> NetError {
        let query = Query::query(
            Name::from_ascii("7.100.51.198.in-addr.arpa.").unwrap(),
            RecordType::PTR,
        );
        NetError::Dns(HickoryDnsError::NoRecordsFound(NoRecords::new(query, code)))
    }

    /// §9.6 mapping: only authoritative "no such record" answers are
    /// `NoRecords`; everything else is a server error or a timeout.
    #[test]
    fn error_mapping() {
        assert_eq!(
            map_error(&no_records(ResponseCode::NXDomain)),
            DnsError::NoRecords
        );
        assert_eq!(
            map_error(&no_records(ResponseCode::NoError)),
            DnsError::NoRecords
        );
        assert!(matches!(
            map_error(&no_records(ResponseCode::ServFail)),
            DnsError::Server(_)
        ));
        for code in [
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::NXDomain,
        ] {
            assert!(matches!(
                map_error(&NetError::Dns(HickoryDnsError::ResponseCode(code))),
                DnsError::Server(_)
            ));
        }
        assert_eq!(map_error(&NetError::Timeout), DnsError::Timeout);
        assert!(matches!(
            map_error(&NetError::NoConnections),
            DnsError::Server(_)
        ));
        assert!(matches!(
            map_error(&NetError::Msg("x".into())),
            DnsError::Server(_)
        ));
    }

    /// D-31: the error text never carries the query name (a PTR name spells
    /// out the client address).
    #[test]
    fn server_errors_do_not_name_the_query() {
        for e in [
            no_records(ResponseCode::ServFail),
            NetError::Dns(HickoryDnsError::ResponseCode(ResponseCode::Refused)),
            NetError::Msg("lookup of 7.100.51.198.in-addr.arpa failed".into()),
        ] {
            let text = map_error(&e).to_string();
            assert!(!text.contains("198"), "{text}");
            assert!(!text.contains("arpa"), "{text}");
        }
    }

    /// A loopback DNS server: PTR / A answers by query name, NXDOMAIN,
    /// NOERROR without answers, SERVFAIL, REFUSED, or silence.
    async fn fake_dns(sock: tokio::net::UdpSocket) {
        use hickory_resolver::proto::op::{Message, OpCode};
        use hickory_resolver::proto::rr::rdata::{A, AAAA, PTR};
        use hickory_resolver::proto::rr::{RData, Record};
        let mut buf = [0u8; 1500];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let Some(query) = q.queries.first().cloned() else {
                continue;
            };
            let name = query.name().to_ascii();
            let mut r = Message::response(q.metadata.id, OpCode::Query);
            r.metadata.recursion_desired = q.metadata.recursion_desired;
            r.metadata.recursion_available = true;
            r.add_query(query.clone());
            let ptr = |target: &str| RData::PTR(PTR(Name::from_ascii(target).unwrap()));
            match (name.as_str(), query.query_type()) {
                ("1.2.0.192.in-addr.arpa.", RecordType::PTR) => {
                    r.add_answer(Record::from_rdata(
                        query.name().clone(),
                        60,
                        ptr("crawl-1.googlebot.com."),
                    ));
                }
                ("crawl-1.googlebot.com.", RecordType::A) => {
                    r.add_answer(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::A(A::new(192, 0, 2, 1)),
                    ));
                }
                ("crawl-1.googlebot.com.", _) => {} // NOERROR, no AAAA
                // An IPv6 crawler: AAAA only (A is NOERROR, empty).
                ("crawl-6.googlebot.com.", RecordType::AAAA) => {
                    r.add_answer(Record::from_rdata(
                        query.name().clone(),
                        60,
                        RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 6)),
                    ));
                }
                ("crawl-6.googlebot.com.", _) => {}
                ("2.2.0.192.in-addr.arpa.", _) => r.metadata.response_code = ResponseCode::NXDomain,
                ("3.2.0.192.in-addr.arpa.", _) => r.metadata.response_code = ResponseCode::ServFail,
                ("4.2.0.192.in-addr.arpa.", _) => r.metadata.response_code = ResponseCode::Refused,
                ("5.2.0.192.in-addr.arpa.", _) => {} // NOERROR, no answers
                _ => continue,                       // silence: a timeout
            }
            let _ = sock.send_to(&r.to_vec().unwrap(), from).await;
        }
    }

    /// §9.6 against hickory itself (a loopback server, no network): only
    /// NXDOMAIN and an empty NOERROR are `NoRecords`; SERVFAIL and REFUSED
    /// are server errors; silence is a timeout; answers come back as names
    /// with a trailing dot and addresses. And the whole rDNS check passes.
    #[test]
    fn hickory_behaviour_on_a_loopback_server() {
        use hickory_resolver::config::{ConnectionConfig, NameServerConfig};
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = sock.local_addr().unwrap().port();
            tokio::spawn(fake_dns(sock));
            let mut udp = ConnectionConfig::udp();
            udp.port = port;
            let ns = NameServerConfig::new("127.0.0.1".parse().unwrap(), true, vec![udp]);
            let r = HickoryResolver::with_config(
                ResolverConfig::from_name_servers(vec![ns]),
                Duration::from_millis(300),
            )
            .unwrap();
            let ip = |last: u8| IpAddr::from([192, 0, 2, last]);
            assert_eq!(r.reverse(ip(1)).await.unwrap(), ["crawl-1.googlebot.com."]);
            assert_eq!(r.forward("crawl-1.googlebot.com.").await.unwrap(), [ip(1)]);
            // §9.6: forward lookups ask for AAAA as well (Ipv6AndIpv4).
            assert_eq!(
                r.forward("crawl-6.googlebot.com.").await.unwrap(),
                [IpAddr::from([0x2001, 0xdb8, 0, 0, 0, 0, 0, 6])]
            );
            assert_eq!(r.reverse(ip(2)).await, Err(DnsError::NoRecords));
            assert!(matches!(r.reverse(ip(3)).await, Err(DnsError::Server(_))));
            assert!(matches!(r.reverse(ip(4)).await, Err(DnsError::Server(_))));
            assert_eq!(r.reverse(ip(5)).await, Err(DnsError::NoRecords));
            assert_eq!(r.reverse(ip(6)).await, Err(DnsError::Timeout));
            // D-31: no error text names the query.
            for last in [3, 4] {
                let text = r.reverse(ip(last)).await.unwrap_err().to_string();
                assert!(!text.contains("192") && !text.contains("arpa"), "{text}");
            }
            let job = mg_intel::RdnsJob::new(ip(1), "googlebot", vec![".googlebot.com".into()]);
            assert_eq!(
                mg_intel::resolve_rdns(&job, &r).await,
                mg_intel::RdnsOutcome::Pass
            );
            let job = mg_intel::RdnsJob::new(ip(3), "googlebot", vec![".googlebot.com".into()]);
            assert_eq!(
                mg_intel::resolve_rdns(&job, &r).await,
                mg_intel::RdnsOutcome::DnsError
            );
        });
    }

    #[test]
    fn deadline_is_two_queries_plus_one_second() {
        assert_eq!(job_deadline(2_000), Duration::from_millis(5_000));
        assert_eq!(job_deadline(100), Duration::from_millis(1_200));
        assert_eq!(job_deadline(u64::MAX), Duration::from_millis(u64::MAX));
    }

    #[test]
    fn static_setup_reads_the_table() {
        let dir = std::env::temp_dir().join(format!("mg-dns-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("static.json");
        std::fs::write(
            &path,
            br#"{"v":1,"ptr":{"198.51.100.7":["crawl-1.googlebot.com."]},"a":{"crawl-1.googlebot.com":["198.51.100.7"]}}"#,
        )
        .unwrap();
        let cfg = IntelConfig {
            dns_resolver: DnsResolverConfig::Static(path.clone()),
            ..IntelConfig::default()
        };
        let setup = ResolverSetup::from_config(&cfg).unwrap();
        assert!(matches!(setup, ResolverSetup::Static(_)));
        let r = setup.build().unwrap();
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut fut = r.reverse("198.51.100.7".parse().unwrap());
        match fut.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(Ok(names)) => assert_eq!(names, ["crawl-1.googlebot.com."]),
            other => panic!("{other:?}"),
        }
        std::fs::write(&path, b"{not json").unwrap();
        assert!(ResolverSetup::from_config(&cfg).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
