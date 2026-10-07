//! The policy IR evaluator: the normative semantics of
//! docs/impl/phase1-spec.md §5.3 (three-valued with MISSING = UNKNOWN,
//! strict nodes, `&&` / `||` absorption, runtime step accounting).

use super::fields::{Activation, FieldId, MissingSet};
use super::ip::{NamedList, NamedLists, parse_entry, parse_subject};
use super::ir::{CompareOp, Expr, Literal, MAX_STEPS, Program, StringFn};
use std::collections::BTreeMap;

wire_enum! {
    /// Error kinds of a failed evaluation (wire strings of `RuleHit.fields`).
    pub enum EvalError {
        /// An operation got operands of the wrong type (or a non-bool root).
        NoSuchOverload => "no_such_overload",
        /// `m[k]` with an absent key.
        NoSuchKey => "no_such_key",
        /// An `ip_in` list entry is not an IP or CIDR.
        InvalidArgument => "invalid_argument",
        /// `list("name")` names no list of the bundle.
        UnknownList => "unknown_list",
        /// The runtime step counter passed [`MAX_STEPS`]; the whole rule is aborted.
        StepLimit => "step_limit",
    }
}

/// Result of evaluating one rule expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvalResult {
    True,
    False,
    /// The result depends on MISSING fields: these paths, sorted and unique.
    Unknown(Vec<&'static str>),
    Error(EvalError),
}

impl EvalResult {
    /// Whether the rule matched.
    pub fn is_true(&self) -> bool {
        *self == Self::True
    }
}

/// Evaluates `p` against one request.
pub fn eval(p: &Program, act: &Activation, missing: &MissingSet, lists: &NamedLists) -> EvalResult {
    eval_steps(p, act, missing, lists).0
}

/// Like [`eval`], also returning the number of steps spent (never more than
/// `p.max_steps()` for an activation within the §4.1 size caps).
pub fn eval_steps(
    p: &Program,
    act: &Activation,
    missing: &MissingSet,
    lists: &NamedLists,
) -> (EvalResult, u64) {
    let mut ev = Evaluator {
        act,
        missing,
        lists,
        steps: 0,
    };
    let result = match ev.node(p.root()) {
        Err(StepLimit) => EvalResult::Error(EvalError::StepLimit),
        Ok(R::Val(V::Bool(true))) => EvalResult::True,
        Ok(R::Val(V::Bool(false))) => EvalResult::False,
        Ok(R::Val(_)) => EvalResult::Error(EvalError::NoSuchOverload),
        Ok(R::Unknown(paths)) => EvalResult::Unknown(paths),
        Ok(R::Err(e)) => EvalResult::Error(e),
    };
    (result, ev.steps)
}

/// The runtime step counter passed [`MAX_STEPS`].
struct StepLimit;

/// A runtime value. Strings and lists borrow from the program, the
/// activation or the named lists; nothing is copied.
#[derive(Debug, Clone)]
enum V<'a> {
    Bool(bool),
    Int(i64),
    Double(f64),
    Str(&'a str),
    List(L<'a>),
    Map(M<'a>),
}

#[derive(Debug, Clone)]
enum L<'a> {
    /// A list(string) field.
    Strs(&'a [String]),
    /// A list literal.
    Vals(Vec<V<'a>>),
    /// `list("name")`.
    Named(&'a NamedList),
}

impl L<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Strs(xs) => xs.len(),
            Self::Vals(xs) => xs.len(),
            Self::Named(l) => l.entries().len(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum M<'a> {
    Str(&'a BTreeMap<String, String>),
    Double(&'a BTreeMap<String, f64>),
}

impl M<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Str(m) => m.len(),
            Self::Double(m) => m.len(),
        }
    }

    fn contains(&self, k: &str) -> bool {
        match self {
            Self::Str(m) => m.contains_key(k),
            Self::Double(m) => m.contains_key(k),
        }
    }
}

/// The result of one node: a value, UNKNOWN (with the MISSING paths read) or an error.
#[derive(Debug, Clone)]
enum R<'a> {
    Val(V<'a>),
    Unknown(Vec<&'static str>),
    Err(EvalError),
}

fn bool_r<'a>(b: bool) -> R<'a> {
    R::Val(V::Bool(b))
}

/// Sorted union of two sorted path sets.
fn union(mut a: Vec<&'static str>, b: Vec<&'static str>) -> Vec<&'static str> {
    a.extend(b);
    a.sort_unstable();
    a.dedup();
    a
}

/// Strict combination of two child results: the first error (in child
/// order), else the union of UNKNOWNs, else both values.
fn strict2<'a>(a: R<'a>, b: R<'a>) -> Result<(V<'a>, V<'a>), R<'a>> {
    match (a, b) {
        (R::Val(a), R::Val(b)) => Ok((a, b)),
        (R::Err(e), _) | (_, R::Err(e)) => Err(R::Err(e)),
        (R::Unknown(a), R::Unknown(b)) => Err(R::Unknown(union(a, b))),
        (R::Unknown(u), _) | (_, R::Unknown(u)) => Err(R::Unknown(u)),
    }
}

/// `⌈x / 64⌉` for runtime sizes.
fn per64(x: usize) -> u64 {
    (x as u64).div_ceil(64)
}

struct Evaluator<'a> {
    act: &'a Activation,
    missing: &'a MissingSet,
    lists: &'a NamedLists,
    steps: u64,
}

impl<'a> Evaluator<'a> {
    fn charge(&mut self, cost: u64) -> Result<(), StepLimit> {
        self.steps = self.steps.saturating_add(cost);
        if self.steps > MAX_STEPS {
            Err(StepLimit)
        } else {
            Ok(())
        }
    }

    fn field(&self, f: FieldId) -> V<'a> {
        let a = self.act;
        match f {
            FieldId::ReqMethod => V::Str(&a.req.method),
            FieldId::ReqHost => V::Str(&a.req.host),
            FieldId::ReqPath => V::Str(&a.req.path),
            FieldId::ReqQuery => V::Str(&a.req.query),
            FieldId::ReqHeaders => V::Map(M::Str(&a.req.headers)),
            FieldId::ReqChannel => V::Str(&a.req.channel),
            FieldId::NetIp => V::Str(&a.net.ip),
            FieldId::NetAsn => V::Int(a.net.asn),
            FieldId::NetCountry => V::Str(&a.net.country),
            FieldId::NetConnType => V::Str(&a.net.conn_type),
            FieldId::NetTor => V::Bool(a.net.tor),
            FieldId::UpstreamProfile => V::Str(&a.upstream.profile),
            FieldId::UpstreamAuthenticated => V::Bool(a.upstream.authenticated),
            FieldId::UpstreamAuthMethod => V::Str(&a.upstream.auth_method),
            FieldId::TlsJa4Value => V::Str(&a.tls.ja4.value),
            FieldId::TlsJa4Source => V::Str(&a.tls.ja4.source),
            FieldId::TlsJa4Authenticated => V::Bool(a.tls.ja4.authenticated),
            FieldId::TlsVersion => V::Str(&a.tls.version),
            FieldId::HttpVersion => V::Str(&a.http.version),
            FieldId::HttpHeaderOrder => V::List(L::Strs(&a.http.header_order)),
            FieldId::EdgeTlsVersion => V::Str(&a.edge_tls.version),
            FieldId::EdgeTlsCipher => V::Str(&a.edge_tls.cipher),
            FieldId::EdgeTlsCiphersSha1 => V::Str(&a.edge_tls.ciphers_sha1),
            FieldId::EdgeTlsExtSha1 => V::Str(&a.edge_tls.ext_sha1),
            FieldId::EdgeTlsHelloLen => V::Int(a.edge_tls.hello_len),
            FieldId::TokenLevel => V::Str(&a.identity.token.level),
            FieldId::TokenAge => V::Int(a.identity.token.age),
            FieldId::ProofValid => V::Bool(a.identity.proof.valid),
            FieldId::AgentId => V::Str(&a.identity.agent.id),
            FieldId::AgentGrantId => V::Str(&a.identity.agent.grant_id),
            FieldId::CrawlerClaimed => V::Bool(a.identity.crawler.claimed),
            FieldId::CrawlerOperator => V::Str(&a.identity.crawler.operator),
            FieldId::CrawlerPurpose => V::Str(&a.identity.crawler.purpose),
            FieldId::CrawlerVerified => V::Bool(a.identity.crawler.verified),
            FieldId::CrawlerCfVbot => V::Bool(a.identity.crawler.cf_vbot),
            FieldId::CrawlerCfVbotCat => V::Str(&a.identity.crawler.cf_vbot_cat),
            FieldId::RiskScore => V::Int(a.risk.score),
            FieldId::RiskConfidence => V::Double(a.risk.confidence),
            FieldId::RiskClass => V::Str(&a.risk.class),
            FieldId::RiskReasons => V::List(L::Strs(&a.risk.reasons)),
            FieldId::RouteName => V::Str(&a.route.name),
            FieldId::RouteSensitivity => V::Str(&a.route.sensitivity),
            FieldId::RouteEnv => V::Str(&a.route.env),
            FieldId::Rate => V::Map(M::Double(&a.rate)),
            FieldId::Labels => V::List(L::Strs(&a.labels)),
        }
    }

    fn node(&mut self, e: &'a Expr) -> Result<R<'a>, StepLimit> {
        match e {
            Expr::Literal(l) => {
                self.charge(1)?;
                Ok(R::Val(match l {
                    Literal::Bool(b) => V::Bool(*b),
                    Literal::Int(i) => V::Int(*i),
                    Literal::Double(d) => V::Double(*d),
                    Literal::Str(s) => V::Str(s),
                }))
            }
            Expr::Field(f) => {
                self.charge(1)?;
                if self.missing.is_missing(f.path()) {
                    Ok(R::Unknown(vec![f.path()]))
                } else {
                    Ok(R::Val(self.field(*f)))
                }
            }
            Expr::Has(h) => {
                self.charge(1)?;
                Ok(bool_r(!self.missing.is_missing(h.path())))
            }
            Expr::NamedList(id) => {
                self.charge(1)?;
                Ok(match self.lists.get(id.name()) {
                    Some(list) => R::Val(V::List(L::Named(list))),
                    None => R::Err(EvalError::UnknownList),
                })
            }
            Expr::List(xs) => {
                let mut vals = Vec::with_capacity(xs.len());
                let mut unknown: Option<Vec<&'static str>> = None;
                let mut error = None;
                for x in xs {
                    match self.node(x)? {
                        R::Val(v) => vals.push(v),
                        R::Unknown(u) => unknown = Some(union(unknown.unwrap_or_default(), u)),
                        R::Err(e) => {
                            error.get_or_insert(e);
                        }
                    }
                }
                self.charge(1)?;
                Ok(match (error, unknown) {
                    (Some(e), _) => R::Err(e),
                    (None, Some(u)) => R::Unknown(u),
                    (None, None) => R::Val(V::List(L::Vals(vals))),
                })
            }
            Expr::Not(x) => {
                let r = self.node(x)?;
                self.charge(1)?;
                Ok(match r {
                    R::Val(V::Bool(b)) => bool_r(!b),
                    R::Val(_) => R::Err(EvalError::NoSuchOverload),
                    other => other,
                })
            }
            Expr::And(xs) => self.logic(xs, false),
            Expr::Or(xs) => self.logic(xs, true),
            Expr::Cond(c, t, f) => {
                let r = self.node(c)?;
                self.charge(1)?;
                match r {
                    R::Val(V::Bool(true)) => self.node(t),
                    R::Val(V::Bool(false)) => self.node(f),
                    R::Val(_) => Ok(R::Err(EvalError::NoSuchOverload)),
                    other => Ok(other),
                }
            }
            Expr::Compare(op, a, b) => {
                let (a, b) = (self.node(a)?, self.node(b)?);
                match strict2(a, b) {
                    Err(r) => {
                        self.charge(1)?;
                        Ok(r)
                    }
                    Ok((a, b)) => {
                        let cost = match (&a, &b) {
                            (V::Str(x), V::Str(y)) => 1 + per64(x.len() + y.len()),
                            _ => 1,
                        };
                        self.charge(cost)?;
                        Ok(compare(*op, &a, &b))
                    }
                }
            }
            Expr::InList(x, l) => {
                let (x, l) = (self.node(x)?, self.node(l)?);
                match strict2(x, l) {
                    Err(r) => {
                        self.charge(1)?;
                        Ok(r)
                    }
                    Ok((x, V::List(l))) => {
                        self.charge(1 + l.len() as u64)?;
                        Ok(bool_r(in_list(&x, &l)))
                    }
                    Ok(_) => {
                        self.charge(1)?;
                        Ok(R::Err(EvalError::NoSuchOverload))
                    }
                }
            }
            Expr::InMap(k, m) => {
                let (k, m) = (self.node(k)?, self.node(m)?);
                self.charge(2)?;
                Ok(match strict2(k, m) {
                    Err(r) => r,
                    Ok((V::Str(k), V::Map(m))) => bool_r(m.contains(k)),
                    Ok(_) => R::Err(EvalError::NoSuchOverload),
                })
            }
            Expr::IndexMap(m, k) => {
                let (m, k) = (self.node(m)?, self.node(k)?);
                self.charge(2)?;
                Ok(match strict2(m, k) {
                    Err(r) => r,
                    Ok((V::Map(M::Str(m)), V::Str(k))) => match m.get(k) {
                        Some(v) => R::Val(V::Str(v)),
                        None => R::Err(EvalError::NoSuchKey),
                    },
                    Ok((V::Map(M::Double(m)), V::Str(k))) => match m.get(k) {
                        Some(v) => R::Val(V::Double(*v)),
                        None => R::Err(EvalError::NoSuchKey),
                    },
                    Ok(_) => R::Err(EvalError::NoSuchOverload),
                })
            }
            Expr::Size(x) => {
                let r = self.node(x)?;
                let (cost, out) = match r {
                    R::Val(V::Str(s)) => {
                        (1 + per64(s.len()), R::Val(V::Int(s.chars().count() as i64)))
                    }
                    R::Val(V::List(l)) => (1, R::Val(V::Int(l.len() as i64))),
                    R::Val(V::Map(m)) => (1, R::Val(V::Int(m.len() as i64))),
                    R::Val(_) => (1, R::Err(EvalError::NoSuchOverload)),
                    other => (1, other),
                };
                self.charge(cost)?;
                Ok(out)
            }
            Expr::StringCall(f, t, a) => {
                let (t, a) = (self.node(t)?, self.node(a)?);
                match strict2(t, a) {
                    Err(r) => {
                        self.charge(1)?;
                        Ok(r)
                    }
                    Ok((V::Str(t), V::Str(a))) => {
                        self.charge(1 + per64(t.len() + a.len()))?;
                        // Valid UTF-8 on both sides: byte-wise prefix, suffix and
                        // substring tests equal the Unicode scalar sequence tests.
                        Ok(bool_r(match f {
                            StringFn::StartsWith => t.starts_with(a),
                            StringFn::EndsWith => t.ends_with(a),
                            StringFn::Contains => t.contains(a),
                        }))
                    }
                    Ok(_) => {
                        self.charge(1)?;
                        Ok(R::Err(EvalError::NoSuchOverload))
                    }
                }
            }
            Expr::IpIn(ip, l) => {
                let (ip, l) = (self.node(ip)?, self.node(l)?);
                match strict2(ip, l) {
                    Err(r) => {
                        self.charge(1)?;
                        Ok(r)
                    }
                    Ok((V::Str(ip), V::List(l))) => {
                        self.charge(1 + l.len() as u64)?;
                        Ok(ip_in(ip, &l))
                    }
                    Ok(_) => {
                        self.charge(1)?;
                        Ok(R::Err(EvalError::NoSuchOverload))
                    }
                }
            }
            Expr::Glob(s, g) => {
                let r = self.node(s)?;
                match r {
                    R::Val(V::Str(s)) => {
                        // Charged before the matcher runs: an oversized subject is
                        // stopped by the step limit, not by the matcher's cost.
                        self.charge(
                            1 + (s.len() as u64).saturating_mul(g.pattern().len() as u64) / 16,
                        )?;
                        Ok(bool_r(g.matches(s)))
                    }
                    R::Val(_) => {
                        self.charge(1)?;
                        Ok(R::Err(EvalError::NoSuchOverload))
                    }
                    other => {
                        self.charge(1)?;
                        Ok(other)
                    }
                }
            }
        }
    }

    /// `&&` (`absorbing = false`) and `||` (`absorbing = true`): left to
    /// right; the absorbing value wins (evaluation stops there), then UNKNOWN
    /// (union of paths), then the first ERROR or non-bool argument.
    fn logic(&mut self, xs: &'a [Expr], absorbing: bool) -> Result<R<'a>, StepLimit> {
        let mut unknown: Option<Vec<&'static str>> = None;
        let mut error: Option<EvalError> = None;
        for x in xs {
            match self.node(x)? {
                R::Val(V::Bool(b)) if b == absorbing => {
                    self.charge(1)?;
                    return Ok(bool_r(absorbing));
                }
                R::Val(V::Bool(_)) => {}
                R::Val(_) => {
                    error.get_or_insert(EvalError::NoSuchOverload);
                }
                R::Unknown(u) => unknown = Some(union(unknown.unwrap_or_default(), u)),
                R::Err(e) => {
                    error.get_or_insert(e);
                }
            }
        }
        self.charge(1)?;
        Ok(match (unknown, error) {
            (Some(u), _) => R::Unknown(u),
            (None, Some(e)) => R::Err(e),
            (None, None) => bool_r(!absorbing),
        })
    }
}

fn compare<'a>(op: CompareOp, a: &V<'a>, b: &V<'a>) -> R<'a> {
    use std::cmp::Ordering;
    let ord: Option<Ordering> = match (a, b) {
        (V::Bool(x), V::Bool(y)) => {
            return match op {
                CompareOp::Eq => bool_r(x == y),
                CompareOp::Ne => bool_r(x != y),
                _ => R::Err(EvalError::NoSuchOverload),
            };
        }
        (V::Int(x), V::Int(y)) => Some(x.cmp(y)),
        // IEEE: every comparison with NaN is false, except != which is true.
        (V::Double(x), V::Double(y)) => x.partial_cmp(y),
        (V::Str(x), V::Str(y)) => Some(x.cmp(y)),
        _ => return R::Err(EvalError::NoSuchOverload),
    };
    bool_r(match (op, ord) {
        (CompareOp::Ne, None) => true,
        (_, None) => false,
        (CompareOp::Eq, Some(o)) => o == Ordering::Equal,
        (CompareOp::Ne, Some(o)) => o != Ordering::Equal,
        (CompareOp::Lt, Some(o)) => o == Ordering::Less,
        (CompareOp::Le, Some(o)) => o != Ordering::Greater,
        (CompareOp::Gt, Some(o)) => o == Ordering::Greater,
        (CompareOp::Ge, Some(o)) => o != Ordering::Less,
    })
}

/// Same type and equal; elements of another type are simply unequal.
fn same_and_equal(a: &V<'_>, b: &V<'_>) -> bool {
    match (a, b) {
        (V::Bool(x), V::Bool(y)) => x == y,
        (V::Int(x), V::Int(y)) => x == y,
        (V::Double(x), V::Double(y)) => x == y,
        (V::Str(x), V::Str(y)) => x == y,
        _ => false,
    }
}

fn in_list(x: &V<'_>, l: &L<'_>) -> bool {
    match (x, l) {
        (V::Str(x), L::Strs(xs)) => xs.iter().any(|e| e == x),
        (V::Str(x), L::Named(n)) => n.entries().iter().any(|e| e == x),
        (_, L::Strs(_) | L::Named(_)) => false,
        (x, L::Vals(vs)) => vs.iter().any(|v| same_and_equal(x, v)),
    }
}

/// §5.3 `ip_in`: a subject that is not an IP (including one with a zone) is
/// `false`; otherwise every entry is validated (an invalid one is
/// `Error(invalid_argument)` even after a match).
fn ip_in<'a>(ip: &str, l: &L<'_>) -> R<'a> {
    let Some(subject) = parse_subject(ip) else {
        return bool_r(false);
    };
    let contains = |nets: &mut dyn Iterator<Item = Option<super::ip::IpNet>>| -> R<'a> {
        let mut found = false;
        for net in nets {
            let Some(net) = net else {
                return R::Err(EvalError::InvalidArgument);
            };
            found |= net.contains(subject);
        }
        bool_r(found)
    };
    match l {
        L::Named(n) => match n.nets() {
            None => R::Err(EvalError::InvalidArgument),
            Some(nets) => contains(&mut nets.iter().map(|n| Some(*n))),
        },
        L::Strs(xs) => contains(&mut xs.iter().map(|e| parse_entry(e))),
        L::Vals(vs) => {
            if vs.iter().any(|v| !matches!(v, V::Str(_))) {
                return R::Err(EvalError::NoSuchOverload);
            }
            contains(&mut vs.iter().map(|v| match v {
                V::Str(s) => parse_entry(s),
                _ => None,
            }))
        }
    }
}
