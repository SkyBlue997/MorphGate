//! §5.3 semantics, node by node: true / false / unknown / error.

use super::dsl::*;
use super::*;
use std::collections::BTreeMap;

fn act() -> Activation {
    let mut a = Activation::default();
    a.req.method = "GET".into();
    a.req.path = "/account/login".into();
    a.req.host = "example.com".into();
    a.req.headers = BTreeMap::from([
        ("accept".to_string(), "text/html".to_string()),
        ("user-agent".to_string(), "Mozilla/5.0".to_string()),
    ]);
    a.net.ip = "203.0.113.7".into();
    a.net.asn = 64500;
    a.net.country = "HK".into();
    a.risk.score = 45;
    a.risk.confidence = 0.6;
    a.risk.class = "UNKNOWN".into();
    a.route.name = "login".into();
    a.rate = BTreeMap::from([("login-per-ip".to_string(), 0.2)]);
    a.labels = vec!["scanner".into()];
    a
}

fn lists() -> NamedLists {
    NamedLists::new(BTreeMap::from([
        (
            "owner_cidrs".to_string(),
            vec!["10.0.0.0/8".to_string(), "2001:db8::/32".to_string()],
        ),
        (
            "broken".to_string(),
            vec!["10.0.0.0/8".to_string(), "bogus".to_string()],
        ),
        (
            "countries".to_string(),
            vec!["HK".to_string(), "MO".to_string()],
        ),
    ]))
}

fn cf_missing() -> MissingSet {
    MissingSet::new([
        "tls",
        "http.header_order",
        "identity.proof",
        "identity.agent",
    ])
    .unwrap()
}

fn ev(e: Expr) -> EvalResult {
    ev_with(e, &act(), &cf_missing())
}

fn ev_with(e: Expr, a: &Activation, m: &MissingSet) -> EvalResult {
    let p = prog(e);
    let (r, steps) = eval_steps(&p, a, m, &lists());
    assert!(
        steps <= p.max_steps(),
        "steps {steps} > bound {}",
        p.max_steps()
    );
    r
}

use EvalResult::{False, True};

fn unknown(paths: &[&'static str]) -> EvalResult {
    EvalResult::Unknown(paths.to_vec())
}

fn err(e: EvalError) -> EvalResult {
    EvalResult::Error(e)
}

const TLS: &str = "tls.version";
const JA4: &str = "tls.ja4.value";

fn tls_unknown() -> Expr {
    eq(f(TLS), s("TLSv1.3"))
}

fn no_key() -> Expr {
    eq(idx(f("req.headers"), s("x-missing")), s("a"))
}

#[test]
fn literals_fields_and_missing() {
    assert_eq!(ev(t()), True);
    assert_eq!(ev(fa()), False);
    assert_eq!(ev(eq(f("req.method"), s("GET"))), True);
    assert_eq!(ev(eq(f("net.asn"), i(64500))), True);
    assert_eq!(ev(f("net.tor")), False, "ABSENT reads as the zero value");
    assert_eq!(ev(tls_unknown()), unknown(&[TLS]));
    assert_eq!(
        ev(eq(f(JA4), s(""))),
        unknown(&[JA4]),
        "under a MISSING prefix"
    );
    // A non-bool root is no_such_overload.
    let p = Program::new(size(f("req.path")));
    assert!(p.is_err(), "rejected at load time");
}

#[test]
fn has_never_unknown_or_error() {
    assert_eq!(ev(has("net.ip")), True, "PRESENT");
    assert_eq!(ev(has("net.country")), True);
    assert_eq!(
        ev(has("identity.crawler.cf_vbot")),
        True,
        "ABSENT still has()"
    );
    assert_eq!(ev(has("tls.version")), False, "MISSING via the tls prefix");
    assert_eq!(
        ev(has("tls.ja4")),
        False,
        "struct under a MISSING namespace"
    );
    assert_eq!(ev(has("identity.proof.valid")), False);
    assert_eq!(ev(has("identity.proof")), False);
    let m = MissingSet::new(["tls.ja4"]).unwrap();
    assert_eq!(ev_with(has("tls.ja4.value"), &act(), &m), False);
    assert_eq!(
        ev_with(has("tls.version"), &act(), &m),
        True,
        "sibling of a MISSING path"
    );
}

/// `&&` / `||` absorption (§5.8 coverage list).
#[test]
fn and_or_absorption() {
    let unk = tls_unknown;
    let e = no_key;
    // false && unknown -> false; true && unknown -> unknown
    assert_eq!(ev(and(vec![fa(), unk()])), False);
    assert_eq!(
        ev(and(vec![unk(), fa()])),
        False,
        "false absorbs in any position"
    );
    assert_eq!(ev(and(vec![t(), unk()])), unknown(&[TLS]));
    // unknown && error -> unknown; error && false -> false
    assert_eq!(ev(and(vec![unk(), e()])), unknown(&[TLS]));
    assert_eq!(ev(and(vec![e(), unk()])), unknown(&[TLS]));
    assert_eq!(ev(and(vec![e(), fa()])), False);
    assert_eq!(ev(and(vec![t(), e()])), err(EvalError::NoSuchKey));
    assert_eq!(ev(and(vec![t(), t(), t()])), True);
    // true || unknown -> true; false || unknown -> unknown; unknown || error -> unknown
    assert_eq!(ev(or(vec![t(), unk()])), True);
    assert_eq!(ev(or(vec![unk(), t()])), True);
    assert_eq!(ev(or(vec![fa(), unk()])), unknown(&[TLS]));
    assert_eq!(ev(or(vec![unk(), e()])), unknown(&[TLS]));
    assert_eq!(ev(or(vec![e(), t()])), True);
    assert_eq!(ev(or(vec![fa(), e()])), err(EvalError::NoSuchKey));
    assert_eq!(ev(or(vec![fa(), fa()])), False);
    // The union of every UNKNOWN argument's paths, sorted.
    let ja4 = eq(f(JA4), s("x"));
    assert_eq!(ev(and(vec![t(), ja4.clone(), unk()])), unknown(&[JA4, TLS]));
    assert_eq!(ev(or(vec![unk(), ja4, fa()])), unknown(&[JA4, TLS]));
    // The first error wins.
    let bad_ip = ip_in(f("net.ip"), named("broken"));
    assert_eq!(
        ev(and(vec![bad_ip.clone(), e()])),
        err(EvalError::InvalidArgument)
    );
    assert_eq!(ev(and(vec![e(), bad_ip])), err(EvalError::NoSuchKey));
}

#[test]
fn not_and_cond() {
    assert_eq!(ev(not(t())), False);
    assert_eq!(ev(not(fa())), True);
    assert_eq!(
        ev(not(tls_unknown())),
        unknown(&[TLS]),
        "!unknown is unknown"
    );
    assert_eq!(ev(not(no_key())), err(EvalError::NoSuchKey));
    // Condition unknown: the whole ?: is that unknown, no branch is evaluated.
    assert_eq!(ev(cond(tls_unknown(), t(), no_key())), unknown(&[TLS]));
    assert_eq!(ev(cond(no_key(), t(), t())), err(EvalError::NoSuchKey));
    assert_eq!(
        ev(cond(t(), t(), no_key())),
        True,
        "only the taken branch runs"
    );
    assert_eq!(ev(cond(fa(), no_key(), fa())), False);
    // The docs/06 has() pattern.
    let e = cond(
        has("tls.ja4"),
        in_list(f(JA4), named("countries")),
        in_list(f("net.country"), named("countries")),
    );
    assert_eq!(ev(e), True);
}

#[test]
fn compare() {
    use CompareOp::*;
    assert_eq!(ev(cmp(Ge, f("risk.score"), i(45))), True);
    assert_eq!(ev(cmp(Gt, f("risk.score"), i(45))), False);
    assert_eq!(ev(cmp(Lt, f("risk.confidence"), d(0.61))), True);
    assert_eq!(ev(cmp(Le, s("a"), s("b"))), True);
    assert_eq!(
        ev(cmp(Lt, s("é"), s("z"))),
        False,
        "Unicode scalar / UTF-8 byte order"
    );
    assert_eq!(ev(cmp(Ne, f("net.tor"), t())), True);
    // NaN: every comparison false except !=.
    let nan = || Expr::Literal(Literal::Double(f64::NAN));
    for op in [Eq, Lt, Le, Gt, Ge] {
        assert_eq!(ev(cmp(op, nan(), d(1.0))), False, "{op:?}");
    }
    assert_eq!(ev(cmp(Ne, nan(), nan())), True);
    assert_eq!(
        ev(cmp(Eq, f(TLS), no_key_value())),
        err(EvalError::NoSuchKey),
        "error before unknown"
    );
    assert_eq!(ev(cmp(Eq, f(TLS), f(JA4))), unknown(&[JA4, TLS]));
}

fn no_key_value() -> Expr {
    idx(f("req.headers"), s("x-missing"))
}

#[test]
fn lists_and_maps() {
    assert_eq!(ev(in_list(s("scanner"), f("labels"))), True);
    assert_eq!(ev(in_list(s("x"), f("labels"))), False);
    assert_eq!(ev(in_list(i(2), list(vec![i(1), i(2)]))), True);
    assert_eq!(ev(in_list(d(2.0), list(vec![d(1.0), d(2.0)]))), True);
    assert_eq!(ev(in_list(s("a"), list(vec![]))), False);
    assert_eq!(ev(in_list(f("net.country"), named("countries"))), True);
    assert_eq!(
        ev(in_list(s("x"), named("nope"))),
        err(EvalError::UnknownList)
    );
    assert_eq!(
        ev(in_list(s("x"), list(vec![s("a"), f(TLS)]))),
        unknown(&[TLS])
    );
    assert_eq!(
        ev(in_list(s("x"), list(vec![no_key_value(), f(TLS)]))),
        err(EvalError::NoSuchKey)
    );
    // Map key presence and index.
    assert_eq!(
        ev(in_map(s("login-per-ip"), f("rate"))),
        True,
        "\"k\" in rate"
    );
    assert_eq!(ev(in_map(s("other"), f("rate"))), False);
    assert_eq!(ev(in_map(s("accept"), f("req.headers"))), True);
    assert_eq!(
        ev(cmp(
            CompareOp::Lt,
            idx(f("rate"), s("login-per-ip")),
            d(0.5)
        )),
        True
    );
    assert_eq!(
        ev(cmp(CompareOp::Lt, idx(f("rate"), s("x")), d(0.5))),
        err(EvalError::NoSuchKey)
    );
    assert_eq!(
        ev(eq(idx(f("req.headers"), s("accept")), s("text/html"))),
        True
    );
}

#[test]
fn size_and_string_functions_count_unicode_scalars() {
    use StringFn::*;
    let mut a = act();
    a.req.path = "/日本語/é".into();
    let m = cf_missing();
    assert_eq!(
        ev_with(eq(size(f("req.path")), i(6)), &a, &m),
        True,
        "6 scalars, 12 bytes"
    );
    assert_eq!(
        ev_with(call(StartsWith, f("req.path"), s("/日本")), &a, &m),
        True
    );
    assert_eq!(
        ev_with(call(EndsWith, f("req.path"), s("/é")), &a, &m),
        True
    );
    assert_eq!(
        ev_with(call(Contains, f("req.path"), s("本語")), &a, &m),
        True
    );
    assert_eq!(
        ev_with(call(Contains, f("req.path"), s("x")), &a, &m),
        False
    );
    assert_eq!(ev(eq(size(f("labels")), i(1))), True);
    assert_eq!(ev(eq(size(f("req.headers")), i(2))), True);
    assert_eq!(ev(eq(size(list(vec![s("a"), s("b")])), i(2))), True);
    assert_eq!(ev(eq(size(f(TLS)), i(0))), unknown(&[TLS]));
    assert_eq!(
        ev(call(StartsWith, f(TLS), no_key_value())),
        err(EvalError::NoSuchKey)
    );
}

#[test]
fn ip_in_semantics() {
    let with_ip = |ip: &str, l: Expr| {
        let mut a = act();
        a.net.ip = ip.into();
        ev_with(ip_in(f("net.ip"), l), &a, &cf_missing())
    };
    assert_eq!(with_ip("10.1.2.3", named("owner_cidrs")), True);
    assert_eq!(with_ip("2001:db8::7", named("owner_cidrs")), True);
    assert_eq!(
        with_ip("::ffff:10.0.0.1", named("owner_cidrs")),
        True,
        "mapped address"
    );
    assert_eq!(with_ip("203.0.113.7", named("owner_cidrs")), False);
    assert_eq!(
        with_ip("10.0.0.1", list(vec![s("::ffff:10.0.0.0/104")])),
        True,
        "mapped CIDR"
    );
    assert_eq!(with_ip("not-an-ip", named("owner_cidrs")), False);
    assert_eq!(
        with_ip("not-an-ip", named("broken")),
        False,
        "invalid subject first"
    );
    assert_eq!(
        with_ip("10.0.0.1", named("broken")),
        err(EvalError::InvalidArgument),
        "even after a match"
    );
    assert_eq!(
        with_ip("10.0.0.1", list(vec![s("10.0.0.1"), s("x")])),
        err(EvalError::InvalidArgument)
    );
    assert_eq!(
        with_ip("10.0.0.1", f("labels")),
        err(EvalError::InvalidArgument)
    );
    assert_eq!(
        with_ip("10.0.0.1", named("nope")),
        err(EvalError::UnknownList)
    );
    // §5.3: a subject with a zone is not an IP ("不带 zone"): `false`, and the
    // entries are not looked at, exactly like Go's `ipIn` (which returns
    // before parsing the list), including for an IPv4-mapped zoned address.
    assert_eq!(with_ip("fe80::1%eth0", list(vec![s("fe80::/10")])), False);
    assert_eq!(
        with_ip("fe80::1%eth0", named("broken")),
        False,
        "not an IP: entries are not validated"
    );
    assert_eq!(
        with_ip("::ffff:10.0.0.1%eth0", named("owner_cidrs")),
        False,
        "a zoned mapped address is not an IP either"
    );
    let m = MissingSet::new(["net.ip"]).unwrap();
    assert_eq!(
        ev_with(ip_in(f("net.ip"), named("owner_cidrs")), &act(), &m),
        unknown(&["net.ip"])
    );
    // docs/06: `!has(net.ip) || !ip_in(net.ip, list("owner_cidrs"))`.
    let e = or(vec![
        not(has("net.ip")),
        not(ip_in(f("net.ip"), named("owner_cidrs"))),
    ]);
    assert_eq!(ev_with(e.clone(), &act(), &m), True);
    assert_eq!(ev(e), True);
}

#[test]
fn glob_semantics() {
    let with_path = |p: &str, pat: &str| {
        let mut a = act();
        a.req.path = p.into();
        ev_with(glob(f("req.path"), pat), &a, &cf_missing())
    };
    assert_eq!(with_path("/admin/users", "/admin/*"), True);
    assert_eq!(with_path("/admin/users/1", "/admin/*"), False);
    assert_eq!(with_path("/admin/users/1", "/admin/**"), True);
    assert_eq!(with_path("/admin/users/1", "/admin/***"), True);
    assert_eq!(with_path("/ab", "/a?"), True);
    assert_eq!(with_path("/日本", "/??"), True);
    assert_eq!(with_path("/Admin", "/admin"), False);
    assert_eq!(ev(glob(f(TLS), "*")), unknown(&[TLS]));
}

/// The runtime step counter aborts the whole rule; `||` does not absorb it.
#[test]
fn step_limit_is_not_absorbed() {
    let mut a = act();
    // Far beyond the §4.1 cap the Edge enforces: only a broken host could do this.
    a.req.path = "/".repeat(1_000_000);
    let e = or(vec![glob(f("req.path"), "/a*"), t()]);
    let p = prog(e);
    let (r, steps) = eval_steps(&p, &a, &cf_missing(), &lists());
    assert_eq!(r, err(EvalError::StepLimit));
    assert!(steps > MAX_STEPS);
    let e = and(vec![glob(f("req.path"), "/a*"), fa()]);
    assert_eq!(
        eval(&prog(e), &a, &cf_missing(), &lists()),
        err(EvalError::StepLimit)
    );
    // Within the cap the same rule is fine.
    a.req.path = "/".repeat(8192);
    let e = or(vec![glob(f("req.path"), "/a*"), t()]);
    assert_eq!(eval(&prog(e), &a, &cf_missing(), &lists()), True);
}

/// Trees that bypass the load-time type check still get `no_such_overload`
/// (never a panic), and `in` compares across types as "not equal" (§5.3).
#[test]
fn dynamic_type_errors() {
    let a = act();
    let m = cf_missing();
    let l = lists();
    let raw = |e: Expr| {
        assert!(Program::new(e.clone()).is_err(), "{e:?} must not load");
        eval(&Program::new_unchecked(e), &a, &m, &l)
    };
    let nso = err(EvalError::NoSuchOverload);
    assert_eq!(raw(f("req.path")), nso, "non-bool root");
    assert_eq!(raw(not(i(1))), nso);
    assert_eq!(raw(and(vec![t(), i(1)])), nso);
    assert_eq!(
        raw(and(vec![i(1), tls_unknown()])),
        unknown(&[TLS]),
        "unknown beats a non-bool"
    );
    assert_eq!(raw(and(vec![i(1), fa()])), False, "false beats a non-bool");
    assert_eq!(
        raw(or(vec![s("x"), no_key()])),
        nso,
        "the first bad argument wins"
    );
    assert_eq!(raw(cond(i(1), t(), t())), nso);
    assert_eq!(raw(cmp(CompareOp::Lt, t(), fa())), nso);
    assert_eq!(raw(eq(i(1), s("1"))), nso);
    assert_eq!(
        raw(eq(i(1), d(1.0))),
        nso,
        "no cross-type numeric comparison"
    );
    assert_eq!(raw(in_list(s("a"), f("rate"))), nso);
    assert_eq!(raw(in_map(i(1), f("rate"))), nso);
    assert_eq!(raw(eq(idx(f("labels"), s("x")), s("x"))), nso);
    assert_eq!(raw(eq(size(i(1)), i(0))), nso);
    assert_eq!(raw(call(StringFn::Contains, i(1), s("x"))), nso);
    assert_eq!(raw(ip_in(i(1), named("owner_cidrs"))), nso);
    assert_eq!(raw(ip_in(f("net.ip"), list(vec![i(1)]))), nso);
    assert_eq!(raw(glob(i(1), "*")), nso);
    // `in` on lists: elements of another type are simply unequal.
    assert_eq!(raw(in_list(i(1), list(vec![d(1.0), s("a")]))), False);
    assert_eq!(raw(in_list(s("a"), list(vec![i(1), s("a")]))), True);
    assert_eq!(raw(in_list(i(1), list(vec![d(1.0)]))), False);
    assert_eq!(raw(in_list(i(1), f("labels"))), False);
}
