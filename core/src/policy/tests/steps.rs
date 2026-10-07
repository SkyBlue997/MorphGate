//! §5.3: runtime steps never exceed the static bound for activations within
//! the §4.1 size caps, over randomly generated well-typed expressions.

use super::dsl::*;
use super::*;
use std::collections::BTreeMap;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
    /// A string of at most `max_bytes` bytes, mixing ASCII and multi-byte characters.
    fn string(&mut self, max_bytes: usize) -> String {
        let target = self.below(max_bytes as u64 + 1) as usize;
        let alphabet = ['a', '/', '.', '1', 'é', '日', '*', '?', ':'];
        let mut s = String::new();
        while s.len() < target {
            let c = self.pick(&alphabet);
            if s.len() + c.len_utf8() > target {
                break;
            }
            s.push(c);
        }
        s
    }
}

const STR_FIELDS: &[&str] = &[
    "req.method",
    "req.host",
    "req.path",
    "req.query",
    "req.channel",
    "net.ip",
    "net.country",
    "net.conn_type",
    "upstream.profile",
    "tls.ja4.value",
    "tls.version",
    "http.version",
    "edge_tls.ciphers_sha1",
    "identity.token.level",
    "risk.class",
    "route.name",
];
const INT_FIELDS: &[&str] = &[
    "net.asn",
    "edge_tls.hello_len",
    "identity.token.age",
    "risk.score",
];
const BOOL_FIELDS: &[&str] = &[
    "net.tor",
    "upstream.authenticated",
    "identity.proof.valid",
    "identity.crawler.verified",
];
const LIST_FIELDS: &[&str] = &["labels", "risk.reasons", "http.header_order"];
const HAS_PATHS: &[&str] = &[
    "net.ip",
    "tls.ja4",
    "tls.version",
    "identity.proof",
    "http.header_order",
    "edge_tls.hello_len",
];
const PATTERNS: &[&str] = &["/a/**", "*", "/?/*.js", "**/x", "/日本/*"];

fn gen_bool(r: &mut Rng, depth: u32) -> Expr {
    let leaf = depth == 0;
    match r.below(if leaf { 3 } else { 14 }) {
        0 => Expr::Literal(Literal::Bool(r.below(2) == 0)),
        1 => f(r.pick(BOOL_FIELDS)),
        2 => has(r.pick(HAS_PATHS)),
        3 => not(gen_bool(r, depth - 1)),
        4 => and((0..2 + r.below(2))
            .map(|_| gen_bool(r, depth - 1))
            .collect()),
        5 => or((0..2 + r.below(2))
            .map(|_| gen_bool(r, depth - 1))
            .collect()),
        6 => cond(
            gen_bool(r, depth - 1),
            gen_bool(r, depth - 1),
            gen_bool(r, depth - 1),
        ),
        7 => {
            let op = r.pick(&[CompareOp::Eq, CompareOp::Ne, CompareOp::Lt, CompareOp::Ge]);
            cmp(op, gen_str(r, depth - 1), gen_str(r, depth - 1))
        }
        8 => cmp(CompareOp::Le, gen_int(r, depth - 1), gen_int(r, depth - 1)),
        9 => in_list(gen_str(r, depth - 1), gen_list(r, depth - 1)),
        10 => in_map(
            gen_str(r, depth - 1),
            if r.below(2) == 0 {
                f("rate")
            } else {
                f("req.headers")
            },
        ),
        11 => {
            let fun = r.pick(&[StringFn::StartsWith, StringFn::EndsWith, StringFn::Contains]);
            call(fun, gen_str(r, depth - 1), gen_str(r, depth - 1))
        }
        12 => ip_in(gen_str(r, depth - 1), gen_list(r, depth - 1)),
        _ => glob(gen_str(r, depth - 1), r.pick(PATTERNS)),
    }
}

fn gen_str(r: &mut Rng, depth: u32) -> Expr {
    match r.below(if depth == 0 { 2 } else { 4 }) {
        0 => s(&r.string(12)),
        1 => f(r.pick(STR_FIELDS)),
        2 => idx(
            f("req.headers"),
            s(r.pick(&["accept", "user-agent", "x-a"])),
        ),
        _ => cond(
            gen_bool(r, depth - 1),
            gen_str(r, depth - 1),
            gen_str(r, depth - 1),
        ),
    }
}

fn gen_int(r: &mut Rng, depth: u32) -> Expr {
    match r.below(if depth == 0 { 2 } else { 4 }) {
        0 => i(r.below(100) as i64 - 50),
        1 => f(r.pick(INT_FIELDS)),
        2 => size(gen_str(r, depth - 1)),
        _ => size(gen_list(r, depth - 1)),
    }
}

fn gen_list(r: &mut Rng, depth: u32) -> Expr {
    match r.below(if depth == 0 { 2 } else { 4 }) {
        0 => f(r.pick(LIST_FIELDS)),
        1 => named(r.pick(&["cidrs", "words"])),
        2 => list((0..r.below(4)).map(|_| gen_str(r, depth - 1)).collect()),
        _ => cond(
            gen_bool(r, depth - 1),
            gen_list(r, depth - 1),
            gen_list(r, depth - 1),
        ),
    }
}

/// A random activation within the §4.1 caps; `big` pushes sizes to the caps.
fn gen_activation(r: &mut Rng, big: bool) -> Activation {
    let scale = |cap: usize| if big { cap } else { cap.min(24) };
    let mut a = Activation::default();
    a.req.method = r.string(scale(32));
    a.req.host = r.string(scale(253));
    a.req.path = r.string(scale(8192));
    a.req.query = r.string(scale(8192));
    a.req.channel = r.string(scale(256));
    let headers = r.below(if big { 129 } else { 4 });
    for n in 0..headers {
        let mut k = r.string(scale(256).saturating_sub(4));
        k.push_str(&n.to_string());
        a.req.headers.insert(k, r.string(scale(8192)));
    }
    if r.below(2) == 0 {
        a.req.headers.insert("accept".into(), r.string(scale(8192)));
    }
    a.net.ip = if r.below(2) == 0 {
        "10.1.2.3".into()
    } else {
        r.string(scale(256))
    };
    a.net.country = r.string(scale(256));
    a.tls.ja4.value = r.string(scale(36));
    a.tls.version = r.string(scale(256));
    a.edge_tls.ciphers_sha1 = r.string(scale(40));
    a.identity.token.level = r.string(scale(256));
    a.risk.class = r.string(scale(256));
    a.route.name = r.string(scale(256));
    a.labels = (0..r.below(if big { 65 } else { 3 }))
        .map(|_| r.string(scale(256)))
        .collect();
    a.risk.reasons = (0..r.below(if big { 33 } else { 3 }))
        .map(|_| r.string(scale(256)))
        .collect();
    a.http.header_order = (0..r.below(if big { 129 } else { 3 }))
        .map(|_| r.string(scale(256)))
        .collect();
    a.rate = (0..r.below(if big { 65 } else { 3 }))
        .map(|n| (format!("l{n}"), (r.below(100) as f64) / 100.0))
        .collect::<BTreeMap<_, _>>();
    a
}

fn lists(r: &mut Rng, big: bool) -> NamedLists {
    let n = if big { 10_000 } else { 5 };
    NamedLists::new(BTreeMap::from([
        (
            "cidrs".to_string(),
            (0..n).map(|k| format!("10.{}.0.0/16", k % 256)).collect(),
        ),
        (
            "words".to_string(),
            (0..n)
                .map(|_| r.string(if big { 256 } else { 8 }))
                .collect(),
        ),
    ]))
}

fn missing(r: &mut Rng) -> MissingSet {
    let pool = [
        "tls",
        "tls.ja4",
        "http.header_order",
        "net.ip",
        "edge_tls",
        "identity.proof",
    ];
    MissingSet::new(pool.iter().filter(|_| r.below(3) == 0)).unwrap()
}

#[test]
fn runtime_steps_never_exceed_the_static_bound() {
    let mut r = Rng(0x5eed_1234_abcd_ef01);
    let mut checked = 0;
    let mut outcomes = [0usize; 4];
    for round in 0..3_000 {
        let big = round % 50 == 0;
        let e = gen_bool(&mut r, 4);
        let Ok(p) = Program::new(e) else {
            continue; // over the step bound: rejected at load time
        };
        let act = gen_activation(&mut r, big);
        let lists = lists(&mut r, big);
        let m = missing(&mut r);
        let (res, steps) = eval_steps(&p, &act, &m, &lists);
        assert!(
            steps <= p.max_steps(),
            "steps {steps} > bound {} for {:?}",
            p.max_steps(),
            p.root()
        );
        assert_ne!(res, EvalResult::Error(EvalError::StepLimit));
        if let EvalResult::Unknown(paths) = &res {
            assert!(!paths.is_empty());
            assert!(
                paths.iter().all(|p| m.is_missing(p)),
                "{paths:?} not under {m:?}"
            );
        }
        outcomes[match res {
            EvalResult::True => 0,
            EvalResult::False => 1,
            EvalResult::Unknown(_) => 2,
            EvalResult::Error(_) => 3,
        }] += 1;
        checked += 1;
    }
    assert!(checked > 2_000, "only {checked} programs accepted");
    assert!(
        outcomes.iter().all(|&n| n > 50),
        "every outcome exercised: {outcomes:?}"
    );
}
