//! Policy IR: wire (`morphgate.v1.PolicyExpr`, `policy_ir.proto`) to native
//! ([`mg_core::policy`]) conversion (docs/impl/phase1-spec.md §3.1, §5.6).
//!
//! [`decode_program`] validates a serialized `PolicyExpr` completely before
//! the Edge accepts it: `ir_version`, schema field paths, `has()` paths,
//! named-list references, the structural limits of §5.3 (nodes, depth,
//! literal sizes), well-typedness, and the static step bound, which is
//! recomputed and must equal the compiler's `max_steps` and be at most
//! [`mg_core::policy::MAX_STEPS`]. [`rule_from_proto`] does the same for a whole
//! `CompiledRule` (phase, mode, action and its Phase 1 params, rollout,
//! expiry). Any error rejects the rule, and with it the whole bundle.

use crate::v1;
use mg_core::enums::{Action, ChallengeType};
use mg_core::policy::{
    COMPUTED_MAP_INDEX, CompareOp, Expr, FieldId, Glob, GlobError, HasPath, ListId, Literal,
    MAX_DEPTH, MAX_LIST_LITERAL, MAX_NODES, MAX_STRING_LITERAL, NamedLists, Phase, Program,
    ProgramError, Rule, RuleAction, RuleMode, StringFn,
};
use mg_core::{Decision, policy};
use prost::Message;
use std::fmt;

/// The only IR version this build understands.
pub const IR_VERSION: u32 = 1;

/// Deepest IR tree that decodes from the wire: prost refuses more than 100
/// nested messages and every IR node below the root costs two (`Expr` and
/// its `Unary` / `Binary` / ... body; a literal leaf `Expr` and its
/// `Literal`), so a `PolicyExpr` deeper than this fails with
/// [`IrError::Decode`]. This is why §5.3 caps the depth at 50: it equals
/// [`mg_core::policy::MAX_DEPTH`] (asserted below), so every tree the Go
/// compiler accepts decodes here.
pub const PROST_MAX_IR_DEPTH: usize = 50;
const _: () = assert!(PROST_MAX_IR_DEPTH == MAX_DEPTH);

/// Why an IR expression or compiled rule was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IrError {
    /// The bytes are not a `PolicyExpr`.
    Decode(prost::DecodeError),
    /// `ir_version` other than 1.
    Version(u32),
    /// A `field` path that is not a readable schema field.
    UnknownField(String),
    /// A `has` path that is not a schema field of depth >= 2.
    BadHas(String),
    /// `list("name")` names no list of the bundle.
    UnknownList(String),
    /// A §5.3 structural limit or the step bound was exceeded.
    Limits(&'static str),
    /// Anything else that is not a well-formed, well-typed rule.
    Malformed(&'static str),
    /// The recomputed static step bound differs from the declared one.
    Steps { declared: u64, computed: u64 },
}

impl fmt::Display for IrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(e) => write!(f, "policy IR does not decode: {e}"),
            Self::Version(v) => write!(f, "unsupported policy IR version {v}"),
            Self::UnknownField(p) => write!(f, "unknown policy field {p:?}"),
            Self::BadHas(p) => write!(f, "has() on {p:?}, which is not a schema field"),
            Self::UnknownList(n) => write!(f, "unknown named list {n:?}"),
            Self::Limits(what) => write!(f, "policy IR limit exceeded: {what}"),
            Self::Malformed(what) => write!(f, "malformed policy IR: {what}"),
            Self::Steps { declared, computed } => write!(
                f,
                "policy IR step bound mismatch: declared {declared}, computed {computed}"
            ),
        }
    }
}

impl std::error::Error for IrError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Decode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ProgramError> for IrError {
    fn from(e: ProgramError) -> Self {
        match e {
            ProgramError::Limits(w) => Self::Limits(w),
            ProgramError::Malformed(w) => Self::Malformed(w),
        }
    }
}

/// Decodes and validates a serialized `PolicyExpr` (§5.3 limits, schema
/// paths, list names, `max_steps` recomputed: it must equal the declared
/// value and be at most [`mg_core::policy::MAX_STEPS`]).
pub fn decode_program(bytes: &[u8], lists: &NamedLists) -> Result<Program, IrError> {
    let expr = v1::PolicyExpr::decode(bytes).map_err(IrError::Decode)?;
    program_from_proto(&expr, lists)
}

/// Like [`decode_program`], from an already decoded message.
pub fn program_from_proto(p: &v1::PolicyExpr, lists: &NamedLists) -> Result<Program, IrError> {
    if p.ir_version != IR_VERSION {
        return Err(IrError::Version(p.ir_version));
    }
    let root = p.root.as_ref().ok_or(IrError::Malformed("missing root"))?;
    let mut nodes = 0;
    let expr = convert(root, 1, &mut nodes, lists)?;
    let computed = policy::max_steps(&expr);
    if computed != p.max_steps {
        return Err(IrError::Steps {
            declared: p.max_steps,
            computed,
        });
    }
    Ok(Program::new(expr)?)
}

type Child = Option<Box<v1::Expr>>;

fn convert(
    e: &v1::Expr,
    depth: usize,
    nodes: &mut usize,
    lists: &NamedLists,
) -> Result<Expr, IrError> {
    use v1::expr::Kind;
    *nodes += 1;
    if *nodes > MAX_NODES {
        return Err(IrError::Limits("more than 4096 nodes"));
    }
    if depth > MAX_DEPTH {
        return Err(IrError::Limits("nesting deeper than 50"));
    }
    let mut sub = |c: &v1::Expr| convert(c, depth + 1, nodes, lists);
    let kind = e
        .kind
        .as_ref()
        .ok_or(IrError::Malformed("empty expression node"))?;
    Ok(match kind {
        Kind::Literal(l) => Expr::Literal(literal(l)?),
        Kind::Field(p) => {
            Expr::Field(FieldId::from_path(p).ok_or_else(|| IrError::UnknownField(p.clone()))?)
        }
        Kind::Has(p) => Expr::Has(HasPath::new(p).ok_or_else(|| IrError::BadHas(p.clone()))?),
        Kind::NamedList(name) => {
            if !lists.contains(name) {
                return Err(IrError::UnknownList(name.clone()));
            }
            Expr::NamedList(ListId::new(name.clone()))
        }
        Kind::List(l) => {
            if l.elements.len() > MAX_LIST_LITERAL {
                return Err(IrError::Limits("list literal with more than 1000 elements"));
            }
            Expr::List(l.elements.iter().map(&mut sub).collect::<Result<_, _>>()?)
        }
        Kind::Not(u) => Expr::Not(Box::new(sub(operand(&u.arg)?)?)),
        Kind::Size(u) => Expr::Size(Box::new(sub(operand(&u.arg)?)?)),
        Kind::And(n) | Kind::Or(n) => {
            if n.args.len() < 2 {
                return Err(IrError::Malformed("&& / || need at least two arguments"));
            }
            let args = n.args.iter().map(&mut sub).collect::<Result<_, _>>()?;
            if matches!(kind, Kind::And(_)) {
                Expr::And(args)
            } else {
                Expr::Or(args)
            }
        }
        Kind::Cond(c) => {
            let cond = sub(operand(&c.cond)?)?;
            let then = sub(operand(&c.then_expr)?)?;
            let other = sub(operand(&c.else_expr)?)?;
            Expr::Cond(Box::new(cond), Box::new(then), Box::new(other))
        }
        Kind::Compare(c) => {
            let op = match v1::CompareOp::try_from(c.op) {
                Ok(v1::CompareOp::Eq) => CompareOp::Eq,
                Ok(v1::CompareOp::Ne) => CompareOp::Ne,
                Ok(v1::CompareOp::Lt) => CompareOp::Lt,
                Ok(v1::CompareOp::Le) => CompareOp::Le,
                Ok(v1::CompareOp::Gt) => CompareOp::Gt,
                Ok(v1::CompareOp::Ge) => CompareOp::Ge,
                _ => return Err(IrError::Malformed("unknown comparison operator")),
            };
            let (l, r) = (sub(operand(&c.lhs)?)?, sub(operand(&c.rhs)?)?);
            Expr::Compare(op, Box::new(l), Box::new(r))
        }
        Kind::InList(b) | Kind::InMap(b) | Kind::IndexMap(b) | Kind::IpIn(b) => {
            let (l, r) = (sub(operand(&b.lhs)?)?, sub(operand(&b.rhs)?)?);
            // Ruling I-20: only a map field is indexed. Checked here, before
            // the step bound is compared, so that a computed-map index is
            // always reported as such (`Program::new` enforces it as well).
            if matches!(kind, Kind::IndexMap(_)) && !matches!(l, Expr::Field(_)) {
                return Err(IrError::Malformed(COMPUTED_MAP_INDEX));
            }
            let (l, r) = (Box::new(l), Box::new(r));
            match kind {
                Kind::InList(_) => Expr::InList(l, r),
                Kind::InMap(_) => Expr::InMap(l, r),
                Kind::IndexMap(_) => Expr::IndexMap(l, r),
                _ => Expr::IpIn(l, r),
            }
        }
        Kind::StringCall(c) => {
            let fun = match v1::StringFunction::try_from(c.function) {
                Ok(v1::StringFunction::StartsWith) => StringFn::StartsWith,
                Ok(v1::StringFunction::EndsWith) => StringFn::EndsWith,
                Ok(v1::StringFunction::Contains) => StringFn::Contains,
                _ => return Err(IrError::Malformed("unknown string function")),
            };
            let (t, a) = (sub(operand(&c.target)?)?, sub(operand(&c.arg)?)?);
            Expr::StringCall(fun, Box::new(t), Box::new(a))
        }
        Kind::Glob(g) => {
            let pattern = Glob::new(&g.pattern).map_err(|e| match e {
                GlobError::Empty => IrError::Malformed("empty glob pattern"),
                GlobError::TooLong => IrError::Limits("glob pattern longer than 4096 bytes"),
            })?;
            Expr::Glob(Box::new(sub(operand(&g.subject)?)?), pattern)
        }
    })
}

fn operand(c: &Child) -> Result<&v1::Expr, IrError> {
    c.as_deref().ok_or(IrError::Malformed("missing operand"))
}

fn literal(l: &v1::Literal) -> Result<Literal, IrError> {
    use v1::literal::Value;
    Ok(
        match l
            .value
            .as_ref()
            .ok_or(IrError::Malformed("empty literal"))?
        {
            Value::BoolValue(b) => Literal::Bool(*b),
            Value::IntValue(i) => Literal::Int(*i),
            Value::DoubleValue(d) => Literal::Double(*d),
            Value::StringValue(s) => {
                if s.len() > MAX_STRING_LITERAL {
                    return Err(IrError::Limits("string literal longer than 4096 bytes"));
                }
                Literal::Str(s.clone())
            }
        },
    )
}

/// Parameter keys of a Phase 1 rule action (§3.2): `type` (challenge),
/// `label` (tag), `limiter` and `retry_after_s` (rate_limit).
fn allowed_params(action: Action) -> &'static [&'static str] {
    match action {
        Action::Challenge => &["type"],
        Action::Tag => &["label"],
        Action::RateLimit => &["limiter", "retry_after_s"],
        _ => &[],
    }
}

/// Default `Retry-After` of a `rate_limit` rule without `retry_after_s`.
pub const DEFAULT_RULE_RETRY_AFTER_S: u32 = 60;

/// Rule ids as the policy compiler accepts them: `[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?`.
fn valid_rule_id(id: &str) -> bool {
    let ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let bytes = id.as_bytes();
    (1..=64).contains(&bytes.len())
        && ok(bytes[0])
        && ok(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|&b| ok(b) || matches!(b, b'.' | b'_' | b'-'))
}

/// Converts a full `CompiledRule` (phase, mode, action and params per §3.2,
/// rollout, expiry). Rejects `ir_version != 1`, unknown or misplaced params,
/// `tarpit` (D-09) and `disabled` rules (the builder never emits them).
pub fn rule_from_proto(r: &v1::CompiledRule, lists: &NamedLists) -> Result<Rule, IrError> {
    use IrError::Malformed;
    if r.ir_version != IR_VERSION {
        return Err(IrError::Version(r.ir_version));
    }
    if !valid_rule_id(&r.id) {
        return Err(Malformed("invalid rule id"));
    }
    let phase: Phase = r
        .phase
        .parse()
        .map_err(|_| Malformed("unknown rule phase"))?;
    let mode = match r.mode.as_str() {
        "enforce" => RuleMode::Enforce,
        "dry_run" => RuleMode::DryRun,
        "disabled" => return Err(Malformed("disabled rules are not bundled")),
        _ => return Err(Malformed("unknown rule mode")),
    };
    let rollout_percent =
        u8::try_from(r.rollout_percent).map_err(|_| Malformed("rollout_percent above 100"))?;
    if rollout_percent > 100 {
        return Err(Malformed("rollout_percent above 100"));
    }
    let action = Action::from_proto(r.action).ok_or(Malformed("unknown rule action"))?;
    if r.params
        .keys()
        .any(|k| !allowed_params(action).contains(&k.as_str()))
    {
        return Err(Malformed("unknown or misplaced rule param"));
    }
    let param = |k: &str| r.params.get(k).map(String::as_str);
    let action = match action {
        Action::Allow => RuleAction::Allow,
        Action::Log => RuleAction::Log,
        Action::Block => RuleAction::Block,
        Action::Tag => {
            let label = param("label").ok_or(Malformed("tag rule without a label"))?;
            if !Decision::is_valid_tag(label) {
                return Err(Malformed("tag label is not [a-z0-9_.-]{1,32}"));
            }
            RuleAction::Tag {
                label: label.to_string(),
            }
        }
        Action::RateLimit => {
            let retry_after_s = match param("retry_after_s") {
                None => DEFAULT_RULE_RETRY_AFTER_S,
                Some(v) => {
                    parse_decimal_u32(v).ok_or(Malformed("retry_after_s is not a number"))?
                }
            };
            RuleAction::RateLimit { retry_after_s }
        }
        Action::Challenge => RuleAction::Challenge(match param("type") {
            None | Some("invisible") => ChallengeType::Invisible,
            Some("pow") => ChallengeType::Pow,
            // Runs as pow in Phase 1 (D-08); the engine annotates the hit.
            Some("interactive") => ChallengeType::Interactive,
            Some(_) => return Err(Malformed("unknown challenge type")),
        }),
        Action::Tarpit => return Err(Malformed("tarpit is not available in Phase 1")),
        Action::Unspecified => return Err(Malformed("rule without an action")),
    };
    let program = decode_program(&r.expr_ir, lists)?;
    Ok(Rule {
        id: r.id.clone(),
        phase,
        priority: r.priority,
        program,
        action,
        mode,
        rollout_percent,
        expires_at_ms: r.expires_at_ms,
    })
}

/// Plain decimal digits only (no sign, no spaces), within `u32`.
fn parse_decimal_u32(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

#[cfg(test)]
mod tests {
    //! Load-time validation: every limit, malformed and ill-typed IR, the
    //! step bound recomputation, `CompiledRule` conversion, and random input.

    use super::*;
    use std::collections::BTreeMap;
    use v1::expr::Kind;

    fn node(k: Kind) -> v1::Expr {
        v1::Expr { kind: Some(k) }
    }
    fn bx(e: v1::Expr) -> Option<Box<v1::Expr>> {
        Some(Box::new(e))
    }
    fn lit(v: v1::literal::Value) -> v1::Expr {
        node(Kind::Literal(v1::Literal { value: Some(v) }))
    }
    fn s(v: &str) -> v1::Expr {
        lit(v1::literal::Value::StringValue(v.into()))
    }
    fn i(v: i64) -> v1::Expr {
        lit(v1::literal::Value::IntValue(v))
    }
    fn t() -> v1::Expr {
        lit(v1::literal::Value::BoolValue(true))
    }
    fn f(p: &str) -> v1::Expr {
        node(Kind::Field(p.into()))
    }
    fn has(p: &str) -> v1::Expr {
        node(Kind::Has(p.into()))
    }
    fn not(x: v1::Expr) -> v1::Expr {
        node(Kind::Not(Box::new(v1::Unary { arg: bx(x) })))
    }
    fn and(xs: Vec<v1::Expr>) -> v1::Expr {
        node(Kind::And(v1::Nary { args: xs }))
    }
    fn or(xs: Vec<v1::Expr>) -> v1::Expr {
        node(Kind::Or(v1::Nary { args: xs }))
    }
    fn cmp(op: v1::CompareOp, l: v1::Expr, r: v1::Expr) -> v1::Expr {
        node(Kind::Compare(Box::new(v1::Compare {
            op: op as i32,
            lhs: bx(l),
            rhs: bx(r),
        })))
    }
    fn bin(k: fn(Box<v1::Binary>) -> Kind, l: v1::Expr, r: v1::Expr) -> v1::Expr {
        node(k(Box::new(v1::Binary {
            lhs: bx(l),
            rhs: bx(r),
        })))
    }
    fn call(fun: v1::StringFunction, x: v1::Expr, a: v1::Expr) -> v1::Expr {
        node(Kind::StringCall(Box::new(v1::StringCall {
            function: fun as i32,
            target: bx(x),
            arg: bx(a),
        })))
    }
    fn glob(x: v1::Expr, p: &str) -> v1::Expr {
        node(Kind::Glob(Box::new(v1::Glob {
            subject: bx(x),
            pattern: p.into(),
        })))
    }
    fn list(xs: Vec<v1::Expr>) -> v1::Expr {
        node(Kind::List(v1::ListLiteral { elements: xs }))
    }
    fn named(n: &str) -> v1::Expr {
        node(Kind::NamedList(n.into()))
    }

    fn lists() -> NamedLists {
        NamedLists::new(BTreeMap::from([(
            "owner_cidrs".to_string(),
            vec!["10.0.0.0/8".to_string()],
        )]))
    }

    /// A `PolicyExpr` whose `max_steps` is the recomputed bound (read back
    /// from the mismatch error of a first attempt with 0).
    fn expr(root: v1::Expr) -> v1::PolicyExpr {
        let mut p = v1::PolicyExpr {
            ir_version: 1,
            root: Some(root),
            fields: vec![],
            max_steps: 0,
        };
        if let Err(IrError::Steps { computed, .. }) = program_from_proto(&p, &lists()) {
            p.max_steps = computed;
        }
        p
    }

    fn load(root: v1::Expr) -> Result<Program, IrError> {
        decode_program(&expr(root).encode_to_vec(), &lists())
    }

    #[test]
    fn valid_expressions_load_with_their_exact_step_bound() {
        use v1::CompareOp as Op;
        // req.headers["content-type"].startsWith("multipart/"):
        // 1 + ⌈(8192 + 10)/64⌉ = 130, + index_map (2 + 1 + 1), + literal 1.
        let e = call(
            v1::StringFunction::StartsWith,
            bin(Kind::IndexMap, f("req.headers"), s("content-type")),
            s("multipart/"),
        );
        let p = load(e).unwrap();
        assert_eq!(p.max_steps(), 135);
        assert_eq!(p.fields(), ["req.headers"]);
        // The docs/06 default-deny rule.
        let e = and(vec![
            bin(
                Kind::InList,
                f("route.env"),
                list(vec![s("staging"), s("test"), s("dev")]),
            ),
            cmp(Op::Ne, f("risk.class"), s("AUTHORIZED_AGENT")),
            or(vec![
                not(has("net.ip")),
                not(bin(Kind::IpIn, f("net.ip"), named("owner_cidrs"))),
            ]),
        ]);
        let p = load(e).unwrap();
        assert_eq!(p.fields(), ["net.ip", "risk.class", "route.env"]);
        assert!(p.max_steps() > 10_000 && p.max_steps() <= policy::MAX_STEPS);
        // Every node kind once.
        let e = and(vec![
            bin(Kind::InMap, s("login"), f("rate")),
            cmp(
                Op::Gt,
                bin(Kind::IndexMap, f("rate"), s("login")),
                lit(v1::literal::Value::DoubleValue(0.8)),
            ),
            cmp(
                Op::Ge,
                node(Kind::Size(Box::new(v1::Unary {
                    arg: bx(f("labels")),
                }))),
                i(0),
            ),
            node(Kind::Cond(Box::new(v1::Cond {
                cond: bx(has("tls.ja4")),
                then_expr: bx(bin(Kind::InList, f("tls.ja4.value"), named("owner_cidrs"))),
                else_expr: bx(t()),
            }))),
            glob(f("req.path"), "/admin/**"),
            call(v1::StringFunction::Contains, f("req.query"), s("debug=")),
        ]);
        assert!(load(e).is_ok());
    }

    #[test]
    fn version_and_decode_errors() {
        let mut p = expr(t());
        p.ir_version = 2;
        assert!(matches!(
            program_from_proto(&p, &lists()),
            Err(IrError::Version(2))
        ));
        p.ir_version = 0;
        assert!(matches!(
            program_from_proto(&p, &lists()),
            Err(IrError::Version(0))
        ));
        assert!(matches!(
            decode_program(&[0xff, 0xff, 0xff], &lists()),
            Err(IrError::Decode(_))
        ));
        let no_root = v1::PolicyExpr {
            ir_version: 1,
            ..Default::default()
        };
        assert!(matches!(
            program_from_proto(&no_root, &lists()),
            Err(IrError::Malformed(_))
        ));
        // An empty buffer is ir_version 0.
        assert!(matches!(
            decode_program(&[], &lists()),
            Err(IrError::Version(0))
        ));
    }

    #[test]
    fn schema_paths_and_lists() {
        let unknown = |e| matches!(load(e), Err(IrError::UnknownField(_)));
        assert!(unknown(cmp(v1::CompareOp::Eq, f("net.ipv4"), s(""))));
        assert!(
            unknown(cmp(v1::CompareOp::Eq, f("tls.ja4"), s(""))),
            "a struct is not a value"
        );
        assert!(unknown(cmp(
            v1::CompareOp::Eq,
            f("req.headers.accept"),
            s("")
        )));
        for bad in ["rate", "tls", "req.headers.accept", "net.ipx", ""] {
            assert!(
                matches!(load(has(bad)), Err(IrError::BadHas(p)) if p == bad),
                "{bad}"
            );
        }
        assert!(load(has("identity.proof")).is_ok());
        assert!(matches!(
            load(bin(Kind::InList, s("x"), named("nope"))),
            Err(IrError::UnknownList(n)) if n == "nope"
        ));
    }

    #[test]
    fn structural_limits() {
        let limits = |e| matches!(load(e), Err(IrError::Limits(_)));
        // Depth (§5.3: 50). prost's fixed decode recursion limit (100 nested
        // messages, two per IR node) refuses wire trees deeper than 50, and
        // the converted tree is held to the same limit. The deepest tree
        // that still decodes has a literal leaf at depth 50: 50 `Expr` + 49
        // `Unary` + 1 `Literal` = 100 nested messages.
        let deep = |n: usize| (1..n).fold(t(), |e, _| not(e));
        assert!(load(deep(MAX_DEPTH)).is_ok());
        assert!(matches!(load(deep(MAX_DEPTH + 1)), Err(IrError::Decode(_))));
        // A `has` leaf (no body message) at depth 51 is 51 `Expr` + 50
        // `Unary` = 101 messages: refused by prost too.
        let deep_has = (1..MAX_DEPTH + 1).fold(has("net.ip"), |e, _| not(e));
        assert!(matches!(load(deep_has), Err(IrError::Decode(_))));
        let p = expr(deep(MAX_DEPTH));
        assert_eq!(p.max_steps, 50);
        assert!(program_from_proto(&p, &lists()).is_ok());
        let p = expr(deep(MAX_DEPTH + 1));
        assert!(
            matches!(program_from_proto(&p, &lists()), Err(IrError::Limits(_))),
            "51 levels are refused without the wire as well"
        );
        // Nodes: 1 `or` + 4095 leaves = 4096 nodes.
        let wide = |n: usize| or((0..n).map(|_| has("net.ip")).collect());
        assert!(load(wide(4095)).is_ok());
        assert!(limits(wide(4096)));
        assert!(limits(cmp(
            v1::CompareOp::Eq,
            f("req.method"),
            s(&"x".repeat(4097))
        )));
        assert!(
            load(cmp(
                v1::CompareOp::Eq,
                f("req.method"),
                s(&"x".repeat(4096))
            ))
            .is_ok()
        );
        let big_list = |n: usize| bin(Kind::InList, s("x"), list((0..n).map(|_| s("x")).collect()));
        assert!(load(big_list(1000)).is_ok());
        assert!(limits(big_list(1001)));
        assert!(limits(glob(f("req.method"), &"a".repeat(4097))));
        // §5.2: 7 globs of 32-byte patterns on req.path exceed 100,000 steps; 6 do not.
        let p32 = format!("/{}*", "a".repeat(30));
        let globs = |n: usize| and((0..n).map(|_| glob(f("req.path"), &p32)).collect());
        assert_eq!(load(globs(6)).unwrap().max_steps(), 98_317);
        let mut p = expr(globs(7));
        assert_eq!(p.max_steps, 114_703, "declared = computed");
        assert!(matches!(
            program_from_proto(&p, &lists()),
            Err(IrError::Limits(_))
        ));
        p.max_steps = 99_999;
        assert!(matches!(
            program_from_proto(&p, &lists()),
            Err(IrError::Steps {
                declared: 99_999,
                computed: 114_703
            })
        ));
    }

    #[test]
    fn declared_steps_must_match() {
        let mut p = expr(cmp(v1::CompareOp::Eq, f("req.path"), s("/x")));
        let good = p.max_steps;
        assert!(program_from_proto(&p, &lists()).is_ok());
        for bad in [0, good - 1, good + 1, u64::MAX] {
            p.max_steps = bad;
            assert!(matches!(
                program_from_proto(&p, &lists()),
                Err(IrError::Steps { declared, computed }) if declared == bad && computed == good
            ));
        }
    }

    #[test]
    fn malformed_and_ill_typed_trees() {
        let malformed = |e| matches!(load(e), Err(IrError::Malformed(_)));
        assert!(malformed(v1::Expr { kind: None }));
        assert!(malformed(node(Kind::Literal(v1::Literal { value: None }))));
        assert!(malformed(node(Kind::Not(Box::new(v1::Unary {
            arg: None
        })))));
        assert!(malformed(and(vec![t()])), "one-argument and");
        assert!(malformed(or(vec![])));
        let bad_op = node(Kind::Compare(Box::new(v1::Compare {
            op: 0,
            lhs: bx(i(1)),
            rhs: bx(i(1)),
        })));
        assert!(malformed(bad_op));
        let bad_op = node(Kind::Compare(Box::new(v1::Compare {
            op: 42,
            lhs: bx(i(1)),
            rhs: bx(i(1)),
        })));
        assert!(malformed(bad_op));
        assert!(malformed(call(
            v1::StringFunction::Unspecified,
            s("a"),
            s("b")
        )));
        assert!(malformed(glob(f("req.path"), "")));
        // Types.
        assert!(malformed(f("req.path")), "non-bool root");
        assert!(malformed(cmp(v1::CompareOp::Eq, i(1), s("1"))));
        assert!(malformed(cmp(
            v1::CompareOp::Eq,
            i(1),
            lit(v1::literal::Value::DoubleValue(1.0))
        )));
        assert!(malformed(cmp(v1::CompareOp::Lt, t(), t())), "bool ordering");
        assert!(malformed(bin(Kind::InList, i(1), list(vec![s("a")]))));
        assert!(
            malformed(bin(Kind::InList, i(1), list(vec![i(1), s("a")]))),
            "heterogeneous list"
        );
        assert!(
            malformed(cmp(v1::CompareOp::Eq, f("labels"), f("labels"))),
            "list equality"
        );
        assert!(malformed(bin(Kind::InMap, i(1), f("rate"))));
        assert!(malformed(glob(f("risk.score"), "*")));
    }

    fn cond(c: v1::Expr, a: v1::Expr, b: v1::Expr) -> v1::Expr {
        node(Kind::Cond(Box::new(v1::Cond {
            cond: bx(c),
            then_expr: bx(a),
            else_expr: bx(b),
        })))
    }

    /// Ruling I-20: an index or select on a map computed by `?:` is rejected
    /// as such, whatever step bound is declared (137 is what the compiler
    /// emitted for it before the ruling); indexing inside each branch and
    /// key presence on a computed map still load.
    #[test]
    fn computed_map_index_is_rejected() {
        use v1::CompareOp as Op;
        let computed = |m: &str| cond(f("net.tor"), f(m), f(m));
        let headers = cmp(
            Op::Eq,
            bin(Kind::IndexMap, computed("req.headers"), s("accept")),
            s("text/html"),
        );
        for declared in [137, 0, u64::MAX] {
            let p = v1::PolicyExpr {
                ir_version: 1,
                root: Some(headers.clone()),
                fields: vec![],
                max_steps: declared,
            };
            assert_eq!(
                decode_program(&p.encode_to_vec(), &lists()).unwrap_err(),
                IrError::Malformed(COMPUTED_MAP_INDEX),
                "declared {declared}"
            );
        }
        let rate = cmp(
            Op::Gt,
            bin(Kind::IndexMap, computed("rate"), s("login")),
            lit(v1::literal::Value::DoubleValue(0.5)),
        );
        let nested = cond(
            f("net.tor"),
            f("req.headers"),
            cond(t(), f("req.headers"), f("req.headers")),
        );
        let nested = and(vec![
            has("net.ip"),
            cmp(Op::Eq, bin(Kind::IndexMap, nested, s("a")), s("b")),
        ]);
        // An index whose map is itself an index result is not a field either
        // (ill-typed as well, but rejected as a computed map first).
        let index_of_index = cmp(
            Op::Eq,
            bin(
                Kind::IndexMap,
                bin(Kind::IndexMap, f("req.headers"), s("a")),
                s("b"),
            ),
            s("c"),
        );
        for e in [rate, nested, index_of_index] {
            assert_eq!(load(e).unwrap_err(), IrError::Malformed(COMPUTED_MAP_INDEX));
        }
        let branches = cmp(
            Op::Eq,
            cond(
                f("net.tor"),
                bin(Kind::IndexMap, f("req.headers"), s("accept")),
                bin(Kind::IndexMap, f("req.headers"), s("accept")),
            ),
            s("text/html"),
        );
        assert_eq!(load(branches).unwrap().max_steps(), 137);
        assert!(load(bin(Kind::InMap, s("accept"), computed("req.headers"))).is_ok());
    }

    fn rule(action: Action, params: &[(&str, &str)]) -> v1::CompiledRule {
        v1::CompiledRule {
            id: "r-1".into(),
            phase: "bot".into(),
            priority: -3,
            expr_source: "true".into(),
            ir_version: 1,
            expr_ir: expr(t()).encode_to_vec(),
            action: action.to_proto(),
            params: params
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            mode: "enforce".into(),
            rollout_percent: 100,
            expires_at_ms: 0,
            locked: false,
        }
    }

    #[test]
    fn compiled_rules() {
        let l = lists();
        let conv = |r: &v1::CompiledRule| rule_from_proto(r, &l);
        let r = conv(&rule(Action::Block, &[])).unwrap();
        assert_eq!(
            (r.id.as_str(), r.phase, r.priority, r.mode),
            ("r-1", Phase::Bot, -3, RuleMode::Enforce)
        );
        assert_eq!(r.action, RuleAction::Block);
        assert_eq!(
            conv(&rule(Action::Allow, &[])).unwrap().action,
            RuleAction::Allow
        );
        assert_eq!(
            conv(&rule(Action::Log, &[])).unwrap().action,
            RuleAction::Log
        );
        assert_eq!(
            conv(&rule(Action::Tag, &[("label", "old_tls.v1")]))
                .unwrap()
                .action,
            RuleAction::Tag {
                label: "old_tls.v1".into()
            }
        );
        assert_eq!(
            conv(&rule(Action::RateLimit, &[])).unwrap().action,
            RuleAction::RateLimit { retry_after_s: 60 }
        );
        assert_eq!(
            conv(&rule(
                Action::RateLimit,
                &[("limiter", "login_ip"), ("retry_after_s", "30")]
            ))
            .unwrap()
            .action,
            RuleAction::RateLimit { retry_after_s: 30 }
        );
        for (ty, want) in [
            (None, ChallengeType::Invisible),
            (Some("invisible"), ChallengeType::Invisible),
            (Some("pow"), ChallengeType::Pow),
            (Some("interactive"), ChallengeType::Interactive),
        ] {
            let params: Vec<(&str, &str)> = ty.map(|t| ("type", t)).into_iter().collect();
            assert_eq!(
                conv(&rule(Action::Challenge, &params)).unwrap().action,
                RuleAction::Challenge(want)
            );
        }
        for phase in [
            "identity",
            "protocol",
            "rate_limit",
            "bot",
            "custom",
            "default",
        ] {
            let mut r = rule(Action::Block, &[]);
            r.phase = phase.into();
            assert_eq!(conv(&r).unwrap().phase.as_str(), phase);
        }
        let mut r = rule(Action::Block, &[]);
        r.mode = "dry_run".into();
        r.rollout_percent = 0;
        r.expires_at_ms = 42;
        let r = conv(&r).unwrap();
        assert_eq!(
            (r.mode, r.rollout_percent, r.expires_at_ms),
            (RuleMode::DryRun, 0, 42)
        );
    }

    #[test]
    fn compiled_rule_rejections() {
        let l = lists();
        let rejected = |r: v1::CompiledRule| rule_from_proto(&r, &l).is_err();
        let with = |f: &dyn Fn(&mut v1::CompiledRule)| {
            let mut r = rule(Action::Block, &[]);
            f(&mut r);
            r
        };
        assert!(matches!(
            rule_from_proto(&with(&|r| r.ir_version = 0), &l),
            Err(IrError::Version(0))
        ));
        assert!(rejected(with(&|r| r.mode = "disabled".into())));
        assert!(rejected(with(&|r| r.mode = String::new())));
        assert!(rejected(with(&|r| r.phase = "pre".into())));
        assert!(rejected(with(&|r| r.rollout_percent = 101)));
        assert!(rejected(with(&|r| r.rollout_percent = 256)));
        assert!(rejected(with(&|r| r.id = String::new())));
        assert!(rejected(with(&|r| r.id = "Upper".into())));
        assert!(rejected(with(&|r| r.id = "a".repeat(65))));
        assert!(rejected(with(&|r| r.action = 99)));
        assert!(rejected(with(&|r| r.expr_ir = vec![1, 2, 3])));
        assert!(rejected(rule(Action::Tarpit, &[])), "D-09");
        assert!(rejected(rule(Action::Unspecified, &[])));
        // Params: unknown, misplaced, missing, invalid.
        assert!(rejected(rule(Action::Block, &[("status", "403")])));
        assert!(rejected(rule(Action::Block, &[("label", "x")])));
        assert!(rejected(rule(Action::Challenge, &[("label", "x")])));
        assert!(rejected(rule(Action::Tag, &[])));
        assert!(rejected(rule(Action::Tag, &[("label", "Bad Label")])));
        assert!(rejected(rule(Action::Tag, &[("label", &"x".repeat(33))])));
        assert!(rejected(rule(
            Action::Challenge,
            &[("type", "attestation")]
        )));
        assert!(rejected(rule(Action::Challenge, &[("type", "")])));
        assert!(rejected(rule(
            Action::RateLimit,
            &[("retry_after_s", "-1")]
        )));
        assert!(rejected(rule(
            Action::RateLimit,
            &[("retry_after_s", "+5")]
        )));
        assert!(rejected(rule(
            Action::RateLimit,
            &[("retry_after_s", "99999999999")]
        )));
        assert!(rejected(rule(Action::Tarpit, &[("delay_ms", "2000")])));
    }

    /// Spec §2.4: 10,000+ deterministic random inputs (raw bytes and bit-flipped
    /// valid encodings) return errors, never panic.
    #[test]
    fn random_inputs_do_not_panic() {
        let l = lists();
        let mut state: u64 = 0x6a09_e667_f3bc_c908;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let valid = expr(and(vec![
            glob(f("req.path"), "/a/**"),
            bin(Kind::IpIn, f("net.ip"), named("owner_cidrs")),
            cmp(v1::CompareOp::Ge, f("risk.score"), i(60)),
        ]))
        .encode_to_vec();
        let mut ok = 0;
        for n in 0..12_000 {
            let bytes: Vec<u8> = if n % 2 == 0 {
                let len = (next() % 96) as usize;
                (0..len).map(|_| next() as u8).collect()
            } else {
                let mut b = valid.clone();
                for _ in 0..(1 + next() % 3) {
                    let pos = (next() as usize) % b.len();
                    b[pos] ^= 1 << (next() % 8);
                }
                b
            };
            if decode_program(&bytes, &l).is_ok() {
                ok += 1;
            }
        }
        assert!(ok < 12_000);
        // Deeply nested wire input stops at prost's recursion limit or ours.
        let mut deep = t();
        for _ in 0..200 {
            deep = not(deep);
        }
        let bytes = v1::PolicyExpr {
            ir_version: 1,
            root: Some(deep),
            ..Default::default()
        }
        .encode_to_vec();
        assert!(decode_program(&bytes, &l).is_err());
    }
}
