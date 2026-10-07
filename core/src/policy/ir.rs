//! Native policy IR (mirrors `proto/morphgate/v1/policy_ir.proto`) with
//! load-time validation and the static step bound of
//! docs/impl/phase1-spec.md §5.3.
//!
//! `mg-proto` converts the wire form into an [`Expr`] (resolving field paths
//! to [`FieldId`], `has()` paths to [`HasPath`], list names to [`ListId`] and
//! glob patterns to [`Glob`]) and calls [`Program::new`], which enforces the
//! structural limits, type-checks the tree and computes [`max_steps`].

use super::fields::{FieldId, FieldType, HasPath};
use super::glob::Glob;
use std::fmt;

/// Upper bound of the static step bound of an accepted rule (ADR-0006 decision 8).
pub const MAX_STEPS: u64 = 100_000;
/// Most IR nodes in one expression.
pub const MAX_NODES: usize = 4096;
/// Deepest nesting of one expression (the root is at depth 1). §5.3 sets it
/// to 50 because `mg-proto` decodes the wire form with prost, whose fixed
/// recursion limit of 100 nested messages (an IR node below the root costs
/// two: `Expr` and its body message) admits no deeper tree.
pub const MAX_DEPTH: usize = 50;
/// Longest string literal, in bytes.
pub const MAX_STRING_LITERAL: usize = 4096;
/// Most elements of one list literal.
pub const MAX_LIST_LITERAL: usize = 1000;
/// `S(named_list)`: most entries of a named list (§4.1).
pub const NAMED_LIST_CAP: u64 = 10_000;
/// `S(req.headers[k])`: largest header value (§4.1).
const HEADER_VALUE_CAP: u64 = 8192;
/// The [`ProgramError::Malformed`] reason for `index_map` on anything but a
/// map field (ruling I-20: an index or select on a map computed by `?:` is
/// rejected; `c ? m[k] : m[k]` expresses the same).
pub const COMPUTED_MAP_INDEX: &str = "index on a computed map (only a map field can be indexed)";

/// A scalar literal.
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    Bool(bool),
    Int(i64),
    Double(f64),
    Str(String),
}

/// `CompareOp` of the IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// `StringFunction` of the IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringFn {
    StartsWith,
    EndsWith,
    Contains,
}

/// A reference to a named list of the site bundle (`list("name")`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListId(String);

impl ListId {
    /// A reference to the list called `name` (existence is checked by the
    /// IR decoder against the bundle's lists; a dangling reference evaluates
    /// to `Error(unknown_list)`).
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The list name.
    pub fn name(&self) -> &str {
        &self.0
    }
}

/// One node of the native IR tree.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    Literal(Literal),
    Field(FieldId),
    Has(HasPath),
    List(Vec<Expr>),
    Not(Box<Expr>),
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Cond(Box<Expr>, Box<Expr>, Box<Expr>),
    Compare(CompareOp, Box<Expr>, Box<Expr>),
    /// `lhs in rhs` (rhs a list).
    InList(Box<Expr>, Box<Expr>),
    /// `lhs in rhs` (rhs a map: key presence).
    InMap(Box<Expr>, Box<Expr>),
    /// `lhs[rhs]` (lhs a map).
    IndexMap(Box<Expr>, Box<Expr>),
    Size(Box<Expr>),
    /// `target.fn(arg)`.
    StringCall(StringFn, Box<Expr>, Box<Expr>),
    /// `ip_in(lhs, rhs)`.
    IpIn(Box<Expr>, Box<Expr>),
    NamedList(ListId),
    /// `glob(subject, pattern)`.
    Glob(Box<Expr>, Glob),
}

/// Why [`Program::new`] rejected an expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProgramError {
    /// A structural limit (§5.3) or the step bound was exceeded.
    Limits(&'static str),
    /// Ill-formed or ill-typed tree.
    Malformed(&'static str),
}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limits(what) => write!(f, "policy IR limit exceeded: {what}"),
            Self::Malformed(what) => write!(f, "malformed policy IR: {what}"),
        }
    }
}

impl std::error::Error for ProgramError {}

/// A validated expression, ready for [`super::eval`].
#[derive(Debug, Clone, PartialEq)]
pub struct Program {
    root: Expr,
    fields: Vec<&'static str>,
    nodes: usize,
    max_steps: u64,
}

impl Program {
    /// Validates `root`: at most [`MAX_NODES`] nodes, depth at most
    /// [`MAX_DEPTH`], string literals at most [`MAX_STRING_LITERAL`] bytes,
    /// list literals at most [`MAX_LIST_LITERAL`] elements, `and` / `or` with
    /// at least two arguments, well-typed (the root is a bool) and a static
    /// step bound of at most [`MAX_STEPS`].
    pub fn new(root: Expr) -> Result<Self, ProgramError> {
        let mut nodes = 0;
        let ty = check(&root, 1, &mut nodes)?;
        if ty != Ty::Scalar(Scalar::Bool) {
            return Err(ProgramError::Malformed("the root must be a bool"));
        }
        let max_steps = max_steps(&root);
        if max_steps > MAX_STEPS {
            return Err(ProgramError::Limits(
                "rule exceeds the evaluation step bound",
            ));
        }
        let mut fields = Vec::new();
        collect_fields(&root, &mut fields);
        fields.sort_unstable();
        fields.dedup();
        Ok(Self {
            root,
            fields,
            nodes,
            max_steps,
        })
    }

    /// A program without validation, for evaluator tests of ill-typed trees.
    #[cfg(test)]
    pub(crate) fn new_unchecked(root: Expr) -> Self {
        Self {
            max_steps: max_steps(&root),
            root,
            fields: Vec::new(),
            nodes: 0,
        }
    }

    /// The expression tree.
    pub fn root(&self) -> &Expr {
        &self.root
    }

    /// Sorted unique field paths the expression reads or `has()`-tests.
    pub fn fields(&self) -> &[&'static str] {
        &self.fields
    }

    /// Number of IR nodes.
    pub fn nodes(&self) -> usize {
        self.nodes
    }

    /// The static step bound `max_steps(root)`.
    pub fn max_steps(&self) -> u64 {
        self.max_steps
    }
}

fn collect_fields(e: &Expr, out: &mut Vec<&'static str>) {
    match e {
        Expr::Field(f) => out.push(f.path()),
        Expr::Has(h) => out.push(h.path()),
        _ => children(e, |c| collect_fields(c, out)),
    }
}

/// Calls `f` on each direct child expression, left to right.
fn children<'a>(e: &'a Expr, mut f: impl FnMut(&'a Expr)) {
    match e {
        Expr::Literal(_) | Expr::Field(_) | Expr::Has(_) | Expr::NamedList(_) => {}
        Expr::List(xs) | Expr::And(xs) | Expr::Or(xs) => xs.iter().for_each(f),
        Expr::Not(x) | Expr::Size(x) | Expr::Glob(x, _) => f(x),
        Expr::Cond(c, t, e) => {
            f(c);
            f(t);
            f(e);
        }
        Expr::Compare(_, a, b)
        | Expr::InList(a, b)
        | Expr::InMap(a, b)
        | Expr::IndexMap(a, b)
        | Expr::StringCall(_, a, b)
        | Expr::IpIn(a, b) => {
            f(a);
            f(b);
        }
    }
}

// --- static types ------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scalar {
    Bool,
    Int,
    Double,
    Str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Scalar(Scalar),
    /// `None`: the empty list literal (element type unconstrained).
    List(Option<Scalar>),
    /// Map with string keys and this value type.
    Map(Scalar),
}

fn field_ty(f: FieldId) -> Ty {
    match f.ty() {
        FieldType::Bool => Ty::Scalar(Scalar::Bool),
        FieldType::Int => Ty::Scalar(Scalar::Int),
        FieldType::Double => Ty::Scalar(Scalar::Double),
        FieldType::Str => Ty::Scalar(Scalar::Str),
        FieldType::StrList => Ty::List(Some(Scalar::Str)),
        FieldType::StrMap => Ty::Map(Scalar::Str),
        FieldType::DoubleMap => Ty::Map(Scalar::Double),
    }
}

fn literal_ty(l: &Literal) -> Scalar {
    match l {
        Literal::Bool(_) => Scalar::Bool,
        Literal::Int(_) => Scalar::Int,
        Literal::Double(_) => Scalar::Double,
        Literal::Str(_) => Scalar::Str,
    }
}

const BOOL: Ty = Ty::Scalar(Scalar::Bool);

/// Strict validation: limits and types. Returns the static type.
fn check(e: &Expr, depth: usize, nodes: &mut usize) -> Result<Ty, ProgramError> {
    use ProgramError::{Limits, Malformed};
    *nodes += 1;
    if *nodes > MAX_NODES {
        return Err(Limits("more than 4096 nodes"));
    }
    if depth > MAX_DEPTH {
        return Err(Limits("nesting deeper than 50"));
    }
    let mut sub = |x: &Expr| check(x, depth + 1, nodes);
    Ok(match e {
        Expr::Literal(l) => {
            if matches!(l, Literal::Str(s) if s.len() > MAX_STRING_LITERAL) {
                return Err(Limits("string literal longer than 4096 bytes"));
            }
            Ty::Scalar(literal_ty(l))
        }
        Expr::Field(f) => field_ty(*f),
        Expr::Has(_) => BOOL,
        Expr::NamedList(_) => Ty::List(Some(Scalar::Str)),
        Expr::List(xs) => {
            if xs.len() > MAX_LIST_LITERAL {
                return Err(Limits("list literal with more than 1000 elements"));
            }
            let mut elem = None;
            for x in xs {
                let Ty::Scalar(s) = sub(x)? else {
                    return Err(Malformed("list elements must be scalars"));
                };
                if elem.is_some_and(|e| e != s) {
                    return Err(Malformed("list elements must share one type"));
                }
                elem = Some(s);
            }
            Ty::List(elem)
        }
        Expr::Not(x) => {
            if sub(x)? != BOOL {
                return Err(Malformed("! needs a bool"));
            }
            BOOL
        }
        Expr::And(xs) | Expr::Or(xs) => {
            if xs.len() < 2 {
                return Err(Malformed("&& / || need at least two arguments"));
            }
            for x in xs {
                if sub(x)? != BOOL {
                    return Err(Malformed("&& / || need bools"));
                }
            }
            BOOL
        }
        Expr::Cond(c, t, f) => {
            if sub(c)? != BOOL {
                return Err(Malformed("the condition of ?: must be a bool"));
            }
            let (tt, ft) = (sub(t)?, sub(f)?);
            match (tt, ft) {
                (Ty::List(a), Ty::List(b)) if a.is_none() || b.is_none() || a == b => {
                    Ty::List(a.or(b))
                }
                (a, b) if a == b => a,
                _ => return Err(Malformed("the branches of ?: must share one type")),
            }
        }
        Expr::Compare(op, a, b) => {
            let (Ty::Scalar(x), Ty::Scalar(y)) = (sub(a)?, sub(b)?) else {
                return Err(Malformed("comparisons need scalars"));
            };
            if x != y {
                return Err(Malformed("comparison operands must share one type"));
            }
            if x == Scalar::Bool && !matches!(op, CompareOp::Eq | CompareOp::Ne) {
                return Err(Malformed("bools are only compared with == and !="));
            }
            BOOL
        }
        Expr::InList(x, l) => {
            let (Ty::Scalar(x), Ty::List(elem)) = (sub(x)?, sub(l)?) else {
                return Err(Malformed("`in` needs a scalar and a list"));
            };
            if elem.is_some_and(|e| e != x) {
                return Err(Malformed(
                    "`in` operand and list elements must share one type",
                ));
            }
            BOOL
        }
        Expr::InMap(k, m) => match (sub(k)?, sub(m)?) {
            (Ty::Scalar(Scalar::Str), Ty::Map(_)) => BOOL,
            _ => return Err(Malformed("`in` on a map needs a string key and a map")),
        },
        Expr::IndexMap(m, k) => {
            // Ruling I-20: only a map field is indexed. A computed map (a
            // `?:` whose branches are maps) is rejected like the Go compiler
            // does; it has no single §5.3 size bound `S(m[k])`.
            if !matches!(**m, Expr::Field(_)) {
                return Err(Malformed(COMPUTED_MAP_INDEX));
            }
            let (Ty::Map(v), Ty::Scalar(Scalar::Str)) = (sub(m)?, sub(k)?) else {
                return Err(Malformed("map index needs a map and a string key"));
            };
            Ty::Scalar(v)
        }
        Expr::Size(x) => match sub(x)? {
            Ty::Scalar(Scalar::Str) | Ty::List(_) | Ty::Map(_) => Ty::Scalar(Scalar::Int),
            _ => return Err(Malformed("size() needs a string, list or map")),
        },
        Expr::StringCall(_, t, a) => {
            if (sub(t)?, sub(a)?) != (Ty::Scalar(Scalar::Str), Ty::Scalar(Scalar::Str)) {
                return Err(Malformed("string functions need strings"));
            }
            BOOL
        }
        Expr::IpIn(ip, l) => match (sub(ip)?, sub(l)?) {
            (Ty::Scalar(Scalar::Str), Ty::List(None | Some(Scalar::Str))) => BOOL,
            _ => return Err(Malformed("ip_in needs a string and a list of strings")),
        },
        Expr::Glob(s, _) => {
            if sub(s)? != Ty::Scalar(Scalar::Str) {
                return Err(Malformed("glob needs a string subject"));
            }
            BOOL
        }
    })
}

// --- static step bound (§5.3) -----------------------------------------------

/// Static facts of a subtree: its (lenient) type, the size bound `S` of its
/// result and its worst-case step count.
struct Info {
    ty: Option<Ty>,
    size: u64,
    steps: u64,
}

impl Info {
    fn is_str(&self) -> bool {
        self.ty == Some(Ty::Scalar(Scalar::Str))
    }
}

/// `⌈x / 64⌉`.
fn per64(x: u64) -> u64 {
    x.div_ceil(64)
}

/// The §5.3 static step bound of `root`: every child is assumed evaluated
/// (`&&` / `||` are not discounted for short-circuiting; `?:` takes the
/// larger branch), every `|x|` is replaced by its bound `S(x)` from the §4.1
/// size caps, and all arithmetic saturates.
pub fn max_steps(root: &Expr) -> u64 {
    info(root).steps
}

/// Every subtree is analysed exactly once (one call per node), so the bound
/// is linear in the tree size whatever its shape.
fn info(e: &Expr) -> Info {
    let scalar = |s: Scalar| Some(Ty::Scalar(s));
    let leaf = |ty, size| Info { ty, size, steps: 1 };
    let sum = |xs: &[Expr]| {
        xs.iter()
            .map(|x| info(x).steps)
            .fold(0u64, u64::saturating_add)
    };
    match e {
        Expr::Literal(l) => leaf(
            scalar(literal_ty(l)),
            match l {
                Literal::Str(s) => s.len() as u64,
                _ => 0,
            },
        ),
        Expr::Field(f) => leaf(Some(field_ty(*f)), f.size_cap()),
        Expr::Has(_) => leaf(Some(BOOL), 0),
        Expr::NamedList(_) => leaf(Some(Ty::List(Some(Scalar::Str))), NAMED_LIST_CAP),
        Expr::List(xs) => {
            let mut elem = None;
            let mut steps = 1u64;
            for (k, x) in xs.iter().enumerate() {
                let x = info(x);
                if k == 0 {
                    elem = match x.ty {
                        Some(Ty::Scalar(s)) => Some(s),
                        _ => None,
                    };
                }
                steps = steps.saturating_add(x.steps);
            }
            Info {
                ty: Some(Ty::List(elem)),
                size: xs.len() as u64,
                steps,
            }
        }
        Expr::Not(x) => Info {
            ty: Some(BOOL),
            size: 0,
            steps: info(x).steps.saturating_add(1),
        },
        Expr::And(xs) | Expr::Or(xs) => Info {
            ty: Some(BOOL),
            size: 0,
            steps: sum(xs).saturating_add(1),
        },
        Expr::Cond(c, t, f) => {
            let (c, t, f) = (info(c), info(t), info(f));
            Info {
                ty: t.ty.or(f.ty),
                size: t.size.max(f.size),
                steps: 1u64
                    .saturating_add(c.steps)
                    .saturating_add(t.steps.max(f.steps)),
            }
        }
        Expr::Compare(_, a, b) => {
            let (a, b) = (info(a), info(b));
            // As in the Go compiler: a string compare if either side is a
            // string (well-typed trees always have both or neither).
            let cost = if a.is_str() || b.is_str() {
                1 + per64(a.size.saturating_add(b.size))
            } else {
                1
            };
            Info {
                ty: Some(BOOL),
                size: 0,
                steps: cost.saturating_add(a.steps).saturating_add(b.steps),
            }
        }
        Expr::InList(x, l) | Expr::IpIn(x, l) => {
            let (x, l) = (info(x), info(l));
            Info {
                ty: Some(BOOL),
                size: 0,
                steps: 1u64
                    .saturating_add(l.size)
                    .saturating_add(x.steps)
                    .saturating_add(l.steps),
            }
        }
        Expr::InMap(a, b) => Info {
            ty: Some(BOOL),
            size: 0,
            steps: 2u64
                .saturating_add(info(a).steps)
                .saturating_add(info(b).steps),
        },
        Expr::IndexMap(m, k) => {
            let (m, k) = (info(m), info(k));
            let (ty, size) = match m.ty {
                Some(Ty::Map(Scalar::Str)) => (scalar(Scalar::Str), HEADER_VALUE_CAP),
                Some(Ty::Map(v)) => (scalar(v), 0),
                _ => (None, 0),
            };
            Info {
                ty,
                size,
                steps: 2u64.saturating_add(m.steps).saturating_add(k.steps),
            }
        }
        Expr::Size(x) => {
            let x = info(x);
            let cost = if x.is_str() { 1 + per64(x.size) } else { 1 };
            Info {
                ty: scalar(Scalar::Int),
                size: 0,
                steps: cost.saturating_add(x.steps),
            }
        }
        Expr::StringCall(_, t, a) => {
            let (t, a) = (info(t), info(a));
            Info {
                ty: Some(BOOL),
                size: 0,
                steps: (1 + per64(t.size.saturating_add(a.size)))
                    .saturating_add(t.steps)
                    .saturating_add(a.steps),
            }
        }
        Expr::Glob(s, g) => {
            let s = info(s);
            let cost = 1u64.saturating_add(s.size.saturating_mul(g.pattern().len() as u64) / 16);
            Info {
                ty: Some(BOOL),
                size: 0,
                steps: cost.saturating_add(s.steps),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(e: Expr) -> Box<Expr> {
        Box::new(e)
    }
    fn f(p: &str) -> Expr {
        Expr::Field(FieldId::from_path(p).unwrap())
    }
    fn s(v: &str) -> Expr {
        Expr::Literal(Literal::Str(v.into()))
    }
    fn i(v: i64) -> Expr {
        Expr::Literal(Literal::Int(v))
    }
    fn t() -> Expr {
        Expr::Literal(Literal::Bool(true))
    }
    fn glob(subject: Expr, p: &str) -> Expr {
        Expr::Glob(b(subject), Glob::new(p).unwrap())
    }

    /// §5.3: the cost table, node by node.
    #[test]
    fn step_bound_per_node() {
        // literal / field / has / named_list: 1.
        assert_eq!(max_steps(&t()), 1);
        assert_eq!(max_steps(&f("req.path")), 1);
        assert_eq!(max_steps(&Expr::Has(HasPath::new("net.ip").unwrap())), 1);
        assert_eq!(max_steps(&Expr::NamedList(ListId::new("x"))), 1);
        // list: 1 + elements; not: 1 + child; and / or: 1 + children.
        assert_eq!(max_steps(&Expr::List(vec![s("a"), s("b")])), 3);
        assert_eq!(max_steps(&Expr::Not(b(t()))), 2);
        assert_eq!(max_steps(&Expr::And(vec![t(), t(), t()])), 4);
        assert_eq!(max_steps(&Expr::Or(vec![t(), t()])), 3);
        // compare of strings: 1 + ⌈(8192 + 3) / 64⌉ = 1 + 129; plus 2 leaves.
        assert_eq!(
            max_steps(&Expr::Compare(CompareOp::Eq, b(f("req.path")), b(s("abc")))),
            130 + 2
        );
        // compare of ints: 1 + leaves.
        assert_eq!(
            max_steps(&Expr::Compare(CompareOp::Ge, b(f("risk.score")), b(i(60)))),
            3
        );
        // in_list: 1 + |rhs| (labels: 64) + leaves.
        assert_eq!(
            max_steps(&Expr::InList(b(s("scanner")), b(f("labels")))),
            1 + 64 + 2
        );
        // in_list over a named list: 1 + 10000 + leaves.
        assert_eq!(
            max_steps(&Expr::InList(
                b(f("net.country")),
                b(Expr::NamedList(ListId::new("x")))
            )),
            1 + 10_000 + 2
        );
        // in_map / index_map: 2 + leaves.
        assert_eq!(max_steps(&Expr::InMap(b(s("k")), b(f("rate")))), 4);
        assert_eq!(max_steps(&Expr::IndexMap(b(f("rate")), b(s("k")))), 4);
        // size of a string: 1 + ⌈8192/64⌉; of a list or map: 1.
        assert_eq!(max_steps(&Expr::Size(b(f("req.query")))), 1 + 128 + 1);
        assert_eq!(max_steps(&Expr::Size(b(f("req.headers")))), 2);
        assert_eq!(max_steps(&Expr::Size(b(f("http.header_order")))), 2);
        // string_call on a header value: 1 + ⌈(8192 + 10) / 64⌉ + (index_map 4) + 1.
        let hv = Expr::IndexMap(b(f("req.headers")), b(s("content-type")));
        assert_eq!(
            max_steps(&Expr::StringCall(
                StringFn::StartsWith,
                b(hv.clone()),
                b(s("multipart/"))
            )),
            1 + 129 + 4 + 1
        );
        // index_map(rate, k) is a double: size 0.
        let rv = Expr::IndexMap(b(f("rate")), b(s("k")));
        assert_eq!(
            max_steps(&Expr::Compare(
                CompareOp::Gt,
                b(rv),
                b(Expr::Literal(Literal::Double(0.8)))
            )),
            1 + 4 + 1
        );
        // ip_in: 1 + |rhs| + leaves.
        assert_eq!(
            max_steps(&Expr::IpIn(
                b(f("net.ip")),
                b(Expr::List(vec![s("10.0.0.0/8")]))
            )),
            1 + 1 + 1 + 2
        );
        // glob: 1 + ⌊8192 · 9 / 16⌋ + subject.
        assert_eq!(
            max_steps(&glob(f("req.path"), "/admin/**")),
            1 + 8192 * 9 / 16 + 1
        );
    }

    /// `?:` takes the larger branch plus the condition.
    #[test]
    fn step_bound_cond_takes_larger_branch() {
        let big = glob(f("req.path"), "/a/**");
        let big_steps = max_steps(&big);
        let small = t();
        let c = Expr::Has(HasPath::new("tls.ja4").unwrap());
        let e = Expr::Cond(b(c.clone()), b(small.clone()), b(big.clone()));
        assert_eq!(max_steps(&e), 1 + 1 + big_steps);
        let e = Expr::Cond(b(c), b(big), b(small));
        assert_eq!(max_steps(&e), 1 + 1 + big_steps);
        // The size of a ?: is the larger branch's.
        let sel = Expr::Cond(b(t()), b(f("req.method")), b(f("req.path")));
        let cmp = Expr::Compare(CompareOp::Eq, b(sel), b(s("")));
        assert_eq!(max_steps(&cmp), 1 + 8192 / 64 + (1 + 1 + 1) + 1);
    }

    /// The spec's example: 7 globs of 32-byte patterns on req.path exceed the
    /// bound, 6 do not.
    #[test]
    fn step_bound_limit_and_saturation() {
        let p32 = format!("/{}*", "a".repeat(30));
        assert_eq!(p32.len(), 32);
        let globs = |n: usize| Expr::And((0..n).map(|_| glob(f("req.path"), &p32)).collect());
        assert_eq!(max_steps(&globs(6)), 1 + 6 * (1 + 8192 * 32 / 16 + 1));
        assert!(Program::new(globs(6)).is_ok());
        assert_eq!(max_steps(&globs(7)), 1 + 7 * 16_386);
        assert_eq!(
            Program::new(globs(7)).unwrap_err(),
            ProgramError::Limits("rule exceeds the evaluation step bound")
        );
        // The largest single node: a 4096-byte pattern on an 8 KiB subject.
        let widest = glob(f("req.path"), &"*".repeat(4096));
        assert_eq!(max_steps(&widest), 1 + 8192 * 4096 / 16 + 1);
        assert!(matches!(Program::new(widest), Err(ProgramError::Limits(_))));
        assert_eq!(per64(u64::MAX), u64::MAX / 64 + 1, "no overflow at the top");
    }

    /// The step bound is computed in one linear pass: every subtree is analysed
    /// once, so a maximally nested list literal (`[size([size([...])])]`,
    /// where each list's first element is itself a list-bearing subtree) loads
    /// instantly instead of in `2^depth` time.
    #[test]
    fn step_bound_is_linear_in_the_tree() {
        let nested = |levels: usize| {
            (0..levels).fold(Expr::List(vec![i(1)]), |e, _| {
                Expr::List(vec![Expr::Size(b(e))])
            })
        };
        // Root `in_list` at depth 1, the innermost literal at depth 3 + 2 * 23 = 49.
        let e = Expr::InList(b(i(1)), b(nested(23)));
        let p = Program::new(e).unwrap();
        // [1]: 2 steps; every level adds a list (1) and a size (1);
        // in_list: 1 + |rhs| (one element) + the lhs literal (1).
        assert_eq!(p.max_steps(), 1 + 1 + 1 + (2 + 2 * 23));
    }

    #[test]
    fn program_limits() {
        // Depth: 50 is fine, 51 is not.
        let mut e = t();
        for _ in 0..49 {
            e = Expr::Not(b(e));
        }
        assert!(Program::new(e.clone()).is_ok());
        let e = Expr::Not(b(e));
        assert_eq!(
            Program::new(e).unwrap_err(),
            ProgramError::Limits("nesting deeper than 50")
        );
        // Nodes: a flat `or` of 4095 leaves has 4096 nodes.
        let flat = |n| {
            Expr::Or(
                (0..n)
                    .map(|_| Expr::Has(HasPath::new("net.ip").unwrap()))
                    .collect(),
            )
        };
        assert_eq!(Program::new(flat(4095)).unwrap().nodes(), 4096);
        assert_eq!(
            Program::new(flat(4096)).unwrap_err(),
            ProgramError::Limits("more than 4096 nodes")
        );
        // String literals and list literals.
        let long = Expr::Compare(CompareOp::Eq, b(f("req.method")), b(s(&"x".repeat(4097))));
        assert!(matches!(Program::new(long), Err(ProgramError::Limits(_))));
        let ok = Expr::Compare(CompareOp::Eq, b(f("req.method")), b(s(&"x".repeat(4096))));
        assert!(Program::new(ok).is_ok());
        let list = |n| {
            Expr::InList(
                b(f("net.country")),
                b(Expr::List((0..n).map(|_| s("x")).collect())),
            )
        };
        assert!(Program::new(list(1000)).is_ok());
        assert!(matches!(
            Program::new(list(1001)),
            Err(ProgramError::Limits(_))
        ));
    }

    #[test]
    fn program_type_checks() {
        let bad = [
            f("req.path"),                         // root not bool
            Expr::And(vec![t()]),                  // one argument
            Expr::And(vec![t(), f("risk.score")]), // non-bool argument
            Expr::Not(b(i(1))),
            Expr::Compare(
                CompareOp::Eq,
                b(i(1)),
                b(Expr::Literal(Literal::Double(1.0))),
            ),
            Expr::Compare(CompareOp::Lt, b(t()), b(t())),
            Expr::Compare(CompareOp::Eq, b(f("labels")), b(f("labels"))),
            Expr::InList(
                b(i(1)),
                b(Expr::List(vec![Expr::Literal(Literal::Double(1.0))])),
            ),
            Expr::InList(b(i(1)), b(Expr::List(vec![i(1), s("a")]))),
            Expr::InList(b(Expr::List(vec![i(1)])), b(Expr::List(vec![i(1)]))),
            Expr::InList(b(s("a")), b(f("rate"))),
            Expr::InMap(b(i(1)), b(f("rate"))),
            Expr::Compare(
                CompareOp::Eq,
                b(Expr::IndexMap(b(f("labels")), b(s("x")))),
                b(s("x")),
            ),
            Expr::Compare(CompareOp::Eq, b(Expr::Size(b(i(1)))), b(i(1))),
            Expr::StringCall(StringFn::Contains, b(f("risk.score")), b(s("x"))),
            Expr::IpIn(b(f("net.ip")), b(Expr::List(vec![i(1)]))),
            glob(f("risk.score"), "*"),
            Expr::Cond(b(i(1)), b(t()), b(t())),
            Expr::Cond(b(t()), b(t()), b(i(1))),
            // Ruling I-20: no index on a computed map, whatever its branches.
            Expr::Compare(
                CompareOp::Eq,
                b(Expr::IndexMap(
                    b(Expr::Cond(b(t()), b(f("req.headers")), b(f("req.headers")))),
                    b(s("accept")),
                )),
                b(s("x")),
            ),
        ];
        for e in bad {
            assert!(
                matches!(Program::new(e.clone()), Err(ProgramError::Malformed(_))),
                "{e:?}"
            );
        }
        let good = [
            Expr::InList(b(s("a")), b(Expr::List(vec![]))),
            Expr::IpIn(b(f("net.ip")), b(Expr::List(vec![]))),
            Expr::InMap(b(s("accept")), b(f("req.headers"))),
            Expr::Compare(CompareOp::Gt, b(Expr::Size(b(f("labels")))), b(i(0))),
            Expr::InList(b(Expr::Cond(b(t()), b(s("a")), b(s("b")))), b(f("labels"))),
            Expr::InList(
                b(s("a")),
                b(Expr::Cond(b(t()), b(Expr::List(vec![])), b(f("labels")))),
            ),
            Expr::Compare(CompareOp::Ne, b(t()), b(f("net.tor"))),
        ];
        for e in good {
            assert!(Program::new(e.clone()).is_ok(), "{e:?}");
        }
    }

    #[test]
    fn program_fields_are_sorted_unique() {
        let e = Expr::And(vec![
            Expr::Has(HasPath::new("tls.ja4").unwrap()),
            Expr::InList(b(f("net.country")), b(Expr::NamedList(ListId::new("x")))),
            Expr::Compare(CompareOp::Eq, b(f("net.country")), b(s("HK"))),
        ]);
        let p = Program::new(e).unwrap();
        assert_eq!(p.fields(), ["net.country", "tls.ja4"]);
        assert_eq!(p.nodes(), 8);
    }
}
