//! Tests of the policy evaluator (§5.3), the step bound, the rule engine
//! (§5.4) and the default matrix (§5.5).

mod engine;
mod eval;
mod matrix;
mod steps;

use super::*;

/// A tiny builder for native IR trees.
pub(super) mod dsl {
    use super::*;

    pub fn b(e: Expr) -> Box<Expr> {
        Box::new(e)
    }
    pub fn f(p: &str) -> Expr {
        Expr::Field(FieldId::from_path(p).unwrap_or_else(|| panic!("no field {p}")))
    }
    pub fn has(p: &str) -> Expr {
        Expr::Has(HasPath::new(p).unwrap())
    }
    pub fn s(v: &str) -> Expr {
        Expr::Literal(Literal::Str(v.into()))
    }
    pub fn i(v: i64) -> Expr {
        Expr::Literal(Literal::Int(v))
    }
    pub fn d(v: f64) -> Expr {
        Expr::Literal(Literal::Double(v))
    }
    pub fn t() -> Expr {
        Expr::Literal(Literal::Bool(true))
    }
    pub fn fa() -> Expr {
        Expr::Literal(Literal::Bool(false))
    }
    pub fn not(x: Expr) -> Expr {
        Expr::Not(b(x))
    }
    pub fn and(xs: Vec<Expr>) -> Expr {
        Expr::And(xs)
    }
    pub fn or(xs: Vec<Expr>) -> Expr {
        Expr::Or(xs)
    }
    pub fn cond(c: Expr, x: Expr, y: Expr) -> Expr {
        Expr::Cond(b(c), b(x), b(y))
    }
    pub fn cmp(op: CompareOp, x: Expr, y: Expr) -> Expr {
        Expr::Compare(op, b(x), b(y))
    }
    pub fn eq(x: Expr, y: Expr) -> Expr {
        cmp(CompareOp::Eq, x, y)
    }
    pub fn list(xs: Vec<Expr>) -> Expr {
        Expr::List(xs)
    }
    pub fn in_list(x: Expr, l: Expr) -> Expr {
        Expr::InList(b(x), b(l))
    }
    pub fn in_map(k: Expr, m: Expr) -> Expr {
        Expr::InMap(b(k), b(m))
    }
    pub fn idx(m: Expr, k: Expr) -> Expr {
        Expr::IndexMap(b(m), b(k))
    }
    pub fn size(x: Expr) -> Expr {
        Expr::Size(b(x))
    }
    pub fn call(fun: StringFn, x: Expr, y: Expr) -> Expr {
        Expr::StringCall(fun, b(x), b(y))
    }
    pub fn ip_in(x: Expr, l: Expr) -> Expr {
        Expr::IpIn(b(x), b(l))
    }
    pub fn named(n: &str) -> Expr {
        Expr::NamedList(ListId::new(n))
    }
    pub fn glob(x: Expr, p: &str) -> Expr {
        Expr::Glob(b(x), Glob::new(p).unwrap())
    }
    pub fn prog(e: Expr) -> Program {
        Program::new(e).expect("valid program")
    }
}
