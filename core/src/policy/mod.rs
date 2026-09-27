//! Policy evaluation (docs/impl/phase1-spec.md §4, §5): the field schema and
//! MISSING semantics, the native policy IR with its static step bound, the
//! three-valued evaluator, `glob` / `ip_in`, the rule engine and the default
//! treatment matrix.
//!
//! Policies are written in CEL and compiled by the Go control plane into a
//! restricted IR (`policy_ir.proto`); `mg-proto` decodes that IR into
//! [`Program`]s. Nothing here parses CEL.

mod engine;
mod eval;
mod fields;
mod glob;
mod ip;
mod ir;
mod matrix;

pub use engine::{
    CrawlerAction, CrawlerPolicy, EngineConfig, INTERACTIVE_AS_POW, Phase, Rule, RuleAction,
    RuleMode, SitePolicy, in_rollout,
};
pub use eval::{EvalError, EvalResult, eval, eval_steps};
pub use fields::{
    Activation, AgentNs, CrawlerNs, EdgeTlsNs, FieldId, HasPath, HttpNs, IdentityNs, Ja4Ns,
    MissingSet, NetNs, ProofNs, ReqNs, RiskNs, RouteNs, TlsNs, TokenNs, UnknownField, UpstreamNs,
};
pub use glob::{Glob, GlobError, MAX_GLOB_LEN};
pub use ip::{NamedList, NamedLists};
pub use ir::{
    CompareOp, Expr, ListId, Literal, MAX_DEPTH, MAX_LIST_LITERAL, MAX_NODES, MAX_STEPS,
    MAX_STRING_LITERAL, NAMED_LIST_CAP, Program, ProgramError, StringFn, max_steps,
};

#[cfg(test)]
mod tests;
