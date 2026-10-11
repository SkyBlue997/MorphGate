# Policy IR conformance suite

Cross-language fixtures for the restricted policy IR ([phase1-spec §5.8](../../docs/impl/phase1-spec.md#58-跨语言一致性套件)). The Go compiler (`control-plane/internal/policy`) owns both files; the Rust evaluator (`proto/rust/tests/policy_ir_conformance.rs`) only reads them.

| File | Contents |
|---|---|
| `cases.json` | Hand-maintained. `lists`: the named lists `list("…")` resolves to. `contexts`: an Activation JSON `input` (§4.2; omitted keys are zero values) and its `missing` path set (§4.3). `cases`: a CEL `expr`, the `context` it runs in, and either `expect` (`true` / `false` / `unknown` / `error`) or `compile_error` (a substring of the compiler's error; such cases are not in the IR file) |
| `cases.ir.json` | Generated. For every case without `compile_error`, in `cases.json` order: `ir` = standard base64 of the deterministic `PolicyExpr` bytes, including `max_steps` |
| `fields.json` | Read-only contract ([phase2-spec §0.4, §22](../../docs/impl/phase2-spec.md#22-phase-1-遗留项的处置)): every policy field path with its `type` (`bool`, `int`, `double`, `string`, `list(string)`, `map(string,string)`, `map(string,double)`), its size `cap` (§4.1: UTF-8 bytes for strings, entries for lists and maps, 0 for scalars; `key_cap` / `value_cap` / `item_cap` bound map keys, map values and list items where the Go cost estimator needs them) and the `phase` that introduced it; `structs` lists the namespace and struct paths. Generated once from the Go table (`internal/policy` `Input` and `sizeHints`) and the Rust table (`core/src/policy/fields.rs`), which agreed field for field, plus the Phase 2 fields of phase2-spec §4.1. The Go (WP-G4) and Rust (WP-R4) tests read it; change the spec first |

Regenerate after changing `cases.json` or the compiler, then review the diff:

```sh
cd control-plane && go test ./internal/policy -run TestIRConformance -update
```

Without `-update` the Go test fails when the committed IR differs from what the compiler emits. It also evaluates every case twice (cel-go partial evaluation, and an independent Go implementation of the §5.3 IR semantics that checks the actual step count against `max_steps`) and checks the §5.8 coverage requirements.

Values are illustrative (documentation address ranges, invented operators and fingerprints).
