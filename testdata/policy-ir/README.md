# Policy IR conformance suite

Cross-language fixtures for the restricted policy IR ([phase1-spec §5.8](../../docs/impl/phase1-spec.md#58-跨语言一致性套件)). The Go compiler (`control-plane/internal/policy`) owns both files; the Rust evaluator (`proto/rust/tests/policy_ir_conformance.rs`) only reads them.

| File | Contents |
|---|---|
| `cases.json` | Hand-maintained. `lists`: the named lists `list("…")` resolves to. `contexts`: an Activation JSON `input` (§4.2; omitted keys are zero values) and its `missing` path set (§4.3). `cases`: a CEL `expr`, the `context` it runs in, and either `expect` (`true` / `false` / `unknown` / `error`) or `compile_error` (a substring of the compiler's error; such cases are not in the IR file) |
| `cases.ir.json` | Generated. For every case without `compile_error`, in `cases.json` order: `ir` = standard base64 of the deterministic `PolicyExpr` bytes, including `max_steps` |

Regenerate after changing `cases.json` or the compiler, then review the diff:

```sh
cd control-plane && go test ./internal/policy -run TestIRConformance -update
```

Without `-update` the Go test fails when the committed IR differs from what the compiler emits. It also evaluates every case twice (cel-go partial evaluation, and an independent Go implementation of the §5.3 IR semantics that checks the actual step count against `max_steps`) and checks the §5.8 coverage requirements.

Values are illustrative (documentation address ranges, invented operators and fingerprints).
