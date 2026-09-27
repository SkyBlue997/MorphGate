package policy

import "reflect"

// The request context visible to policy expressions (docs/06 §2). Each
// top-level namespace is a CEL variable; struct namespaces are exposed through
// cel-go native types so that misspelled fields are compile-time errors.
//
// These Go types define the policy language surface only. The Edge fills the
// same fields from its native RequestContext (proto morphgate.v1.RequestContext
// is the wire form, with the same field paths except risk.class / risk.reasons
// = RiskAssessment.bot_class / top_reasons); Phase 1 adds the Rust-side mapping
// and a conformance suite generated from these declarations.
//
// Missing input (docs/06 §2, docs/03 §3.1): at evaluation time a field is
// PRESENT, ABSENT (the profile can supply it but this request lacks it: it
// reads as its zero value and has(x) is true) or MISSING (the profile cannot
// supply it, or an upstream-injected header did not arrive: has(x) is false
// and any comparison reading it is "unknown"; an expression that ends up
// unknown means the rule does not match and dry-run logs missing_input). That
// three-state semantics is implemented in Phase 1 by the Rust IR evaluator and
// this package's reference Evaluator. In Phase 0 these plain Go values have no
// MISSING state: every field reads as its value or zero value, and has(x) is
// cel-go's native-type presence test (x is not the zero value). The compiler
// already warns about unguarded reads of fields that are always MISSING under
// the policy file's declared profile (see checkAvailability).

// Input is a complete evaluation context. It is used by Evaluator (reference
// semantics and tests); the data plane never evaluates CEL directly.
type Input struct {
	Req      Request            `cel:"req"`
	Net      Net                `cel:"net"`
	Upstream Upstream           `cel:"upstream"`
	TLS      TLS                `cel:"tls"`
	HTTP     HTTP               `cel:"http"`
	EdgeTLS  EdgeTLS            `cel:"edge_tls"`
	Identity Identity           `cel:"identity"`
	Risk     Risk               `cel:"risk"`
	Route    Route              `cel:"route"`
	Rate     map[string]float64 `cel:"rate"`
	Labels   []string           `cel:"labels"`
}

// Request is `req`.
type Request struct {
	Method  string            `cel:"method"`
	Host    string            `cel:"host"`
	Path    string            `cel:"path"`
	Query   string            `cel:"query"`   // raw query string without '?'
	Headers map[string]string `cel:"headers"` // lower-case names; repeated headers joined with ", "
	Channel string            `cel:"channel"` // web | api | mobile
}

// Net is `net`. IP is the client address resolved by the UpstreamProfile.
type Net struct {
	IP       string `cel:"ip"`
	ASN      int64  `cel:"asn"`
	Country  string `cel:"country"`   // ISO 3166-1 alpha-2
	ConnType string `cel:"conn_type"` // datacenter | residential | mobile | education | unknown
	Tor      bool   `cel:"tor"`
}

// Upstream is `upstream`: how the request reached the Edge.
type Upstream struct {
	Profile       string `cel:"profile"` // cloudflare | direct_tls | ...
	Authenticated bool   `cel:"authenticated"`
	AuthMethod    string `cel:"auth_method"` // loopback | origin_mtls | secret_header | src_cidr | none
}

// TLS is `tls`: the visitor's TLS as seen by the Edge itself. It is MISSING
// behind a CDN (see edge_tls for the coarse CDN-forwarded profile).
type TLS struct {
	JA4     JA4    `cel:"ja4"`
	Version string `cel:"version"`
}

// JA4 carries the fingerprint together with its provenance.
type JA4 struct {
	Value         string `cel:"value"`
	Source        string `cel:"source"` // self | cloudfront | gcp_alb | esa | envoy | openresty
	Authenticated bool   `cel:"authenticated"`
}

// HTTP is `http`.
type HTTP struct {
	Version     string   `cel:"version"`
	HeaderOrder []string `cel:"header_order"` // direct_tls only; empty when not preserved
}

// EdgeTLS is `edge_tls`: weak TLS signals forwarded by Cloudflare as
// x-mg-cf-tls-* headers (EDGE_TLS family, shadow first). MISSING under every
// other profile.
type EdgeTLS struct {
	Version     string `cel:"version"`
	Cipher      string `cel:"cipher"`
	CiphersSHA1 string `cel:"ciphers_sha1"`
	ExtSHA1     string `cel:"ext_sha1"` // ordering undocumented: never for binding or high weight until measured
	HelloLen    int64  `cel:"hello_len"`
}

// Identity is `identity`.
type Identity struct {
	Token   Token   `cel:"token"`
	Proof   Proof   `cel:"proof"`
	Agent   Agent   `cel:"agent"`
	Crawler Crawler `cel:"crawler"`
}

// Token describes the visitor's MorphGate credential.
type Token struct {
	Level string `cel:"level"` // "" | invisible | pow | interactive | interactive_a11y | interactive_ext:{provider}
	Age   int64  `cel:"age"`   // seconds since issuance; 0 when there is no token
}

// Proof is the proof-of-possession result for the request.
type Proof struct {
	Valid bool `cel:"valid"`
}

// Agent identifies an authorised AI agent and its grant.
type Agent struct {
	ID      string `cel:"id"`
	GrantID string `cel:"grant_id"`
}

// Crawler is the crawler verification result. The two cf_* fields come from
// Cloudflare (x-mg-cf-vbot, x-mg-cf-vbot-cat), are MISSING under every profile
// but cloudflare, and are corroboration only: the compiler warns about allow
// or block rules that rely on them without MorphGate's own verification.
type Crawler struct {
	Operator  string `cel:"operator"`
	Verified  bool   `cel:"verified"`    // verified by MorphGate (signature, official IP ranges, rDNS)
	Purpose   string `cel:"purpose"`     // e.g. search | ai_training | ai_agent
	CFVBot    bool   `cel:"cf_vbot"`     // Cloudflare verified-bot flag
	CFVBotCat string `cel:"cf_vbot_cat"` // Cloudflare verified-bot category
}

// Risk is `risk`.
type Risk struct {
	Score      int64    `cel:"score"`      // 0..100
	Confidence float64  `cel:"confidence"` // 0..1
	Class      string   `cel:"class"`      // BotClass name without prefix, e.g. IMPERSONATOR
	Reasons    []string `cel:"reasons"`
}

// Route is `route`.
type Route struct {
	Name        string `cel:"name"`
	Sensitivity string `cel:"sensitivity"` // low | medium | high | critical
	Env         string `cel:"env"`         // production | staging | test | dev
}

// activation maps variable names to values for cel.Program.Eval. Nil maps
// and slices become empty ones so expressions never see null.
func (in *Input) activation() map[string]any {
	v := reflect.ValueOf(in).Elem()
	t := v.Type()
	out := make(map[string]any, t.NumField())
	for i := range t.NumField() {
		f := v.Field(i)
		if (f.Kind() == reflect.Map || f.Kind() == reflect.Slice) && f.IsNil() {
			if f.Kind() == reflect.Map {
				f = reflect.MakeMap(f.Type())
			} else {
				f = reflect.MakeSlice(f.Type(), 0, 0)
			}
		}
		out[t.Field(i).Tag.Get("cel")] = f.Interface()
	}
	return out
}
