package policy

import "reflect"

// The request context visible to policy expressions (docs/06 §2,
// docs/impl/phase1-spec.md §4.1). Each top-level namespace is a CEL variable;
// struct namespaces are exposed through cel-go native types so that misspelled
// fields are compile-time errors.
//
// These Go types define the policy language surface. The Rust Decision Core
// mirrors them field for field in mg_core::policy::Activation, and the JSON
// form of Input (the `json` tags, equal to the `cel` tags; omitted keys read as
// zero values) is the Activation JSON of spec §4.2 that the cross-language
// conformance fixtures in testdata/policy-ir use.
//
// Missing input (docs/06 §2, docs/03 §3.1, spec §4.3): at evaluation time a
// field is PRESENT, ABSENT (the profile can supply it but this request lacks
// it: it reads as its zero value and has(x) is true) or MISSING (the profile
// cannot supply it, or an upstream-injected header did not arrive: has(x) is
// false and reading it yields "unknown"). Input itself has no MISSING state;
// the MISSING paths travel next to it as a path set (Evaluator.EvalWithMissing,
// Rust MissingSet). The compiler warns about unguarded reads of fields that
// are always MISSING under the policy file's declared profile (see
// checkAvailability).

// Input is a complete evaluation context. It is used by Evaluator (reference
// semantics and tests); the data plane never evaluates CEL directly.
type Input struct {
	Req      Request            `cel:"req" json:"req"`
	Net      Net                `cel:"net" json:"net"`
	Upstream Upstream           `cel:"upstream" json:"upstream"`
	TLS      TLS                `cel:"tls" json:"tls"`
	HTTP     HTTP               `cel:"http" json:"http"`
	EdgeTLS  EdgeTLS            `cel:"edge_tls" json:"edge_tls"`
	Identity Identity           `cel:"identity" json:"identity"`
	Risk     Risk               `cel:"risk" json:"risk"`
	Route    Route              `cel:"route" json:"route"`
	Rate     map[string]float64 `cel:"rate" json:"rate"`
	Labels   []string           `cel:"labels" json:"labels"`
}

// Request is `req`.
type Request struct {
	Method  string            `cel:"method" json:"method"`
	Host    string            `cel:"host" json:"host"`
	Path    string            `cel:"path" json:"path"`
	Query   string            `cel:"query" json:"query"`     // raw query string without '?'
	Headers map[string]string `cel:"headers" json:"headers"` // lower-case names; repeated headers joined with ", "
	Channel string            `cel:"channel" json:"channel"` // web | api | mobile
}

// Net is `net`. IP is the client address resolved by the UpstreamProfile.
type Net struct {
	IP       string `cel:"ip" json:"ip"`
	ASN      int64  `cel:"asn" json:"asn"`
	Country  string `cel:"country" json:"country"`     // ISO 3166-1 alpha-2
	ConnType string `cel:"conn_type" json:"conn_type"` // datacenter | residential | mobile | education | unknown
	Tor      bool   `cel:"tor" json:"tor"`
}

// Upstream is `upstream`: how the request reached the Edge.
type Upstream struct {
	Profile       string `cel:"profile" json:"profile"` // cloudflare | direct_tls | ...
	Authenticated bool   `cel:"authenticated" json:"authenticated"`
	AuthMethod    string `cel:"auth_method" json:"auth_method"` // loopback | origin_mtls | secret_header | src_cidr | none
}

// TLS is `tls`: the visitor's TLS as seen by the Edge itself. It is MISSING
// behind a CDN (see edge_tls for the coarse CDN-forwarded profile); in Phase 1
// tls.ja4 is MISSING under direct_tls as well (JA4 is a spike only, D-07).
type TLS struct {
	JA4     JA4    `cel:"ja4" json:"ja4"`
	Version string `cel:"version" json:"version"`
}

// JA4 carries the fingerprint together with its provenance.
type JA4 struct {
	Value         string `cel:"value" json:"value"`
	Source        string `cel:"source" json:"source"` // self | cloudfront | gcp_alb | esa | envoy | openresty
	Authenticated bool   `cel:"authenticated" json:"authenticated"`
}

// HTTP is `http`.
type HTTP struct {
	Version string `cel:"version" json:"version"`
	// HeaderOrder is the distinct request header names in order of first
	// appearance, original case, at most 128 (direct_tls with HTTP/1.x only;
	// MISSING otherwise). Pingora folds repeated names into their first
	// position, so interleaved repeats cannot be reconstructed: detectors and
	// policies must not depend on the position of a repeated header.
	HeaderOrder []string `cel:"header_order" json:"header_order"`
}

// EdgeTLS is `edge_tls`: weak TLS signals forwarded by Cloudflare as
// x-mg-cf-tls-* headers (EDGE_TLS family, shadow first). MISSING under every
// other profile.
type EdgeTLS struct {
	Version     string `cel:"version" json:"version"`
	Cipher      string `cel:"cipher" json:"cipher"`
	CiphersSHA1 string `cel:"ciphers_sha1" json:"ciphers_sha1"`
	ExtSHA1     string `cel:"ext_sha1" json:"ext_sha1"` // ordering undocumented: never for binding or high weight until measured
	HelloLen    int64  `cel:"hello_len" json:"hello_len"`
}

// Identity is `identity`.
type Identity struct {
	Token   Token   `cel:"token" json:"token"`
	Proof   Proof   `cel:"proof" json:"proof"`
	Agent   Agent   `cel:"agent" json:"agent"`
	Crawler Crawler `cel:"crawler" json:"crawler"`
}

// Token describes the visitor's MorphGate credential.
type Token struct {
	Level string `cel:"level" json:"level"` // "" | invisible | pow | interactive | interactive_a11y | interactive_ext:{provider}
	Age   int64  `cel:"age" json:"age"`     // seconds since issuance; 0 when there is no token
}

// Proof is the proof-of-possession result for the request.
type Proof struct {
	Valid bool `cel:"valid" json:"valid"`
}

// Agent identifies an authorised AI agent and its grant.
type Agent struct {
	ID      string `cel:"id" json:"id"`
	GrantID string `cel:"grant_id" json:"grant_id"`
}

// Crawler is the crawler verification result. The two cf_* fields come from
// Cloudflare (x-mg-cf-vbot, x-mg-cf-vbot-cat), are MISSING under every profile
// but cloudflare, and are corroboration only: the compiler warns about allow
// or block rules that rely on them without MorphGate's own verification.
type Crawler struct {
	Claimed   bool   `cel:"claimed" json:"claimed"` // the User-Agent claims a crawler of the registry
	Operator  string `cel:"operator" json:"operator"`
	Verified  bool   `cel:"verified" json:"verified"`       // verified by MorphGate (signature, official IP ranges, rDNS)
	Purpose   string `cel:"purpose" json:"purpose"`         // e.g. search | ai_training | ai_agent
	CFVBot    bool   `cel:"cf_vbot" json:"cf_vbot"`         // Cloudflare verified-bot flag
	CFVBotCat string `cel:"cf_vbot_cat" json:"cf_vbot_cat"` // Cloudflare verified-bot category
}

// Risk is `risk`.
type Risk struct {
	Score      int64    `cel:"score" json:"score"`           // 0..100
	Confidence float64  `cel:"confidence" json:"confidence"` // 0..1
	Class      string   `cel:"class" json:"class"`           // upper-case BotClass name, e.g. IMPERSONATOR (event JSON uses the lower-case wire name)
	Reasons    []string `cel:"reasons" json:"reasons"`
}

// Route is `route`.
type Route struct {
	Name        string `cel:"name" json:"name"`
	Sensitivity string `cel:"sensitivity" json:"sensitivity"` // low | medium | high | critical
	Env         string `cel:"env" json:"env"`                 // production | staging | test | dev
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
