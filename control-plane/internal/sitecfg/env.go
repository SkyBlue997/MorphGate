package sitecfg

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// CatchAllPattern is the path of the implicit "default" route.
const CatchAllPattern = "/**"

func (p *parser) parseEnvironments(n *yaml.Node, s *Site) []Environment {
	items, ok := p.seq(n, "environments")
	if !ok {
		return nil
	}
	if len(items) == 0 {
		p.errorf(n, "environments: must list at least one environment")
	}
	var out []Environment
	seen := map[string]bool{}
	for i, it := range items {
		path := fmt.Sprintf("environments[%d]", i)
		o := p.object(it, path)
		if o == nil {
			continue
		}
		env := Environment{}
		if v := o.require("name"); v != nil {
			if name, ok := p.enum(v, o.sub("name"), EnvironmentNames); ok {
				if seen[name] {
					p.errorf(v, "%s: duplicate environment %q", o.sub("name"), name)
				}
				seen[name] = true
				env.Name = name
				path = "environments[" + name + "]"
				o.path = path
			}
		}
		if v := o.require("hosts"); v != nil {
			env.Hosts = p.hostList(v, o.sub("hosts"))
			if len(env.Hosts) == 0 && v.Kind == yaml.SequenceNode {
				p.errorf(v, "%s: must list at least one host", o.sub("hosts"))
			}
		}
		if v := o.get("policies"); v != nil {
			files, _ := p.strList(v, o.sub("policies"), func(it *yaml.Node, ip, f string) bool {
				if f == "" {
					p.errorf(it, "%s: empty path", ip)
					return false
				}
				return true
			})
			for _, f := range files {
				env.Policies = append(env.Policies, resolve(s.Dir, f))
			}
		}
		env.AutomationAllowlistOnly = env.Name != "production"
		if v := o.get("automation_allowlist_only"); v != nil {
			env.AutomationAllowlistOnly, _ = p.boolean(v, o.sub("automation_allowlist_only"))
		}
		routesNode := o.get("routes")
		if routesNode != nil {
			env.Routes = p.parseRoutes(routesNode, o.sub("routes"), env.Hosts)
		}
		env.Routes = p.appendDefaultRoute(it, path, env.Routes)
		if len(env.Routes) > MaxRoutesPerEnv {
			p.errorf(routesNode, "%s: %d routes (including default), at most %d", o.sub("routes"), len(env.Routes), MaxRoutesPerEnv)
		}
		if v := o.get("rate_limits"); v != nil {
			env.RateLimits = p.parseRateLimits(v, o.sub("rate_limits"), env.Routes, s)
		}
		o.finish()
		out = append(out, env)
	}
	return out
}

// appendDefaultRoute appends the catch-all {name: default, paths: ["/**"],
// channel: web, sensitivity: low} unless a route already matches every
// request (paths exactly ["/**"], no host or method restriction).
func (p *parser) appendDefaultRoute(n *yaml.Node, path string, routes []Route) []Route {
	for _, r := range routes {
		if len(r.Paths) == 1 && r.Paths[0] == CatchAllPattern && len(r.Hosts) == 0 && len(r.Methods) == 0 {
			return routes
		}
	}
	if slices.ContainsFunc(routes, func(r Route) bool { return r.Name == "default" }) {
		p.errorf(n, "%s.routes: the name \"default\" is reserved for the catch-all route (paths: [\"/**\"], no hosts or methods)", path)
		return routes
	}
	return append(routes, Route{Name: "default", Paths: []string{CatchAllPattern}, Channel: "web", Sensitivity: "low", Implicit: true})
}

func (p *parser) parseRoutes(n *yaml.Node, path string, envHosts []string) []Route {
	items, ok := p.seq(n, path)
	if !ok {
		return nil
	}
	var out []Route
	seen := map[string]bool{}
	for i, it := range items {
		rp := fmt.Sprintf("%s[%d]", path, i)
		o := p.object(it, rp)
		if o == nil {
			continue
		}
		r := Route{Channel: "web"}
		if v := o.require("name"); v != nil {
			if name, ok := p.str(v, o.sub("name")); ok {
				switch {
				case !RouteNamePattern.MatchString(name):
					p.errorf(v, "%s: %q does not match %s", o.sub("name"), name, RouteNamePattern)
				case seen[name]:
					p.errorf(v, "%s: duplicate route name %q in this environment", o.sub("name"), name)
				}
				seen[name] = true
				r.Name = name
			}
		}
		if v := o.require("paths"); v != nil {
			r.Paths, _ = p.strList(v, o.sub("paths"), p.checkRoutePattern)
			if v.Kind == yaml.SequenceNode && (len(v.Content) < 1 || len(v.Content) > MaxPathsPerRoute) {
				p.errorf(v, "%s: %d patterns, want 1-%d", o.sub("paths"), len(v.Content), MaxPathsPerRoute)
			}
		}
		if v := o.get("hosts"); v != nil {
			r.Hosts = p.hostList(v, o.sub("hosts"))
			for _, h := range r.Hosts {
				if !slices.Contains(envHosts, h) {
					p.errorf(v, "%s: %q is not a host of this environment", o.sub("hosts"), h)
				}
			}
		}
		if v := o.get("methods"); v != nil {
			r.Methods, _ = p.strList(v, o.sub("methods"), func(it *yaml.Node, ip, m string) bool {
				if !methodPattern.MatchString(m) {
					p.errorf(it, "%s: %q is not an upper-case HTTP method", ip, m)
					return false
				}
				return true
			})
			p.uniqueStrings(v, o.sub("methods"), r.Methods)
		}
		if v := o.get("channel"); v != nil {
			r.Channel, _ = p.enum(v, o.sub("channel"), Channels)
		}
		if v := o.require("sensitivity"); v != nil {
			r.Sensitivity, _ = p.enum(v, o.sub("sensitivity"), Sensitivities)
		}
		critical := r.Sensitivity == "critical"
		r.RequireClearance, r.FailClosed = critical, critical
		if v := o.get("require_clearance"); v != nil {
			r.RequireClearance, _ = p.boolean(v, o.sub("require_clearance"))
		}
		if v := o.get("fail_closed"); v != nil {
			r.FailClosed, _ = p.boolean(v, o.sub("fail_closed"))
		}
		if v := o.get("redact_path"); v != nil {
			r.RedactPath, _ = p.boolean(v, o.sub("redact_path"))
		}
		o.finish()
		out = append(out, r)
	}
	return out
}

// checkRoutePattern enforces the route pattern limits (spec §8.2): leading
// "/", visible ASCII only, at most 128 bytes and 4 wildcards ("*" runs count
// once, each "?" once).
func (p *parser) checkRoutePattern(it *yaml.Node, path, pat string) bool {
	switch {
	case !strings.HasPrefix(pat, "/"):
		p.errorf(it, "%s: %q must start with /", path, pat)
	case len(pat) > MaxPatternLen:
		p.errorf(it, "%s: pattern is %d bytes, at most %d", path, len(pat), MaxPatternLen)
	case strings.ContainsFunc(pat, func(r rune) bool { return r <= 0x20 || r >= 0x7f }):
		p.errorf(it, "%s: %q must contain visible ASCII characters only", path, pat)
	case WildcardCount(pat) > MaxWildcards:
		p.errorf(it, "%s: %q has %d wildcards, at most %d", path, pat, WildcardCount(pat), MaxWildcards)
	default:
		if lit := literalPrefix(pat); lit != "/" && IsReserved(lit) {
			p.warnf(it, "%s: %q is in the Edge's reserved %s/ namespace; such requests never reach routing", path, pat, EdgePrefix)
		}
		return true
	}
	return false
}

// WildcardCount counts glob wildcards the way mg_core's Glob does: a run of
// "*" counts once, every "?" once.
func WildcardCount(pat string) int {
	n := 0
	for i := 0; i < len(pat); i++ {
		switch pat[i] {
		case '?':
			n++
		case '*':
			n++
			for i+1 < len(pat) && pat[i+1] == '*' {
				i++
			}
		}
	}
	return n
}

func literalPrefix(pat string) string {
	if i := strings.IndexAny(pat, "*?"); i >= 0 {
		return pat[:i]
	}
	return pat
}

func (p *parser) parseRateLimits(n *yaml.Node, path string, routes []Route, s *Site) []RateLimit {
	items, ok := p.seq(n, path)
	if !ok {
		return nil
	}
	if len(items) > MaxLimitersPerEnv {
		p.errorf(n, "%s: %d limiters, at most %d", path, len(items), MaxLimitersPerEnv)
	}
	var out []RateLimit
	seen := map[string]bool{}
	for i, it := range items {
		lp := fmt.Sprintf("%s[%d]", path, i)
		o := p.object(it, lp)
		if o == nil {
			continue
		}
		l := RateLimit{Scope: "global", Mode: "enforce", Rate: Rate{Burst: 1}}
		if v := o.require("id"); v != nil {
			if id, ok := p.str(v, o.sub("id")); ok {
				switch {
				case !LimiterIDPattern.MatchString(id):
					p.errorf(v, "%s: %q does not match %s", o.sub("id"), id, LimiterIDPattern)
				case strings.HasPrefix(id, "mg."):
					p.errorf(v, "%s: the \"mg.\" prefix is reserved for built-in limiters", o.sub("id"))
				case seen[id]:
					p.errorf(v, "%s: duplicate limiter id %q in this environment", o.sub("id"), id)
				}
				seen[id] = true
				l.ID = id
			}
		}
		if v := o.get("routes"); v != nil {
			l.Routes, _ = p.strList(v, o.sub("routes"), func(it *yaml.Node, ip, name string) bool {
				if !slices.ContainsFunc(routes, func(r Route) bool { return r.Name == name }) {
					p.errorf(it, "%s: no route %q in this environment", ip, name)
					return false
				}
				return true
			})
			p.uniqueStrings(v, o.sub("routes"), l.Routes)
		}
		if v := o.require("key"); v != nil {
			keys, ok := p.strList(v, o.sub("key"), func(it *yaml.Node, ip, k string) bool {
				if !slices.Contains(LimiterKeys, k) {
					p.errorf(it, "%s: %q is not one of %s", ip, k, strings.Join(LimiterKeys, ", "))
					return false
				}
				return true
			})
			if ok && len(keys) == 0 {
				p.errorf(v, "%s: must list at least one dimension", o.sub("key"))
			}
			p.uniqueStrings(v, o.sub("key"), keys)
			if slices.Contains(keys, "asn") && !s.HasArtifact("geoip-asn") {
				p.errorf(v, "%s: the asn dimension needs artifacts.geoip_asn (without it the limiter would skip every request)", o.sub("key"))
			}
			if slices.Contains(keys, "session") && !slices.ContainsFunc(keys, func(k string) bool { return k == "ip" || k == "ip_prefix" }) {
				p.warnf(v, "%s: a session-keyed limiter skips requests without clearance; pair it with an ip or ip_prefix limiter", o.sub("key"))
			}
			l.Key = keys
		}
		if v := o.require("rate"); v != nil {
			if spec, ok := p.str(v, o.sub("rate")); ok {
				if rate, period, err := ParseRate(spec); err != nil {
					p.errorf(v, "%s: %v", o.sub("rate"), err)
				} else {
					l.Rate.Rate, l.Rate.PeriodS = rate, period
				}
			}
		}
		if v := o.get("burst"); v != nil {
			l.Rate.Burst, _ = p.uint(v, o.sub("burst"), 1, 100_000)
		}
		if v := o.get("scope"); v != nil {
			l.Scope, _ = p.enum(v, o.sub("scope"), LimiterScopes)
		}
		if v := o.require("on_exceed"); v != nil {
			l.OnExceed = p.parseOnExceed(v, o.sub("on_exceed"))
		}
		if v := o.get("mode"); v != nil {
			l.Mode, _ = p.enum(v, o.sub("mode"), LimiterModes)
		}
		o.finish()
		if l.Rate.Rate != 0 && l.Rate.Burst != 0 && !GCRAValid(l.Rate) {
			p.errorf(it, "%s: %d per %d s with burst %d is not a valid GCRA limiter (interval must be >= 1 us and interval x burst <= 7 days)", lp, l.Rate.Rate, l.Rate.PeriodS, l.Rate.Burst)
		}
		out = append(out, l)
	}
	return out
}

func (p *parser) parseOnExceed(n *yaml.Node, path string) OnExceed {
	var e OnExceed
	o := p.object(n, path)
	if o == nil {
		return e
	}
	defer o.finish()
	v := o.require("action")
	if v == nil {
		return e
	}
	e.Action, _ = p.enum(v, o.sub("action"), LimiterActions)
	switch e.Action {
	case "signal":
		if w := o.require("weight"); w != nil {
			if f, ok := p.float(w, o.sub("weight"), 0, 2); ok {
				// RateLimit.signal_weight is a float32: a value that rounds
				// to 0 there is 0 to the Edge, which requires (0, 2].
				if float32(f) == 0 {
					p.errorf(w, "%s: must be greater than 0", o.sub("weight"))
				}
				e.Weight = f
			}
		}
	case "challenge":
		if t := o.require("type"); t != nil {
			e.Type, _ = p.enum(t, o.sub("type"), LimiterChallengeTypes)
		}
	case "rate_limit":
		if r := o.get("retry_after_s"); r != nil {
			e.RetryAfterS, _ = p.uint(r, o.sub("retry_after_s"), 0, 86400)
		}
	}
	return e
}

// ParseRate parses "<n>/<duration>" with duration [<n>]s|m|h, e.g. 20/1m,
// 5/15m, 10/s: at least 1 request per 1-86400 seconds.
func ParseRate(spec string) (rate, periodS uint32, err error) {
	m := ratePattern.FindStringSubmatch(spec)
	if m == nil {
		return 0, 0, fmt.Errorf("%q is not <n>/<duration> such as 20/1m, 5/15m or 10/s", spec)
	}
	n, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil || n == 0 {
		return 0, 0, fmt.Errorf("%q: the request count must be between 1 and 4294967295", spec)
	}
	count := uint64(1)
	if m[2] != "" {
		if count, err = strconv.ParseUint(m[2], 10, 32); err != nil || count == 0 {
			return 0, 0, fmt.Errorf("%q: the duration must be at least 1", spec)
		}
	}
	unit := map[string]uint64{"s": 1, "m": 60, "h": 3600}[m[3]]
	if count > 86400/unit {
		return 0, 0, fmt.Errorf("%q: the period must be at most 86400 s", spec)
	}
	return uint32(n), uint32(count * unit), nil
}

// checkHostPartition: the environments' hosts partition the site's hosts.
func (p *parser) checkHostPartition(envNode *yaml.Node, s *Site) {
	owner := map[string]string{}
	for _, env := range s.Environments {
		for _, h := range env.Hosts {
			switch {
			case !slices.Contains(s.Hosts, h):
				p.errorf(envNode, "environments[%s].hosts: %q is not one of the site's hosts", env.Name, h)
			case owner[h] != "":
				p.errorf(envNode, "environments[%s].hosts: %q already belongs to environment %s", env.Name, h, owner[h])
			default:
				owner[h] = env.Name
			}
		}
	}
	for _, h := range s.Hosts {
		if owner[h] == "" {
			p.errorf(envNode, "environments: site host %q belongs to no environment", h)
		}
	}
}
