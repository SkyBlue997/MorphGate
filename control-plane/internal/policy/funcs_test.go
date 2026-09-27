package policy

import "testing"

func TestIPIn(t *testing.T) {
	cases := []struct {
		ip      string
		list    []string
		want    bool
		wantErr bool
	}{
		{"10.1.2.3", []string{"10.0.0.0/8"}, true, false},
		{"11.1.2.3", []string{"10.0.0.0/8"}, false, false},
		{"192.0.2.1", []string{"192.0.2.1"}, true, false},
		{"192.0.2.2", []string{"192.0.2.1"}, false, false},
		{"::ffff:10.0.0.1", []string{"10.0.0.0/8"}, true, false},
		{"10.0.0.1", []string{"::ffff:10.0.0.0/104"}, true, false},
		{"2001:db8::1", []string{"2001:db8::/32"}, true, false},
		{"2001:db9::1", []string{"2001:db8::/32"}, false, false},
		{"10.0.0.1", []string{"10.0.0.5/8"}, true, false}, // host bits are masked
		{"10.0.0.1", nil, false, false},
		{"not-an-ip", []string{"0.0.0.0/0"}, false, false},
		{"", []string{"0.0.0.0/0"}, false, false},
		{"10.0.0.1", []string{"10.0.0.0/8", "bogus"}, false, true}, // bad entries always error
		{"10.0.0.1", []string{"10.0.0.0/33"}, false, true},
		{"fe80::1", []string{"fe80::1%eth0"}, false, true},
	}
	for _, tc := range cases {
		got, err := ipIn(tc.ip, tc.list)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ipIn(%q, %q) = %v, %v; want %v, err=%v", tc.ip, tc.list, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		s, pattern string
		want       bool
	}{
		{"/admin", "/admin", true},
		{"/admin/", "/admin", false},
		{"/admin/users", "/admin/*", true},
		{"/admin/users/1", "/admin/*", false},
		{"/admin/users/1", "/admin/**", true},
		{"/admin", "/admin/**", false},
		{"/admin/", "/admin/**", true},
		{"/api/v1/login", "/api/*/login", true},
		{"/api/v1/x/login", "/api/*/login", false},
		{"/api/v1/x/login", "/api/**/login", true},
		{"/a.js", "/*.js", true},
		{"/a/b.js", "/*.js", false},
		{"/a/b.js", "/**.js", true},
		{"/ab", "/a?", true},
		{"/a/", "/a?", false},
		{"/A", "/a", false},
		{"", "**", true},
		{"", "*", true},
		{"x", "", false},
		{"/日本/語", "/*/?", true},
		{"/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab", "/*a*a*a*a*a*a*a*a*a*a*c", false},
	}
	for _, tc := range cases {
		got, err := glob(tc.s, tc.pattern)
		if tc.pattern == "" {
			if err == nil {
				t.Errorf("glob(%q, \"\") returned no error", tc.s)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("glob(%q, %q) = %v, %v; want %v", tc.s, tc.pattern, got, err, tc.want)
		}
	}
}
