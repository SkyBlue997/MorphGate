package nearline

import (
	"os"
	"strings"
	"testing"
	"time"
)

const specPath = "../../../docs/impl/phase2-spec.md"

// specACL returns the arguments of the §13.6 ACL SETUSER line, read from the
// spec itself so that the test cannot drift from it.
func specACL(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ACL SETUSER mg-nearline ") {
			return strings.Fields(line)
		}
	}
	t.Fatal("the spec has no ACL SETUSER mg-nearline line")
	return nil
}

// aclUser creates the §13.6 user for the fixture's site with a random name
// and password and returns them. Only the user name, the password and the
// site of ~mg:v:<site>:* differ from the spec's line.
func (fx *fixture) aclUser() (string, string) {
	t := fx.t
	t.Helper()
	args := specACL(t)
	user, password := "mg-nearline-t"+randHex(4), randHex(16)
	sawKey := false
	for i, a := range args {
		switch {
		case a == "mg-nearline":
			args[i] = user
		case strings.HasPrefix(a, ">"):
			args[i] = ">" + password
		case a == "~mg:v:blog:*":
			args[i] = "~mg:v:" + fx.site + ":*"
			sawKey = true
		}
	}
	if !sawKey || args[0] != "ACL" || args[1] != "SETUSER" {
		t.Fatalf("unexpected ACL line %q", args)
	}
	if err := fx.do(args...).Error(); err != nil {
		t.Fatalf("ACL SETUSER: %v", err)
	}
	t.Cleanup(func() { _ = fx.do("ACL", "DELUSER", user).Error() })
	return user, password
}

func TestACLUserRunsEveryOperation(t *testing.T) {
	fx := needValkey(t)
	user, password := fx.aclUser()
	cfg := fx.config()
	cfg.Detectors.Scanner.Mode = ModeEnforce
	cfg.Stream.ReclaimIdleMs = 1 // test only: claim at once
	o := fx.connOptions(user, password)

	// --check-config as the user.
	if err := CheckValkeyWith(fx.ctx, o, cfg); err != nil {
		t.Fatalf("check as ACL user: %v", err)
	}
	// A stale consumer with nothing pending and one with a pending entry.
	fx.do("XGROUP", "CREATE", fx.key, "nl", "$", "MKSTREAM")
	fx.do("XGROUP", "CREATECONSUMER", fx.key, "nl", "old-idle")
	fx.xadd(decisionFV(fx.site, time.Now().UnixMilli(), map[string]string{"bt": "1", "ph": "00000000000000a1", "status": "404"})...)
	if err := fx.do("XREADGROUP", "GROUP", "nl", "old-busy", "COUNT", "10", "STREAMS", fx.key, ">").Error(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)

	s := fx.store(o, "w-1")
	// Ruling I-46: the handshake names the client (HELLO ... SETNAME) and
	// sends no CLIENT SETINFO.
	list, err := fx.do("CLIENT", "LIST").ToString()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for line := range strings.SplitSeq(list, "\n") {
		if strings.Contains(line, " user="+user+" ") {
			found = true
			if !strings.Contains(line, " name="+ClientName+" ") || !strings.Contains(line, " lib-name= ") {
				t.Errorf("worker connection: %s", line)
			}
		}
	}
	if !found {
		t.Fatal("no connection of the ACL user in CLIENT LIST")
	}
	m := NewMetrics(cfg)
	w := NewWorker(cfg, s, m, nil, nil, nil)
	if err := w.Start(fx.ctx); err != nil { // SCRIPT LOAD, XGROUP CREATE, XAUTOCLAIM, XINFO CONSUMERS, XGROUP DELCONSUMER, XACK
		t.Fatalf("Start as ACL user: %v", err)
	}
	fx.xadd(decisionFV(fx.site, time.Now().UnixMilli(), map[string]string{"bt": "1", "ph": "00000000000000a2", "status": "404"})...)
	if err := w.Step(fx.ctx); err != nil { // XREADGROUP, EVALSHA, XACK
		t.Fatalf("Step as ACL user: %v", err)
	}
	if err := w.PollStatus(fx.ctx); err != nil { // XINFO GROUPS, XPENDING
		t.Fatalf("PollStatus as ACL user: %v", err)
	}
	if _, err := s.StreamLen(fx.ctx); err != nil {
		t.Fatalf("XLEN: %v", err)
	}
	vkey := "mg:v:" + fx.site + ":ip:" + testIPK(1)
	if v, err := fx.do("GET", vkey).ToString(); err != nil || !strings.Contains(v, `"source":"nearline/scanner"`) {
		t.Fatalf("verdict not written as the ACL user: %q %v", v, err)
	}
	cs, err := s.Consumers(fx.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].Name != "w-1" {
		t.Fatalf("consumers after Start: %+v (old-idle and the drained old-busy must be gone)", cs)
	}
	// NOSCRIPT recovery uses SCRIPT LOAD, never EVAL.
	fx.do("SCRIPT", "FLUSH")
	if _, err := s.PutVerdict(fx.ctx, "mg:v:"+fx.site+":ip:x", `{"risk":1}`, 1000, 1, time.Now().UnixMilli(), "nearline/scanner"); err != nil {
		t.Fatalf("PutVerdict after SCRIPT FLUSH: %v", err)
	}

	// Everything else is refused.
	c := s.Client()
	other := "mg:v:other" + randHex(4) + ":ip:" + testIPK(1)
	denied := [][]string{
		{"GET", other},
		{"SET", other, "1"},
		{"GET", "mg:v:all:ip:" + testIPK(1)},
		{"SET", "mg:rl:" + fx.site + ":x:y", "1"},
		{"GET", "mg:n:" + fx.site + ":00"},
		{"GET", "mg:rev:" + fx.site},
		{"XADD", fx.key, "*", "v", "2"},
		{"XRANGE", fx.key, "-", "+"},
		{"XTRIM", fx.key, "MAXLEN", "0"},
		{"XGROUP", "DESTROY", fx.key, "nl"},
		{"XGROUP", "SETID", fx.key, "nl", "0"},
		{"XDEL", fx.key, "0-1"},
		{"DEL", fx.key},
		{"DEL", "mg:v:" + fx.site + ":ip:x"},
		{"EVAL", "return 1", "0"},
		{"EVALSHA", VerdictPutSHA, "1", other, "{}", "1000", "1", "0", "nearline/scanner"},
		{"EVALSHA", VerdictPutSHA, "1", "mg:v:all:ip:" + testIPK(1), "{}", "1000", "1", "0", "nearline/scanner"},
		{"PUBLISH", "mg:pub:inv", "x"},
		{"KEYS", "*"},
		{"SCAN", "0"},
		{"FLUSHDB"},
		{"FLUSHALL"},
		{"CONFIG", "GET", "*"},
		{"SCRIPT", "FLUSH"},
		{"SCRIPT", "KILL"},
		{"ACL", "LIST"},
		{"CLIENT", "LIST"},
		{"CLIENT", "KILL", "ID", "1"},
		{"MGET", vkey},
		{"INFO"},
	}
	for _, cmd := range denied {
		err := c.Do(fx.ctx, c.B().Arbitrary(cmd[0]).Args(cmd[1:]...).Build()).Error()
		if err == nil || !strings.Contains(err.Error(), "NOPERM") {
			t.Errorf("%s as the ACL user: %v, want NOPERM", strings.Join(cmd[:min(2, len(cmd))], " "), err)
		}
	}
	// The ACL cannot restrict writes to the script (spec §13.6): a direct SET
	// of this site's verdict key is allowed.
	if err := c.Do(fx.ctx, c.B().Arbitrary("SET").Args("mg:v:"+fx.site+":ip:y", "{}").Build()).Error(); err != nil {
		t.Errorf("SET of an own verdict key: %v", err)
	}
}
