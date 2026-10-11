package nearline

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

// VerdictPutLua is mg_verdict_put v1, byte for byte as in
// docs/impl/phase2-spec.md §14.2 (verdict_test.go compares the two).
//
//go:embed lua/mg_verdict_put.lua
var VerdictPutLua string

// VerdictPutSHA is the SHA-1 of VerdictPutLua, as SCRIPT LOAD returns it.
var VerdictPutSHA = func() string {
	h := sha1.Sum([]byte(VerdictPutLua))
	return hex.EncodeToString(h[:])
}()

// ConnOptions describe the worker's Valkey connection.
type ConnOptions struct {
	Addr     ValkeyAddr
	User     string
	Password string // never logged
	// ClientName is sent with HELLO (CLIENT SETNAME): "mg-nearline".
	ClientName string
	// DialTimeout bounds connecting; 0 = 5 s.
	DialTimeout time.Duration
}

// clientOption builds the valkey-go options. The handshake must stay inside
// the ACL of spec §13.6: no client-side caching (CLIENT TRACKING), no
// cluster probe, CLIENT SETINFO and SETNAME are allowed.
func (o ConnOptions) clientOption() valkey.ClientOption {
	timeout := o.DialTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	opt := valkey.ClientOption{
		InitAddress:       []string{o.Addr.Address},
		Username:          o.User,
		Password:          o.Password,
		ClientName:        o.ClientName,
		SelectDB:          o.Addr.DB,
		DisableCache:      true,
		ForceSingleClient: true,
		Dialer:            net.Dialer{Timeout: timeout},
		ConnWriteTimeout:  10 * time.Second,
	}
	if o.Addr.Network == "unix" {
		opt.DialCtxFn = func(ctx context.Context, addr string, d *net.Dialer, _ *tls.Config) (net.Conn, error) {
			return d.DialContext(ctx, "unix", addr)
		}
	}
	return opt
}

// Store wraps the Valkey operations of the worker (spec §13.2, §13.4, §13.7).
type Store struct {
	c        valkey.Client
	key      string
	group    string
	consumer string
}

// StreamEntry is one entry of an XREADGROUP / XAUTOCLAIM reply.
type StreamEntry struct {
	ID     string
	Fields []string // alternating field / value; nil for a deleted entry
}

// Dial connects and checks the connection with PING.
func Dial(ctx context.Context, o ConnOptions, key, group, consumer string) (*Store, error) {
	c, err := valkey.NewClient(o.clientOption())
	if err != nil {
		return nil, fmt.Errorf("valkey connect: %w", scrub(err, o.Password))
	}
	s := &Store{c: c, key: key, group: group, consumer: consumer}
	if err := c.Do(ctx, c.B().Ping().Build()).Error(); err != nil {
		c.Close()
		return nil, fmt.Errorf("valkey PING: %w", scrub(err, o.Password))
	}
	return s, nil
}

// scrub removes the password from an error text, should a library ever
// echo it.
func scrub(err error, password string) error {
	if err == nil || password == "" || !strings.Contains(err.Error(), password) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), password, "<redacted>"))
}

// Close closes the connections.
func (s *Store) Close() { s.c.Close() }

// Client returns the underlying client (tests).
func (s *Store) Client() valkey.Client { return s.c }

// Consumer returns the consumer name.
func (s *Store) Consumer() string { return s.consumer }

// LoadScript loads mg_verdict_put and checks that the server's SHA-1 is the
// expected one.
func (s *Store) LoadScript(ctx context.Context) error {
	sha, err := s.c.Do(ctx, s.c.B().ScriptLoad().Script(VerdictPutLua).Build()).ToString()
	if err != nil {
		return fmt.Errorf("SCRIPT LOAD: %w", err)
	}
	if sha != VerdictPutSHA {
		return fmt.Errorf("SCRIPT LOAD returned an unexpected SHA-1 %q", sha)
	}
	return nil
}

// EnsureGroup creates the consumer group at the stream's end ($), creating
// the stream if needed; an existing group is kept.
func (s *Store) EnsureGroup(ctx context.Context) (created bool, err error) {
	err = s.c.Do(ctx, s.c.B().XgroupCreate().Key(s.key).Group(s.group).Id("$").Mkstream().Build()).Error()
	if err == nil {
		return true, nil
	}
	if valkey.IsValkeyBusyGroup(err) {
		return false, nil
	}
	return false, fmt.Errorf("XGROUP CREATE: %w", err)
}

// ConsumerInfo is one row of XINFO CONSUMERS.
type ConsumerInfo struct {
	Name    string
	Pending int64
}

// Consumers lists the group's consumers.
func (s *Store) Consumers(ctx context.Context) ([]ConsumerInfo, error) {
	rows, err := s.c.Do(ctx, s.c.B().XinfoConsumers().Key(s.key).Group(s.group).Build()).ToArray()
	if err != nil {
		return nil, fmt.Errorf("XINFO CONSUMERS: %w", err)
	}
	out := make([]ConsumerInfo, 0, len(rows))
	for _, r := range rows {
		m, err := r.AsMap()
		if err != nil {
			return nil, fmt.Errorf("XINFO CONSUMERS: %w", err)
		}
		name, err := msgString(m["name"])
		if err != nil {
			return nil, fmt.Errorf("XINFO CONSUMERS name: %w", err)
		}
		pending, err := msgInt(m["pending"])
		if err != nil {
			return nil, fmt.Errorf("XINFO CONSUMERS pending: %w", err)
		}
		out = append(out, ConsumerInfo{Name: name, Pending: pending})
	}
	return out, nil
}

// DeleteIdleConsumers deletes the group's other consumers that have no
// pending entries (earlier processes). Consumers with pending entries stay
// until XAUTOCLAIM has taken their entries over.
func (s *Store) DeleteIdleConsumers(ctx context.Context) ([]string, error) {
	cs, err := s.Consumers(ctx)
	if err != nil {
		return nil, err
	}
	var deleted []string
	for _, c := range cs {
		if c.Name == s.consumer || c.Pending != 0 {
			continue
		}
		if err := s.c.Do(ctx, s.c.B().XgroupDelconsumer().Key(s.key).Group(s.group).Consumername(c.Name).Build()).Error(); err != nil {
			return deleted, fmt.Errorf("XGROUP DELCONSUMER: %w", err)
		}
		deleted = append(deleted, c.Name)
	}
	return deleted, nil
}

// ReadGroup reads up to count new entries, blocking up to blockMs.
func (s *Store) ReadGroup(ctx context.Context, count, blockMs int) ([]StreamEntry, error) {
	cmd := s.c.B().Xreadgroup().Group(s.group, s.consumer).Count(int64(count)).Block(int64(blockMs)).Streams().Key(s.key).Id(">").Build()
	res := s.c.Do(ctx, cmd)
	if err := res.Error(); err != nil {
		if valkey.IsValkeyNil(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("XREADGROUP: %w", err)
	}
	msg, err := res.ToMessage()
	if err != nil {
		return nil, fmt.Errorf("XREADGROUP: %w", err)
	}
	if msg.IsNil() {
		return nil, nil
	}
	// RESP3: a map {key: entries}; RESP2: [[key, entries]].
	var entries valkey.ValkeyMessage
	if m, err := msg.ToMap(); err == nil {
		e, ok := m[s.key]
		if !ok {
			return nil, nil
		}
		entries = e
	} else {
		arr, err := msg.ToArray()
		if err != nil {
			return nil, fmt.Errorf("XREADGROUP reply: %w", err)
		}
		for _, kv := range arr {
			pair, err := kv.ToArray()
			if err != nil || len(pair) != 2 {
				return nil, errors.New("XREADGROUP reply: malformed stream element")
			}
			if k, _ := pair[0].ToString(); k == s.key {
				entries = pair[1]
			}
		}
	}
	return parseEntries(entries)
}

// AutoClaim claims up to count entries idle for at least idleMs, starting at
// start. It returns the next cursor ("0-0" when the scan is complete).
func (s *Store) AutoClaim(ctx context.Context, idleMs int64, start string, count int) (string, []StreamEntry, error) {
	cmd := s.c.B().Xautoclaim().Key(s.key).Group(s.group).Consumer(s.consumer).MinIdleTime(strconv.FormatInt(idleMs, 10)).Start(start).Count(int64(count)).Build()
	arr, err := s.c.Do(ctx, cmd).ToArray()
	if err != nil {
		return "", nil, fmt.Errorf("XAUTOCLAIM: %w", err)
	}
	if len(arr) < 2 {
		return "", nil, errors.New("XAUTOCLAIM: short reply")
	}
	next, err := arr[0].ToString()
	if err != nil {
		return "", nil, fmt.Errorf("XAUTOCLAIM cursor: %w", err)
	}
	entries, err := parseEntries(arr[1])
	if err != nil {
		return "", nil, fmt.Errorf("XAUTOCLAIM: %w", err)
	}
	return next, entries, nil
}

// Ack acknowledges ids.
func (s *Store) Ack(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if err := s.c.Do(ctx, s.c.B().Xack().Key(s.key).Group(s.group).Id(ids...).Build()).Error(); err != nil {
		return fmt.Errorf("XACK: %w", err)
	}
	return nil
}

// PutVerdict runs mg_verdict_put (EVALSHA; on NOSCRIPT it loads the script
// and retries once). It reports whether the verdict was written.
func (s *Store) PutVerdict(ctx context.Context, key, value string, ttlMs int64, risk int, nowMs int64, source string) (bool, error) {
	cmd := func() valkey.Completed {
		return s.c.B().Evalsha().Sha1(VerdictPutSHA).Numkeys(1).Key(key).
			Arg(value, strconv.FormatInt(ttlMs, 10), strconv.Itoa(risk), strconv.FormatInt(nowMs, 10), source).Build()
	}
	n, err := s.c.Do(ctx, cmd()).AsInt64()
	if ve, ok := valkey.IsValkeyErr(err); ok && ve.IsNoScript() {
		if err := s.LoadScript(ctx); err != nil {
			return false, err
		}
		n, err = s.c.Do(ctx, cmd()).AsInt64()
	}
	if err != nil {
		return false, fmt.Errorf("EVALSHA mg_verdict_put: %w", err)
	}
	return n == 1, nil
}

// GroupInfo is the group's row of XINFO GROUPS.
type GroupInfo struct {
	Lag           int64 // undelivered entries
	LagKnown      bool  // false when Valkey reports lag as nil
	Pending       int64
	LastDelivered string
}

// Group returns the XINFO GROUPS row of the worker's group.
func (s *Store) Group(ctx context.Context) (GroupInfo, error) {
	rows, err := s.c.Do(ctx, s.c.B().XinfoGroups().Key(s.key).Build()).ToArray()
	if err != nil {
		return GroupInfo{}, fmt.Errorf("XINFO GROUPS: %w", err)
	}
	for _, r := range rows {
		m, err := r.AsMap()
		if err != nil {
			return GroupInfo{}, fmt.Errorf("XINFO GROUPS: %w", err)
		}
		if name, _ := msgString(m["name"]); name != s.group {
			continue
		}
		var g GroupInfo
		if g.Pending, err = msgInt(m["pending"]); err != nil {
			return GroupInfo{}, fmt.Errorf("XINFO GROUPS pending: %w", err)
		}
		g.LastDelivered, _ = msgString(m["last-delivered-id"])
		if lag, ok := m["lag"]; ok && !lag.IsNil() {
			if g.Lag, err = msgInt(lag); err != nil {
				return GroupInfo{}, fmt.Errorf("XINFO GROUPS lag: %w", err)
			}
			g.LagKnown = true
		}
		return g, nil
	}
	return GroupInfo{}, fmt.Errorf("XINFO GROUPS: group %q not found", s.group)
}

// PendingSummary returns XPENDING's count and smallest pending ID.
func (s *Store) PendingSummary(ctx context.Context) (int64, string, error) {
	arr, err := s.c.Do(ctx, s.c.B().Xpending().Key(s.key).Group(s.group).Build()).ToArray()
	if err != nil {
		return 0, "", fmt.Errorf("XPENDING: %w", err)
	}
	if len(arr) < 2 {
		return 0, "", errors.New("XPENDING: short reply")
	}
	n, err := arr[0].AsInt64()
	if err != nil {
		return 0, "", fmt.Errorf("XPENDING count: %w", err)
	}
	if n == 0 {
		return 0, "", nil
	}
	minID, err := arr[1].ToString()
	if err != nil {
		return 0, "", fmt.Errorf("XPENDING min id: %w", err)
	}
	return n, minID, nil
}

// StreamLen returns XLEN of the stream.
func (s *Store) StreamLen(ctx context.Context) (int64, error) {
	return s.c.Do(ctx, s.c.B().Xlen().Key(s.key).Build()).AsInt64()
}

// IDMillis returns the millisecond part of a stream ID ("<ms>-<seq>").
func IDMillis(id string) (int64, bool) {
	ms, _, ok := strings.Cut(id, "-")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(ms, 10, 64)
	return n, err == nil
}

func parseEntries(m valkey.ValkeyMessage) ([]StreamEntry, error) {
	if m.IsNil() {
		return nil, nil
	}
	arr, err := m.ToArray()
	if err != nil {
		return nil, fmt.Errorf("entries: %w", err)
	}
	out := make([]StreamEntry, 0, len(arr))
	for _, it := range arr {
		pair, err := it.ToArray()
		if err != nil || len(pair) != 2 {
			return nil, errors.New("entries: malformed entry")
		}
		id, err := pair[0].ToString()
		if err != nil {
			return nil, fmt.Errorf("entry id: %w", err)
		}
		e := StreamEntry{ID: id}
		if !pair[1].IsNil() {
			fv, err := pair[1].ToArray()
			if err != nil {
				// A RESP3 server could send the fields as a map; mg:ev entries
				// are always arrays, so anything else is unreadable.
				out = append(out, StreamEntry{ID: id, Fields: []string{"\x00"}})
				continue
			}
			e.Fields = make([]string, 0, len(fv))
			for _, f := range fv {
				sv, err := f.ToString()
				if err != nil {
					e.Fields = []string{"\x00"}
					break
				}
				e.Fields = append(e.Fields, sv)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

func msgString(m valkey.ValkeyMessage) (string, error) { return m.ToString() }

func msgInt(m valkey.ValkeyMessage) (int64, error) {
	if n, err := m.AsInt64(); err == nil {
		return n, nil
	}
	return m.ToInt64()
}
