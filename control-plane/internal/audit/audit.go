// Package audit is mgctl's local, append-only, hash-chained audit log
// (docs/06 §6, docs/impl/phase1-spec.md §12.8).
//
// Each line is one JSON record. hash = lower_hex(SHA-256(prev_hash || "\n" ||
// canonical)), where canonical is the record without its hash member, keys
// in the order of Record, no insignificant whitespace and no HTML escaping;
// the first record chains to 64 zeros. A line must be exactly the canonical
// serialisation of its record plus the hash, so changing any byte of the file
// breaks the chain at that line. Appends hold an exclusive flock on
// <log>.lock and fsync the file.
package audit

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"morphgate/control-plane/internal/cli"
)

// EnvAuditLog overrides the default audit log path.
const EnvAuditLog = "MGCTL_AUDIT_LOG"

// GenesisHash is the prev_hash of the first record.
var GenesisHash = strings.Repeat("0", 64)

// maxLine bounds one record (diffs are small summaries).
const maxLine = 1 << 20

// tsLayout always renders nine fractional digits so records sort and
// compare as plain strings.
const tsLayout = "2006-01-02T15:04:05.000000000Z07:00"

// Record is one audit log line (§12.8, fields in this order).
type Record struct {
	ID           string          `json:"id"`
	TS           string          `json:"ts"`
	Actor        string          `json:"actor"`
	ActorKind    string          `json:"actor_kind"`
	Auth         string          `json:"auth"`
	ReauthAt     *string         `json:"reauth_at"`
	ActorIP      string          `json:"actor_ip"`
	Site         string          `json:"site"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Diff         json.RawMessage `json:"diff"`
	Reason       string          `json:"reason"`
	ConfirmText  string          `json:"confirm_text"`
	EffectiveAt  string          `json:"effective_at"`
	RequestID    string          `json:"request_id"`
	PrevHash     string          `json:"prev_hash"`
	Hash         string          `json:"hash"`
}

// unhashed is Record without the hash member: the canonical form hashed.
type unhashed struct {
	ID           string          `json:"id"`
	TS           string          `json:"ts"`
	Actor        string          `json:"actor"`
	ActorKind    string          `json:"actor_kind"`
	Auth         string          `json:"auth"`
	ReauthAt     *string         `json:"reauth_at"`
	ActorIP      string          `json:"actor_ip"`
	Site         string          `json:"site"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Diff         json.RawMessage `json:"diff"`
	Reason       string          `json:"reason"`
	ConfirmText  string          `json:"confirm_text"`
	EffectiveAt  string          `json:"effective_at"`
	RequestID    string          `json:"request_id"`
	PrevHash     string          `json:"prev_hash"`
}

// DefaultPath returns MGCTL_AUDIT_LOG, else $XDG_STATE_HOME/morphgate/audit.jsonl,
// else ~/.local/state/morphgate/audit.jsonl. (The --audit-log flag, handled by
// the caller, takes precedence over all of these.) A relative XDG_STATE_HOME
// is ignored, as the XDG Base Directory specification requires.
func DefaultPath(getenv func(string) string) (string, error) {
	if p := getenv(EnvAuditLog); p != "" {
		return p, nil
	}
	if d := getenv("XDG_STATE_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "morphgate", "audit.jsonl"), nil
	}
	if h := getenv("HOME"); h != "" {
		return filepath.Join(h, ".local", "state", "morphgate", "audit.jsonl"), nil
	}
	return "", fmt.Errorf("cannot place the audit log: set --audit-log, %s, XDG_STATE_HOME or HOME", EnvAuditLog)
}

// Log is an open audit log.
type Log struct {
	path string
}

// Open prepares the log at path: it creates missing directories (0700),
// checks that the last record of an existing file is intact and that the file
// can be appended to (creating an empty log if there is none), so that a
// command can fail before it writes anything when the log is unusable
// (ruling I-27). A read-only log would otherwise pass here and fail only in
// Append, after the command's change was made.
func Open(path string) (*Log, error) {
	if path == "" {
		return nil, errors.New("audit log path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	l := &Log{path: path}
	unlock, err := l.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if _, err := l.tailHash(); err != nil {
		return nil, err
	}
	// The same open as Append's, without writing: an existing log's bytes
	// are unchanged, a missing one becomes a valid empty log.
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return l, nil
}

// Path is the log file.
func (l *Log) Path() string { return l.path }

// Append writes one record for ev and returns it.
func (l *Log) Append(ev cli.AuditEvent, now time.Time) (*Record, error) {
	diff := json.RawMessage("null")
	if ev.Diff != nil {
		b, err := marshalCompact(ev.Diff)
		if err != nil {
			return nil, fmt.Errorf("audit diff: %w", err)
		}
		diff = b
	}
	var idb [16]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, fmt.Errorf("audit id: %w", err)
	}
	effective := ev.EffectiveAt
	if effective.IsZero() {
		effective = now
	}
	rec := &Record{
		ID:           hex.EncodeToString(idb[:]),
		TS:           now.UTC().Format(tsLayout),
		Actor:        "owner",
		ActorKind:    "owner",
		Auth:         "local",
		Site:         ev.Site,
		Action:       ev.Action,
		ResourceType: ev.ResourceType,
		ResourceID:   ev.ResourceID,
		Diff:         diff,
		Reason:       ev.Reason,
		ConfirmText:  ev.ConfirmText,
		EffectiveAt:  effective.UTC().Format(tsLayout),
	}

	unlock, err := l.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	prev, err := l.tailHash()
	if err != nil {
		return nil, err
	}
	rec.PrevHash = prev
	line, err := rec.seal()
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit log: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return rec, nil
}

// seal computes rec.Hash from its other members and returns the line.
func (rec *Record) seal() ([]byte, error) {
	canonical, err := marshalCompact(unhashed{
		rec.ID, rec.TS, rec.Actor, rec.ActorKind, rec.Auth, rec.ReauthAt, rec.ActorIP, rec.Site,
		rec.Action, rec.ResourceType, rec.ResourceID, rec.Diff, rec.Reason, rec.ConfirmText,
		rec.EffectiveAt, rec.RequestID, rec.PrevHash,
	})
	if err != nil {
		return nil, err
	}
	rec.Hash = ChainHash(rec.PrevHash, canonical)
	return marshalCompact(rec)
}

// ChainHash is lower_hex(SHA-256(prevHash || "\n" || canonical)).
func ChainHash(prevHash string, canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte{'\n'})
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

// marshalCompact is json.Marshal without HTML escaping.
func marshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte{'\n'}), nil
}

// parseLine decodes and re-seals one line: it fails unless the line is the
// canonical serialisation of a record whose hash matches.
func parseLine(line []byte) (*Record, error) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.DisallowUnknownFields()
	var rec Record
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("invalid record: %v", err)
	}
	claimed := rec.Hash
	again, err := rec.seal()
	if err != nil {
		return nil, fmt.Errorf("invalid record: %v", err)
	}
	if rec.Hash != claimed {
		return nil, errors.New("hash does not match the record")
	}
	if !bytes.Equal(again, line) {
		return nil, errors.New("record is not in canonical form (bytes changed)")
	}
	return &rec, nil
}

// tailHash returns the hash of the last record (GenesisHash for an empty or
// missing file) after checking that record. Callers hold the lock.
func (l *Log) tailHash() (string, error) {
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return GenesisHash, nil
	}
	if err != nil {
		return "", fmt.Errorf("audit log: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("audit log: %w", err)
	}
	if st.Size() == 0 {
		return GenesisHash, nil
	}
	start := max(st.Size()-maxLine-1, 0)
	buf := make([]byte, st.Size()-start)
	if _, err := f.ReadAt(buf, start); err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("audit log: %w", err)
	}
	if !bytes.HasSuffix(buf, []byte{'\n'}) {
		return "", fmt.Errorf("audit log %s: the last line is incomplete; run `mgctl audit verify`", l.path)
	}
	body := buf[:len(buf)-1]
	last := body[bytes.LastIndexByte(body, '\n')+1:]
	rec, err := parseLine(last)
	if err != nil {
		return "", fmt.Errorf("audit log %s: last record: %v; run `mgctl audit verify`", l.path, err)
	}
	return rec.Hash, nil
}

// VerifyError reports the first broken line of a log.
type VerifyError struct {
	Line int // 1-based
	Err  error
}

func (e *VerifyError) Error() string { return fmt.Sprintf("line %d: %v", e.Line, e.Err) }
func (e *VerifyError) Unwrap() error { return e.Err }

// Verify checks the whole chain. It returns the number of records and the
// last hash (GenesisHash for an empty file); a *VerifyError names the first
// broken line.
func Verify(path string) (count int, lastHash string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	prev := GenesisHash
	for n := 1; ; n++ {
		line, rerr := readLine(r)
		if rerr == io.EOF {
			return count, prev, nil
		}
		if rerr != nil {
			return count, prev, &VerifyError{Line: n, Err: rerr}
		}
		rec, err := parseLine(line)
		if err != nil {
			return count, prev, &VerifyError{Line: n, Err: err}
		}
		if rec.PrevHash != prev {
			return count, prev, &VerifyError{Line: n, Err: fmt.Errorf("prev_hash %s does not match the previous record's hash %s (a record was removed, reordered or changed)", rec.PrevHash, prev)}
		}
		prev = rec.Hash
		count++
	}
}

// readLine returns one '\n'-terminated line without the terminator; io.EOF at
// a clean end; an error for an unterminated or oversized last line.
func readLine(r *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > maxLine+1 {
			return nil, fmt.Errorf("line longer than %d bytes", maxLine)
		}
		switch {
		case err == nil:
			return line[:len(line)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			if len(line) == 0 {
				return nil, io.EOF
			}
			return nil, errors.New("incomplete last line (no newline)")
		default:
			return nil, err
		}
	}
}
