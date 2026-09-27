package keys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strconv"

	"golang.org/x/term"

	"morphgate/control-plane/internal/cli"
)

// Environment variables read by the passphrase flow (§12.6, §14.1).
const (
	EnvPassphraseFile = "MGCTL_PASSPHRASE_FILE"
	EnvWorkFactor     = "MGCTL_AGE_WORK_FACTOR"
)

// maxPassphraseFile bounds MGCTL_PASSPHRASE_FILE.
const maxPassphraseFile = 4096

// openTTY opens the controlling terminal; tests replace it.
var openTTY = func() (*os.File, error) { return os.OpenFile("/dev/tty", os.O_RDWR, 0) }

// ErrUsage marks errors that are the caller's fault (exit code 2).
var ErrUsage = errors.New("usage")

// ReadPassphrase returns the passphrase for age key files: the first line of
// the file named by MGCTL_PASSPHRASE_FILE (tests and automation), otherwise
// read without echo from the terminal (stdin when it is one, else /dev/tty),
// twice when confirm is set. A passphrase never comes from the command line.
func ReadPassphrase(env cli.Env, confirm bool) ([]byte, error) {
	if path := env.Getenv(EnvPassphraseFile); path != "" {
		data, err := ReadFileLimit(path, maxPassphraseFile)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", EnvPassphraseFile, err)
		}
		line, _, _ := bytes.Cut(data, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			return nil, fmt.Errorf("%s: the first line of %s is empty", EnvPassphraseFile, path)
		}
		return line, nil
	}
	tty, closeTTY, err := terminal(env)
	if err != nil {
		return nil, err
	}
	defer closeTTY()
	fmt.Fprint(env.Stderr, "Passphrase: ")
	p, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(env.Stderr)
	if err != nil {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	if len(p) == 0 {
		return nil, errors.New("empty passphrase")
	}
	if confirm {
		fmt.Fprint(env.Stderr, "Confirm passphrase: ")
		again, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(env.Stderr)
		if err != nil {
			return nil, fmt.Errorf("reading passphrase: %w", err)
		}
		if !bytes.Equal(p, again) {
			return nil, errors.New("the passphrases do not match")
		}
	}
	return p, nil
}

// terminal returns stdin when it is a terminal, else the controlling terminal.
func terminal(env cli.Env) (*os.File, func(), error) {
	if f, ok := env.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		return f, func() {}, nil
	}
	f, err := openTTY()
	if err != nil || !term.IsTerminal(int(f.Fd())) {
		if f != nil {
			f.Close()
		}
		return nil, nil, fmt.Errorf("no passphrase: set %s or run mgctl on a terminal", EnvPassphraseFile)
	}
	return f, func() { f.Close() }, nil
}

// WorkFactor returns the scrypt work factor for new age files:
// MGCTL_AGE_WORK_FACTOR (10-22) or the default 18. Values below 18 are
// refused unless insecureTestKey is set (--insecure-test-key); the error then
// wraps ErrUsage.
func WorkFactor(getenv func(string) string, insecureTestKey bool) (int, error) {
	s := getenv(EnvWorkFactor)
	if s == "" {
		return DefaultWorkFactor, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < MinWorkFactor || n > MaxWorkFactor {
		return 0, fmt.Errorf("%w: %s must be an integer between %d and %d, got %q", ErrUsage, EnvWorkFactor, MinWorkFactor, MaxWorkFactor, s)
	}
	if n < SafeWorkFactor && !insecureTestKey {
		return 0, fmt.Errorf("%w: %s=%d is below %d; such keys are for tests only and need --insecure-test-key", ErrUsage, EnvWorkFactor, n, SafeWorkFactor)
	}
	return n, nil
}
