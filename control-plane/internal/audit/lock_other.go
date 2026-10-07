//go:build !unix

package audit

import "errors"

// lock is unsupported off Unix: mgctl's audit log relies on flock (§12.8).
func (l *Log) lock() (func(), error) {
	return nil, errors.New("audit log locking (flock) is only supported on Unix")
}
