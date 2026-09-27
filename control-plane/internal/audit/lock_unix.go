//go:build unix

package audit

import (
	"fmt"
	"os"
	"syscall"
)

// lock takes an exclusive flock on <log>.lock (§12.8) and returns the
// function that releases it.
func (l *Log) lock() (func(), error) {
	f, err := os.OpenFile(l.path+".lock", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log lock: %w", err)
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("audit log lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
