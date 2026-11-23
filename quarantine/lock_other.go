//go:build !windows

package quarantine

import (
	"os"
	"syscall"
)

type fileLock struct {
	f *os.File
}

// acquireFileLock uses a non-blocking POSIX advisory lock. The project targets
// Windows; this keeps the package buildable elsewhere for development.
func acquireFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) release() error {
	err := syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	cerr := l.f.Close()
	if err != nil {
		return err
	}
	return cerr
}
