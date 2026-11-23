//go:build windows

package quarantine

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

type fileLock struct {
	f *os.File
}

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = kernel32.NewProc("LockFileEx")
	procUnlockFileEx = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002
)

// acquireFileLock takes an exclusive byte-range lock on path through
// LockFileEx. Unlike an exclusive-create lock file, the OS releases this lock
// when the process exits, so a crash cannot leave the data directory
// permanently locked.
func acquireFileLock(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	var ol syscall.Overlapped
	r1, _, e1 := procLockFileEx.Call(
		f.Fd(),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0, 1, 0,
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		f.Close()
		if e1 != nil && e1 != syscall.Errno(0) {
			return nil, fmt.Errorf("quarantine: data directory is locked by another process: %w", e1)
		}
		return nil, fmt.Errorf("quarantine: data directory is locked by another process")
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) release() error {
	var ol syscall.Overlapped
	_, _, _ = procUnlockFileEx.Call(l.f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	return l.f.Close()
}
