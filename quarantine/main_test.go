package quarantine_test

import (
	"fmt"
	"os"
	"runtime/pprof"
	"testing"
	"time"
)

// TestMain installs a watchdog that dumps every goroutine if the suite wedges,
// then exits. This makes a deadlock visible in plain `go test` output on
// Windows without needing flags the harness may not allow.
func TestMain(m *testing.M) {
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
			return
		case <-time.After(40 * time.Second):
			fmt.Fprintln(os.Stderr, "WATCHDOG: suite exceeded 40s; dumping goroutines")
			_ = pprof.Lookup("goroutine").WriteTo(os.Stderr, 1)
			os.Exit(3)
		}
	}()
	code := m.Run()
	close(done)
	os.Exit(code)
}
