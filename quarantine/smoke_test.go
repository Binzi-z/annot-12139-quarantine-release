package quarantine_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"quarantine/quarantine"
)

func newEngine(t *testing.T, cfg quarantine.Config) *quarantine.Engine {
	t.Helper()
	if cfg.DataDir == "" {
		cfg.DataDir = t.TempDir()
	}
	if cfg.Clock == nil {
		cfg.Clock = quarantine.NewManualClock(time.Unix(1700000000, 0))
	}
	if cfg.AttemptTimeout == 0 {
		cfg.AttemptTimeout = 5 * time.Second
	}
	e, err := quarantine.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestSubmitMergeAndBind(t *testing.T) {
	clk := quarantine.SystemClock{}
	e := newEngine(t, quarantine.Config{
		Clock:       clk,
		MaxAttempts: 3,
		Tenants:     []quarantine.Tenant{"tenant-a", "tenant-b"},
		Slots:       3,
		UseFileLock: false,
		Scanner:     quarantine.NewSimulator(clk, quarantine.SimulatorOptions{}),
	})

	data := []byte("hello SIM-CLEAN world")
	sub, err := e.Submit("tenant-a", data, "req-1")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if sub.Route != quarantine.RouteNew {
		t.Fatalf("route = %s, want new", sub.Route)
	}

	sub2, err := e.Submit("tenant-a", data, "req-2")
	if err != nil {
		t.Fatalf("Submit 2: %v", err)
	}
	if sub2.Route != quarantine.RouteMerged {
		t.Fatalf("route = %s, want merged", sub2.Route)
	}
	if sub2.JobID != sub.JobID {
		t.Fatalf("merged job id %s != %s", sub2.JobID, sub.JobID)
	}

	sub3, err := e.Submit("tenant-b", data, "req-3")
	if err != nil {
		t.Fatalf("Submit 3: %v", err)
	}
	if sub3.Route != quarantine.RouteNew {
		t.Fatalf("other tenant route = %s, want new", sub3.Route)
	}
	if sub3.JobID == sub.JobID {
		t.Fatalf("other tenant attached to job %s", sub.JobID)
	}

	// Duplicate request returns the prior task.
	dup, err := e.Submit("tenant-a", data, "req-1")
	if err != nil {
		t.Fatalf("dup submit: %v", err)
	}
	if dup.Route != quarantine.RouteDuplicate || dup.TaskID != sub.TaskID {
		t.Fatalf("dup = %+v, want task %d", dup, sub.TaskID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	v, err := e.Wait(ctx, "tenant-a", sub.TaskID)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if v.State != quarantine.StateClean {
		t.Fatalf("state = %s, want clean", v.State)
	}
	if v.Result == nil {
		t.Fatal("nil result")
	}
	if v.Result.Tenant != "tenant-a" || v.Result.Digest != quarantine.DigestBytes(data) || v.Result.TaskID != sub.TaskID {
		t.Fatalf("bad binding: %+v", v.Result)
	}
	if err := v.Result.Validate(); err != nil {
		t.Fatalf("result binding invalid: %v", err)
	}

	if got := e.ScannerCalls(); got != 2 {
		t.Fatalf("scanner calls = %d, want 2 (one per distinct job)", got)
	}
	if err := os.MkdirAll(e.ReleaseDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	info, err := e.Release("tenant-a", sub.TaskID)
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	b, err := os.ReadFile(info.Path)
	if err != nil {
		t.Fatalf("read release: %v", err)
	}
	if quarantine.DigestBytes(b) != v.Result.Digest {
		t.Fatalf("release digest mismatch")
	}
	if filepath.Dir(info.Path) != e.ReleaseDir() {
		t.Fatalf("release path outside release dir")
	}
}
