package quarantine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// DemoReport summarizes one offline demonstration run.
type DemoReport struct {
	Rule               RuleVersion    `json:"rule"`
	Slots              int            `json:"slots"`
	Steps              []string       `json:"steps"`
	TenantASubmissions []TaskID       `json:"tenant_a_submissions"`
	TenantBSubmissions []TaskID       `json:"tenant_b_submissions"`
	ScannerCalls       int            `json:"scanner_calls"`
	MaxInflight        int            `json:"max_inflight"`
	DispatchOrder      []string       `json:"dispatch_order"`
	ReleaseFiles       []ReleasedFile `json:"release_files"`
	Tasks              []TaskView     `json:"tasks"`
}

// ReleasedFile is a release-directory entry with its verified digest.
type ReleasedFile struct {
	Path   string `json:"path"`
	Digest Digest `json:"digest"`
	Size   int64  `json:"size"`
}

// RunDemo executes a self-contained, offline demonstration in dir. It uses the
// shipped deterministic Simulator, the real engine and real workers. It writes
// only synthetic harmless files.
//
// The scripted story:
//  1. tenant-a uploads two identical clean files while not-yet-scanned: they
//     merge into one scan.
//  2. tenant-b uploads the same bytes: a distinct scan (no cross-tenant attach).
//  3. tenant-a uploads an infected file: it must never be released.
//  4. tenant-a requests a duplicate with the same request ID: served from the
//     determined result.
//  5. Everyone's clean result is released; the actual release-directory
//     digests are re-read and reported.
func RunDemo(dir string) (*DemoReport, error) {
	clk := SystemClock{}
	cfg := Config{
		DataDir:        dir,
		Slots:          3,
		Tenants:        []Tenant{"tenant-a", "tenant-b"},
		MaxAttempts:    2,
		AttemptTimeout: 5 * time.Second,
		Clock:          clk,
		Scanner:        NewSimulator(clk, SimulatorOptions{BaseDelay: 5 * time.Millisecond, SlowDelay: 250 * time.Millisecond}),
	}
	e, err := NewEngine(cfg)
	if err != nil {
		return nil, err
	}
	defer e.Close()

	rep := &DemoReport{Rule: e.Rule(), Slots: cfg.Slots}
	step := func(format string, args ...any) {
		rep.Steps = append(rep.Steps, fmt.Sprintf(format, args...))
	}

	cleanA := []byte("synthetic harmless file SIM-CLEAN shared-alpha\n")
	cleanB := []byte("synthetic harmless file SIM-CLEAN shared-beta\n")
	infected := []byte("synthetic harmless file SIM-INFECTED eicar-not-really\n")

	a1, err := e.Submit("tenant-a", cleanA, "demo-a-1")
	if err != nil {
		return nil, err
	}
	a2, err := e.Submit("tenant-a", cleanA, "demo-a-2")
	if err != nil {
		return nil, err
	}
	b1, err := e.Submit("tenant-b", cleanA, "demo-b-1")
	if err != nil {
		return nil, err
	}
	step("tenant-a submit #1 route=%s task=%d job=%s", a1.Route, a1.TaskID, a1.JobID)
	step("tenant-a submit #2 route=%s task=%d job=%s", a2.Route, a2.TaskID, a2.JobID)
	step("tenant-b submit #1 route=%s task=%d job=%s", b1.Route, b1.TaskID, b1.JobID)

	b2, err := e.Submit("tenant-b", cleanB, "demo-b-2")
	if err != nil {
		return nil, err
	}
	bad, err := e.Submit("tenant-a", infected, "demo-a-bad")
	if err != nil {
		return nil, err
	}
	step("tenant-b submit #2 route=%s task=%d", b2.Route, b2.TaskID)
	step("tenant-a submit infected route=%s task=%d", bad.Route, bad.TaskID)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, x := range []struct {
		tenant Tenant
		id     TaskID
	}{{"tenant-a", a1.TaskID}, {"tenant-a", a2.TaskID}, {"tenant-b", b1.TaskID}, {"tenant-b", b2.TaskID}, {"tenant-a", bad.TaskID}} {
		v, err := e.Wait(ctx, x.tenant, x.id)
		if err != nil {
			return nil, err
		}
		step("task %d (%s) settled state=%s verdict=%s rule=%d", v.TaskID, v.Tenant, v.State, verdictOf(v), v.RuleVersion)
	}

	dup, err := e.Submit("tenant-a", cleanA, "demo-a-1")
	if err != nil {
		return nil, err
	}
	step("tenant-a duplicate request route=%s task=%d state=%s", dup.Route, dup.TaskID, dup.State)

	for _, id := range []TaskID{a1.TaskID, a2.TaskID, b1.TaskID, b2.TaskID} {
		v, _ := e.Get("tenant-a", id)
		if v.Tenant == "" {
			v, _ = e.Get("tenant-b", id)
		}
		info, err := e.Release(v.Tenant, id)
		if err != nil {
			return nil, fmt.Errorf("release task %d: %w", id, err)
		}
		step("released task %d -> %s", id, info.Path)
	}
	if _, err := e.Release("tenant-a", bad.TaskID); err == nil {
		return nil, fmt.Errorf("infected task was released")
	} else {
		step("refused to release infected task %d: %v", bad.TaskID, err)
	}

	// Verify the release directory's actual bytes.
	files, err := ReleasedFiles(e.ReleaseDir())
	if err != nil {
		return nil, err
	}
	rep.ReleaseFiles = files

	rep.TenantASubmissions = []TaskID{a1.TaskID, a2.TaskID, bad.TaskID}
	rep.TenantBSubmissions = []TaskID{b1.TaskID, b2.TaskID}
	rep.ScannerCalls = e.ScannerCalls()
	rep.MaxInflight = e.Stats().MaxInflight
	for _, ev := range e.DispatchSequence() {
		rep.DispatchOrder = append(rep.DispatchOrder, fmt.Sprintf("%s:%s:%s", ev.JobID, ev.Tenant, ev.Digest[:12]))
	}
	for _, t := range []Tenant{"tenant-a", "tenant-b"} {
		rep.Tasks = append(rep.Tasks, e.Tasks(t)...)
	}
	return rep, nil
}

func verdictOf(v TaskView) Verdict {
	if v.Result != nil {
		return v.Result.Verdict
	}
	return ""
}

// ReleasedFiles reads dir and returns each entry with its re-computed digest.
func ReleasedFiles(dir string) ([]ReleasedFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []ReleasedFile
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		p := filepath.Join(dir, ent.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, ReleasedFile{Path: p, Digest: DigestBytes(b), Size: int64(len(b))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
