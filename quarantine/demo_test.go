package quarantine_test

import (
	"os"
	"testing"

	"quarantine/quarantine"
)

// TestOfflineDemo runs the shipped demo and checks its outputs against the
// real release directory and scanner call count.
func TestOfflineDemo(t *testing.T) {
	dir := t.TempDir()
	rep, err := quarantine.RunDemo(dir)
	if err != nil {
		t.Fatalf("RunDemo: %v", err)
	}
	if rep.ScannerCalls != 4 {
		t.Fatalf("scanner calls = %d, want 4 (2 merged tenant-a + 2 tenant-b + infected share none)", rep.ScannerCalls)
	}
	// tenant-a's two identical clean uploads merge into one scan; tenant-b's
	// same bytes are a separate scan; the infected file is a separate scan;
	// tenant-b's second clean file is another. That is 4 distinct jobs.
	if rep.MaxInflight > rep.Slots {
		t.Fatalf("max inflight %d > slots %d", rep.MaxInflight, rep.Slots)
	}
	if len(rep.ReleaseFiles) != 4 {
		t.Fatalf("release files = %d, want 4", len(rep.ReleaseFiles))
	}
	// Each release file's digest must be one of the clean digests, never the
	// infected one.
	cleanDigests := map[quarantine.Digest]bool{
		quarantine.DigestBytes([]byte("synthetic harmless file SIM-CLEAN shared-alpha\n")): true,
		quarantine.DigestBytes([]byte("synthetic harmless file SIM-CLEAN shared-beta\n")):  true,
	}
	infected := quarantine.DigestBytes([]byte("synthetic harmless file SIM-INFECTED eicar-not-really\n"))
	for _, f := range rep.ReleaseFiles {
		if f.Digest == infected {
			t.Fatalf("infected file appeared in release dir: %s", f.Path)
		}
		if !cleanDigests[f.Digest] {
			t.Fatalf("unexpected digest %s in release dir", f.Digest)
		}
		b, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatalf("read release: %v", err)
		}
		if quarantine.DigestBytes(b) != f.Digest {
			t.Fatalf("release file %s digest changed", f.Path)
		}
	}
	// The infected task is terminal and bound.
	var infectedTask *quarantine.TaskView
	for i := range rep.Tasks {
		if rep.Tasks[i].Tenant == "tenant-a" && rep.Tasks[i].Result != nil && rep.Tasks[i].Result.Verdict == quarantine.VerdictInfected {
			infectedTask = &rep.Tasks[i]
		}
	}
	if infectedTask == nil {
		t.Fatalf("infected task not reported")
	}
	if infectedTask.State == quarantine.StateReleased {
		t.Fatalf("infected task was released")
	}
}
