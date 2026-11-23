package quarantine_test

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"quarantine/quarantine"
	"quarantine/quarantine/internal/model"
)

// pilot drives the real engine and the independent reference model through the
// same operations. Scans are gated per engine job ID, so the test decides when
// and with what verdict each job completes. Every operation is followed by a
// comparison of the observable state.
type pilot struct {
	t *testing.T
	e *quarantine.Engine
	m *model.Machine

	mu      sync.Mutex
	gates   map[string]chan quarantine.Verdict // jobID -> verdict
	entered map[string]chan struct{}
	// verdicts planned per digest, as submitted.
	seen []quarantine.TaskID
}

func newPilot(t *testing.T, slots int) *pilot {
	t.Helper()
	clk := quarantine.NewManualClock(time.Unix(1700000000, 0))
	p := &pilot{
		t:       t,
		m:       model.New(),
		gates:   map[string]chan quarantine.Verdict{},
		entered: map[string]chan struct{}{},
	}
	sc := &pilotScanner{p: p}
	e, err := quarantine.NewEngine(quarantine.Config{
		DataDir:        t.TempDir(),
		Clock:          clk,
		Scanner:        sc,
		Slots:          slots,
		MaxAttempts:    2,
		AttemptTimeout: 10 * time.Second,
		Tenants:        []quarantine.Tenant{"ta", "tb"},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	p.e = e
	t.Cleanup(func() { e.Close() })
	return p
}

type pilotScanner struct{ p *pilot }

func (s *pilotScanner) Scan(ctx context.Context, req quarantine.ScanRequest) (quarantine.ScanOutput, error) {
	s.p.mu.Lock()
	g, ok := s.p.gates[req.JobID]
	if !ok {
		g = make(chan quarantine.Verdict, 1)
		s.p.gates[req.JobID] = g
	}
	ent, ok := s.p.entered[req.JobID]
	if !ok {
		ent = make(chan struct{})
		s.p.entered[req.JobID] = ent
		close(ent)
	}
	s.p.mu.Unlock()
	select {
	case <-ctx.Done():
		return quarantine.ScanOutput{}, ctx.Err()
	case v := <-g:
		return quarantine.ScanOutput{Verdict: v, Reason: "pilot " + string(v)}, nil
	}
}

func (p *pilot) submit(tenant quarantine.Tenant, digest string, reqID string, verdict quarantine.Verdict) quarantine.TaskID {
	p.t.Helper()
	data := []byte("pilot file " + digest)
	es, err := p.e.Submit(tenant, data, reqID)
	if err != nil {
		p.t.Fatalf("engine submit: %v", err)
	}
	ms := p.m.Submit(string(tenant), digest, reqID, model.Verdict(verdict))
	if es.Route != quarantine.SubmitRoute(ms.Route) {
		p.t.Fatalf("submit %s/%s: engine route %s, model route %s", tenant, digest, es.Route, ms.Route)
	}
	if es.TaskID != quarantine.TaskID(ms.TaskID) {
		p.t.Fatalf("submit %s/%s: engine task %d, model task %d", tenant, digest, es.TaskID, ms.TaskID)
	}
	if es.JobID != ms.JobID {
		p.t.Fatalf("submit %s/%s: engine job %q, model job %q", tenant, digest, es.JobID, ms.JobID)
	}
	if es.JobID != "" {
		p.mu.Lock()
		if _, ok := p.gates[es.JobID]; !ok {
			p.gates[es.JobID] = make(chan quarantine.Verdict, 1)
		}
		p.mu.Unlock()
	}
	p.seen = append(p.seen, es.TaskID)
	return es.TaskID
}

// complete resolves the model's live job for tenant/digest at rule, sends its
// verdict to the corresponding engine job, and waits for the engine to commit.
func (p *pilot) complete(tenant quarantine.Tenant, digest string, rule int64) {
	p.t.Helper()
	jobID := p.liveJobID(tenant, digest, rule)
	if jobID == "" {
		p.t.Fatalf("complete: no live model job for %s/%s rule %d", tenant, digest, rule)
	}
	verdict := p.m.JobVerdict(string(tenant), digest, rule)
	p.mu.Lock()
	g := p.gates[jobID]
	ent := p.entered[jobID]
	if g == nil {
		g = make(chan quarantine.Verdict, 1)
		p.gates[jobID] = g
	}
	p.mu.Unlock()
	// Wait for the engine to dispatch the job so the scanner is listening.
	if ent != nil {
		select {
		case <-ent:
		case <-time.After(10 * time.Second):
			p.t.Fatalf("job %s never entered the scanner", jobID)
		}
	}
	g <- quarantine.Verdict(verdict)
	// Wait for the engine to settle this job.
	p.waitJobSettled(tenant, jobID)
	if !p.m.CompleteRule(string(tenant), digest, rule) {
		p.t.Fatalf("model complete: no live job %s/%s rule %d", tenant, digest, rule)
	}
	p.compareAll()
}

func (p *pilot) liveJobID(tenant quarantine.Tenant, digest string, rule int64) string {
	snap := p.m.Snapshot()
	for _, t := range snap.Tasks {
		if t.Tenant == string(tenant) && t.Digest == digest && t.Rule == rule && t.JobID != "" &&
			(t.State == model.Scanning || t.State == model.Queued) {
			return t.JobID
		}
	}
	return ""
}

func (p *pilot) waitJobSettled(tenant quarantine.Tenant, jobID string) {
	p.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		all := true
		found := false
		for _, v := range p.e.Tasks(tenant) {
			if v.JobID != jobID {
				continue
			}
			found = true
			if !terminalState(v.State) {
				all = false
				break
			}
		}
		if found && all {
			return
		}
		time.Sleep(time.Millisecond)
	}
	var states []string
	for _, v := range p.e.Tasks(tenant) {
		if v.JobID == jobID {
			states = append(states, fmt.Sprintf("task %d %s", v.TaskID, v.State))
		}
	}
	p.t.Fatalf("job %s did not settle (tenant %s): %v; model: %+v", jobID, tenant, states, p.m.Snapshot().Tasks)
}

func terminalState(s quarantine.TaskState) bool {
	switch s {
	case quarantine.StateClean, quarantine.StateInfected, quarantine.StateFailed, quarantine.StateCancelled, quarantine.StateReleased:
		return true
	}
	return false
}

func (p *pilot) cancel(tenant quarantine.Tenant, id quarantine.TaskID) {
	p.t.Helper()
	eerr := p.e.Cancel(tenant, id)
	mres := p.m.Cancel(string(tenant), uint64(id))
	switch {
	case mres.TooLate:
		if eerr == nil {
			p.t.Fatalf("cancel task %d: engine accepted, model says too late", id)
		}
	case mres.Cancelled:
		if eerr != nil {
			p.t.Fatalf("cancel task %d: engine %v, model cancels", id, eerr)
		}
	default:
		p.t.Fatalf("unexpected model cancel result %+v", mres)
	}
	p.compareAll()
}

func (p *pilot) updateRules() {
	p.t.Helper()
	if _, err := p.e.UpdateRules(); err != nil {
		p.t.Fatalf("UpdateRules: %v", err)
	}
	if mr := p.m.UpdateRules(); mr != int64(p.e.Rule()) {
		p.t.Fatalf("rule mismatch: engine %d model %d", p.e.Rule(), mr)
	}
}

func (p *pilot) release(tenant quarantine.Tenant, id quarantine.TaskID) {
	p.t.Helper()
	_, eerr := p.e.Release(tenant, id)
	mres := p.m.Release(string(tenant), uint64(id))
	wantErr := ""
	switch {
	case mres.Already:
		wantErr = "already"
	case mres.Cancelled:
		wantErr = "cancelled"
	case mres.Stale:
		wantErr = "stale"
	case mres.NotClean:
		wantErr = "notclean"
	case mres.TooLate:
		wantErr = "tooLate"
	case mres.Released:
		wantErr = ""
	default:
		wantErr = "notready"
	}
	if wantErr == "" && eerr != nil {
		p.t.Fatalf("release task %d: engine %v, model ok", id, eerr)
	}
	if wantErr != "" && wantErr != "already" && eerr == nil {
		// Releasing an already-released task is idempotent in both.
		p.t.Fatalf("release task %d: engine ok, model wants %s", id, wantErr)
	}
	p.compareAll()
}

// compareAll checks every task known to the model against the engine.
func (p *pilot) compareAll() {
	p.t.Helper()
	snap := p.m.Snapshot()
	ids := make([]uint64, 0, len(snap.Tasks))
	for id := range snap.Tasks {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		mt := snap.Tasks[id]
		ev, err := p.e.Get(quarantine.Tenant(mt.Tenant), quarantine.TaskID(id))
		if err != nil {
			p.t.Fatalf("engine Get task %d: %v", id, err)
		}
		want := mapModelState(mt)
		if ev.State != want {
			// The engine may still be dispatching a merged/queued task. Only
			// fail when the model has settled.
			if terminalState(want) {
				p.t.Fatalf("task %d (%s/%s) state: engine %s, model %s (model says %+v)", id, mt.Tenant, mt.Digest, ev.State, want, mt)
			}
		}
		if mt.HasResult {
			if ev.Result == nil {
				p.t.Fatalf("task %d: model has result, engine does not", id)
			}
			if ev.Result.RuleVersion != quarantine.RuleVersion(mt.ResultRule) {
				p.t.Fatalf("task %d result rule: engine %d, model %d", id, ev.Result.RuleVersion, mt.ResultRule)
			}
			if quarantine.Verdict(mt.Verdict) != ev.Result.Verdict {
				p.t.Fatalf("task %d verdict: engine %s, model %s", id, ev.Result.Verdict, mt.Verdict)
			}
			if err := ev.Result.Validate(); err != nil {
				p.t.Fatalf("task %d binding: %v", id, err)
			}
		}
		if mt.Released && (ev.Result == nil || !ev.Result.Released) {
			p.t.Fatalf("task %d: model released, engine not", id)
		}
		if !mt.Released && ev.Result != nil && ev.Result.Released {
			p.t.Fatalf("task %d: engine released, model not", id)
		}
	}
}

func mapModelState(t model.Task) quarantine.TaskState {
	switch t.State {
	case model.Queued:
		return quarantine.StateQueued
	case model.Scanning:
		return quarantine.StateScanning
	case model.CleanS:
		return quarantine.StateClean
	case model.InfectedS:
		return quarantine.StateInfected
	case model.Cancelled:
		return quarantine.StateCancelled
	case model.Released:
		return quarantine.StateReleased
	}
	return quarantine.TaskState(t.State)
}

// scenario is one interleaving of two tenants. Every op refers to a digest.
type scenario struct {
	name string
	ops  []op
}

type op func(p *pilot)

func TestModelInterleavings(t *testing.T) {
	const (
		clean1  = "d-clean-1"
		clean2  = "d-clean-2"
		infect1 = "d-infect-1"
	)
	sub := func(tenant quarantine.Tenant, digest string, verdict quarantine.Verdict) op {
		return func(p *pilot) { p.submit(tenant, digest, "", verdict) }
	}
	subReq := func(tenant quarantine.Tenant, digest, req string, verdict quarantine.Verdict) op {
		return func(p *pilot) { p.submit(tenant, digest, req, verdict) }
	}
	complete := func(tenant quarantine.Tenant, digest string, rule int64) op {
		return func(p *pilot) { p.complete(tenant, digest, rule) }
	}
	cancelNth := func(tenant quarantine.Tenant, n int) op {
		return func(p *pilot) { p.cancel(tenant, p.seen[n]) }
	}
	releaseNth := func(tenant quarantine.Tenant, n int) op {
		return func(p *pilot) { p.release(tenant, p.seen[n]) }
	}
	update := func() op { return func(p *pilot) { p.updateRules() } }

	scenarios := []scenario{
		{
			name: "same-tenant-same-digest-merges",
			ops: []op{
				sub("ta", clean1, quarantine.VerdictClean),
				sub("ta", clean1, quarantine.VerdictClean),
				complete("ta", clean1, 1),
				releaseNth("ta", 0),
				releaseNth("ta", 1),
			},
		},
		{
			name: "other-tenant-does-not-merge",
			ops: []op{
				sub("ta", clean1, quarantine.VerdictClean),
				sub("tb", clean1, quarantine.VerdictClean),
				complete("ta", clean1, 1),
				complete("tb", clean1, 1),
				releaseNth("ta", 0),
				releaseNth("tb", 1),
			},
		},
		{
			name: "cancel-one-of-merged",
			ops: []op{
				sub("ta", clean1, quarantine.VerdictClean),
				sub("ta", clean1, quarantine.VerdictClean),
				cancelNth("ta", 0),
				complete("ta", clean1, 1),
				releaseNth("ta", 1),
			},
		},
		{
			name: "cancel-both-of-merged",
			ops: []op{
				sub("ta", clean1, quarantine.VerdictClean),
				sub("ta", clean1, quarantine.VerdictClean),
				cancelNth("ta", 0),
				cancelNth("ta", 1),
			},
		},
		{
			name: "duplicate-request-sticky",
			ops: []op{
				subReq("ta", clean1, "r1", quarantine.VerdictClean),
				complete("ta", clean1, 1),
				subReq("ta", clean1, "r1", quarantine.VerdictClean),
				releaseNth("ta", 0),
			},
		},
		{
			name: "rule-update-blocks-old-result",
			ops: []op{
				sub("ta", clean1, quarantine.VerdictClean),
				update(),
				complete("ta", clean1, 1),
				releaseNth("ta", 0), // stale
				sub("ta", clean1, quarantine.VerdictClean), // new job under rule 2
				complete("ta", clean1, 2),
				releaseNth("ta", 1),
			},
		},
		{
			name: "cache-hit-after-complete",
			ops: []op{
				sub("ta", clean1, quarantine.VerdictClean),
				complete("ta", clean1, 1),
				sub("ta", clean1, quarantine.VerdictClean),
				sub("ta", clean1, quarantine.VerdictClean),
				releaseNth("ta", 2),
			},
		},
		{
			name: "infected-cannot-release",
			ops: []op{
				sub("ta", infect1, quarantine.VerdictInfected),
				complete("ta", infect1, 1),
				releaseNth("ta", 0),
			},
		},
		{
			name: "two-tenants-two-digests",
			ops: []op{
				sub("ta", clean1, quarantine.VerdictClean),
				sub("tb", clean2, quarantine.VerdictClean),
				sub("ta", infect1, quarantine.VerdictInfected),
				complete("ta", clean1, 1),
				complete("tb", clean2, 1),
				complete("ta", infect1, 1),
				releaseNth("ta", 0),
				releaseNth("tb", 1),
				releaseNth("ta", 2), // not clean
			},
		},
		{
			name: "cancel-after-complete-too-late",
			ops: []op{
				sub("ta", clean1, quarantine.VerdictClean),
				complete("ta", clean1, 1),
				cancelNth("ta", 0),
			},
		},
	}

	for _, sc := range scenarios {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			p := newPilot(t, 3)
			for i, o := range sc.ops {
				o(p)
				_ = i
			}
			p.compareAll()
		})
	}
}

// TestModelRandomInterleavings performs a deterministic randomized walk over
// two tenants, always choosing only legal operations.
func TestModelRandomInterleavings(t *testing.T) {
	digests := []string{"r-a", "r-b", "r-c"}
	verdictOf := func(d string) quarantine.Verdict {
		if d == "r-c" {
			return quarantine.VerdictInfected
		}
		return quarantine.VerdictClean
	}
	tenants := []quarantine.Tenant{"ta", "tb"}

	seed := uint64(0x9e3779b97f4a7c15)
	next := func(n int) int {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return int(seed % uint64(n))
	}

	for round := 0; round < 25; round++ {
		round := round
		t.Run(fmt.Sprintf("round-%02d", round), func(t *testing.T) {
			p := newPilot(t, 3)
			for step := 0; step < 14; step++ {
				// Keep the number of live jobs within the slot count so every
				// live job can be dispatched and the gated scanner never
				// deadlocks. This is a test-harness constraint, not an engine
				// one: the engine correctly queues the excess.
				if len(p.m.LiveJobs()) >= 3 {
					live := p.m.LiveJobs()
					pair := live[next(len(live))]
					p.complete(quarantine.Tenant(pair[0]), pair[1], 1)
					continue
				}
				choice := next(6)
				switch choice {
				case 0, 1: // submit
					tenant := tenants[next(len(tenants))]
					d := digests[next(len(digests))]
					req := ""
					if next(3) == 0 {
						// Request IDs are content-scoped so a random walk never
						// triggers the (separately tested) conflict path.
						req = fmt.Sprintf("q%d-%d-%s", round, step, d)
					}
					p.submit(tenant, d, req, verdictOf(d))
				case 2, 3: // complete a live job
					live := p.m.LiveJobs()
					if len(live) == 0 {
						break
					}
					pair := live[next(len(live))]
					p.complete(quarantine.Tenant(pair[0]), pair[1], 1)
				case 4: // cancel a non-terminal task
					if len(p.seen) == 0 {
						break
					}
					id := p.seen[next(len(p.seen))]
					v, err := p.e.Get("ta", id)
					if err != nil {
						v, err = p.e.Get("tb", id)
					}
					if err != nil {
						break
					}
					if terminalState(v.State) {
						break
					}
					p.cancel(v.Tenant, id)
				case 5: // release a task whose model result exists
					if len(p.seen) == 0 {
						break
					}
					id := p.seen[next(len(p.seen))]
					v, err := p.e.Get("ta", id)
					if err != nil {
						v, err = p.e.Get("tb", id)
					}
					if err != nil {
						break
					}
					if !terminalState(v.State) {
						break
					}
					p.release(v.Tenant, id)
				}
			}
			p.compareAll()
		})
	}
}
