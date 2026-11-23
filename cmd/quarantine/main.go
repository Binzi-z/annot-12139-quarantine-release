// Command quarantine is the CLI for the two-tenant file quarantine.
//
// All commands operate on a data directory (default ./demo-data, overridable
// with -data or QUARANTINE_DATA). Each invocation opens the engine, performs the
// action, and closes it; committed results and the rule version are durable
// across invocations.
//
//	quarantine submit   -tenant T -file PATH [-request ID]   freeze and submit
//	quarantine status   -tenant T -task ID                   show one task
//	quarantine list     -tenant T                            list a tenant's tasks
//	quarantine result   -tenant T -task ID                   print the bound result
//	quarantine release  -tenant T -task ID                   release a clean file
//	quarantine cancel   -tenant T -task ID                   cancel before commit
//	quarantine rules    [-update]                            show or bump rule version
//	quarantine slots                                         show worker stats
//	quarantine demo     [-out DIR]                           run the offline demo
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"quarantine/quarantine"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// run dispatches one CLI invocation and returns its error. It is separate from
// main so tests can exercise every command in-process.
func run(args []string) error {
	if len(args) < 1 {
		usage()
		return errUsage
	}
	cmd := args[0]
	rest := args[1:]
	switch cmd {
	case "submit":
		return runSubmit(rest)
	case "status":
		return runStatus(rest)
	case "list":
		return runList(rest)
	case "result":
		return runResult(rest)
	case "release":
		return runRelease(rest)
	case "cancel":
		return runCancel(rest)
	case "rules":
		return runRules(rest)
	case "slots":
		return runSlots(rest)
	case "demo":
		return runDemo(rest)
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// errUsage signals a usage error; main exits non-zero either way.
var errUsage = errors.New("usage")

func usage() {
	fmt.Fprint(os.Stderr, `quarantine - two-tenant local file quarantine (3 shared scan slots)

usage:
  quarantine submit  -tenant T -file PATH [-request ID] [-wait]
  quarantine status  -tenant T -task ID
  quarantine list    -tenant T
  quarantine result  -tenant T -task ID
  quarantine release -tenant T -task ID
  quarantine cancel  -tenant T -task ID
  quarantine rules   [-update]
  quarantine slots
  quarantine demo    [-out DIR]

global flags (before or after the command):
  -data DIR    data directory (default $QUARANTINE_DATA or ./demo-data)
  -json        emit JSON
`)
}

func must(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// commonFlags parses flags shared by store-backed commands.
type commonFlags struct {
	data *string
	json *bool
	fs   *flag.FlagSet
}

func newFlags(name string) *commonFlags {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	cf := &commonFlags{fs: fs}
	cf.data = fs.String("data", envData(), "data directory")
	cf.json = fs.Bool("json", false, "emit JSON")
	return cf
}

func envData() string {
	if d := os.Getenv("QUARANTINE_DATA"); d != "" {
		return d
	}
	return "demo-data"
}

func (c *commonFlags) open() (*quarantine.Engine, error) {
	dir := *c.data
	if dir == "" {
		dir = "demo-data"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	scanner, err := scannerFor(dir)
	if err != nil {
		return nil, err
	}
	return quarantine.NewEngine(quarantine.Config{
		DataDir:        dir,
		Slots:          3,
		Tenants:        []quarantine.Tenant{"tenant-a", "tenant-b"},
		MaxAttempts:    2,
		AttemptTimeout: 5 * time.Second,
		UseFileLock:    true,
		Scanner:        scanner,
	})
}

// scannerFor returns a simulator that reads from the same data directory.
func scannerFor(dir string) (quarantine.Scanner, error) {
	clk := quarantine.SystemClock{}
	return quarantine.NewSimulator(clk, quarantine.SimulatorOptions{
		BaseDelay: 2 * time.Millisecond,
		SlowDelay: 4 * time.Second,
	}), nil
}

func (c *commonFlags) emit(v any) {
	if *c.json {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		must(enc.Encode(v))
		return
	}
	printHuman(v)
}

func printHuman(v any) {
	switch x := v.(type) {
	case quarantine.Submission:
		fmt.Printf("task=%d state=%s route=%s job=%s\n", x.TaskID, x.State, x.Route, x.JobID)
		if x.Result != nil {
			fmt.Printf("result: verdict=%s rule=%d binding=%s\n", x.Result.Verdict, x.Result.RuleVersion, short(x.Result.Binding))
		}
	case quarantine.TaskView:
		printTask(x)
	case []quarantine.TaskView:
		for _, t := range x {
			printTask(t)
		}
	case *quarantine.Result:
		if x == nil {
			fmt.Println("no result")
			return
		}
		fmt.Printf("task=%d tenant=%s digest=%s verdict=%s rule=%d released=%v\n",
			x.TaskID, x.Tenant, x.Digest, x.Verdict, x.RuleVersion, x.Released)
		fmt.Printf("binding=%s\n", x.Binding)
		if x.Reason != "" {
			fmt.Printf("reason=%s\n", x.Reason)
		}
		if x.ReleasePath != "" {
			fmt.Printf("release_path=%s\n", x.ReleasePath)
		}
	case quarantine.ReleaseInfo:
		fmt.Printf("released task=%d rule=%d path=%s already=%v\n", x.TaskID, x.RuleVersion, x.Path, x.Already)
	case quarantine.RuleVersion:
		fmt.Printf("rule=%d\n", x)
	case quarantine.Stats:
		fmt.Printf("rule=%d slots=%d inflight=%d max_inflight=%d scanner_calls=%d dispatches=%d tasks=%d jobs=%d queued=%d\n",
			x.Rule, x.Slots, x.Inflight, x.MaxInflight, x.ScannerCalls, x.Dispatches, x.Tasks, x.Jobs, x.Queued)
	default:
		fmt.Printf("%v\n", v)
	}
}

func printTask(t quarantine.TaskView) {
	line := fmt.Sprintf("task=%d tenant=%s state=%s rule=%d job=%s merged=%v attempts=%d",
		t.TaskID, t.Tenant, t.State, t.RuleVersion, t.JobID, t.Merged, t.Attempts)
	if t.Result != nil {
		line += fmt.Sprintf(" verdict=%s result_rule=%d released=%v", t.Result.Verdict, t.Result.RuleVersion, t.Result.Released)
	}
	if t.Reason != "" {
		line += " reason=" + sanitizeReason(t.Reason)
	}
	fmt.Println(line)
}

func sanitizeReason(s string) string {
	return strings.ReplaceAll(s, "\n", " ")
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func tenantArg(s string) quarantine.Tenant { return quarantine.Tenant(s) }

func taskArg(s string) (quarantine.TaskID, error) {
	var id uint64
	_, err := fmt.Sscanf(s, "%d", &id)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("invalid task id %q", s)
	}
	return quarantine.TaskID(id), nil
}

func runSubmit(args []string) error {
	cf := newFlags("submit")
	tenant := cf.fs.String("tenant", "", "tenant (tenant-a or tenant-b)")
	file := cf.fs.String("file", "", "path to the file to submit")
	request := cf.fs.String("request", "", "optional idempotency key")
	wait := cf.fs.Bool("wait", true, "wait for a determined result (default true; the CLI processes are short-lived)")
	if err := cf.fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" || *file == "" {
		return errors.New("submit requires -tenant and -file")
	}
	e, err := cf.open()
	if err != nil {
		return err
	}
	defer e.Close()
	sub, err := e.SubmitFile(tenantArg(*tenant), *file, *request)
	if err != nil {
		return err
	}
	if *wait {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		v, err := e.Wait(ctx, tenantArg(*tenant), sub.TaskID)
		if err != nil {
			return err
		}
		sub.State = v.State
		sub.Result = v.Result
	}
	cf.emit(sub)
	return nil
}

func runStatus(args []string) error {
	cf := newFlags("status")
	tenant := cf.fs.String("tenant", "", "tenant")
	task := cf.fs.String("task", "", "task id")
	if err := cf.fs.Parse(args); err != nil {
		return err
	}
	id, err := taskArg(*task)
	if err != nil {
		return err
	}
	e, err := cf.open()
	if err != nil {
		return err
	}
	defer e.Close()
	v, err := e.Get(tenantArg(*tenant), id)
	if err != nil {
		return err
	}
	cf.emit(v)
	return nil
}

func runList(args []string) error {
	cf := newFlags("list")
	tenant := cf.fs.String("tenant", "", "tenant")
	if err := cf.fs.Parse(args); err != nil {
		return err
	}
	if *tenant == "" {
		return errors.New("list requires -tenant")
	}
	e, err := cf.open()
	if err != nil {
		return err
	}
	defer e.Close()
	cf.emit(e.Tasks(tenantArg(*tenant)))
	return nil
}

func runResult(args []string) error {
	cf := newFlags("result")
	tenant := cf.fs.String("tenant", "", "tenant")
	task := cf.fs.String("task", "", "task id")
	if err := cf.fs.Parse(args); err != nil {
		return err
	}
	id, err := taskArg(*task)
	if err != nil {
		return err
	}
	e, err := cf.open()
	if err != nil {
		return err
	}
	defer e.Close()
	r, err := e.Result(tenantArg(*tenant), id)
	if err != nil {
		return err
	}
	cf.emit(r)
	return nil
}

func runRelease(args []string) error {
	cf := newFlags("release")
	tenant := cf.fs.String("tenant", "", "tenant")
	task := cf.fs.String("task", "", "task id")
	if err := cf.fs.Parse(args); err != nil {
		return err
	}
	id, err := taskArg(*task)
	if err != nil {
		return err
	}
	e, err := cf.open()
	if err != nil {
		return err
	}
	defer e.Close()
	info, err := e.Release(tenantArg(*tenant), id)
	if err != nil {
		return err
	}
	cf.emit(info)
	return nil
}

func runCancel(args []string) error {
	cf := newFlags("cancel")
	tenant := cf.fs.String("tenant", "", "tenant")
	task := cf.fs.String("task", "", "task id")
	if err := cf.fs.Parse(args); err != nil {
		return err
	}
	id, err := taskArg(*task)
	if err != nil {
		return err
	}
	e, err := cf.open()
	if err != nil {
		return err
	}
	defer e.Close()
	if err := e.Cancel(tenantArg(*tenant), id); err != nil {
		return err
	}
	cf.emit(map[string]any{"task": id, "cancelled": true})
	return nil
}

func runRules(args []string) error {
	cf := newFlags("rules")
	update := cf.fs.Bool("update", false, "advance the rule version")
	if err := cf.fs.Parse(args); err != nil {
		return err
	}
	e, err := cf.open()
	if err != nil {
		return err
	}
	defer e.Close()
	if *update {
		v, err := e.UpdateRules()
		if err != nil {
			return err
		}
		cf.emit(v)
		return nil
	}
	cf.emit(e.Rule())
	return nil
}

func runSlots(args []string) error {
	cf := newFlags("slots")
	if err := cf.fs.Parse(args); err != nil {
		return err
	}
	e, err := cf.open()
	if err != nil {
		return err
	}
	defer e.Close()
	cf.emit(e.Stats())
	return nil
}

func runDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	out := fs.String("out", "", "data directory for the demo (default: temp dir)")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := *out
	cleanup := false
	if dir == "" {
		d, err := os.MkdirTemp("", "quarantine-demo-*")
		if err != nil {
			return err
		}
		dir = d
		cleanup = true
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	rep, err := quarantine.RunDemo(dir)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return err
		}
	} else {
		fmt.Println("== offline demo: two tenants sharing 3 scan slots ==")
		for i, s := range rep.Steps {
			fmt.Printf("%2d. %s\n", i+1, s)
		}
		fmt.Println("\n-- dispatch order --")
		for _, d := range rep.DispatchOrder {
			fmt.Println("  ", d)
		}
		fmt.Printf("\nscanner calls: %d (merged tasks share one call)\n", rep.ScannerCalls)
		fmt.Printf("max parallel workers: %d / %d\n", rep.MaxInflight, rep.Slots)
		fmt.Println("\n-- release directory (digests re-read from disk) --")
		for _, f := range rep.ReleaseFiles {
			fmt.Printf("  %s\n    sha256=%s size=%d\n", f.Path, f.Digest, f.Size)
		}
		fmt.Println("\n-- final tasks --")
		for _, t := range rep.Tasks {
			printTask(t)
		}
	}
	if cleanup {
		fmt.Printf("\ndemo data directory: %s (retained for inspection)\n", dir)
	}
	return nil
}
