// Command agentguard is a least-privilege sandbox for AI coding agents.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/longvo2k/agentguard/internal/audit"
	"github.com/longvo2k/agentguard/internal/config"
	"github.com/longvo2k/agentguard/internal/demo"
	"github.com/longvo2k/agentguard/internal/policy"
	"github.com/longvo2k/agentguard/internal/sandbox"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const usage = `AgentGuard: give AI agents only the access they need.  (experimental MVP)

Usage:
  agentguard setup [--yes]                       one-time setup: user policies, image, agent hooks
  sudo agentguard setup --server --workspace DIR lock down Claude Code on a server
  agentguard doctor                              check that everything is in place
  agentguard init [--force]                      create .agentguard/ for this project only
  agentguard trust [--revoke]                    approve this project's .agentguard/ policies
  agentguard check [--role R] <action> [path]    ask the policy engine (exit 0 allow, 1 deny)
  agentguard run [--role R] -- <command> [args]  run a command in a least-privilege sandbox
  agentguard audit [--tail N] [--json]           summarize logged decisions
  agentguard hook claude                         Claude Code PreToolUse hook (installed by setup)
  agentguard demo [--keep] [--no-docker]         see it work in 30 seconds
  agentguard version

Actions: read, write, execute, network
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	var err error
	code := 0
	switch cmd {
	case "setup":
		err = cmdSetup(rest, stdin, stdout)
	case "doctor":
		code, err = cmdDoctor(rest, stdout)
	case "trust":
		err = cmdTrust(rest, stdout)
	case "hook":
		code = cmdHook(rest, stdin, stdout, stderr)
	case "init":
		err = cmdInit(rest, stdout)
	case "check":
		code, err = cmdCheck(rest, stdout)
	case "run":
		code, err = cmdRun(rest, stdin, stdout, stderr)
	case "audit":
		err = cmdAudit(rest, stdout)
	case "demo":
		err = cmdDemo(rest, stdout)
	case "version", "--version":
		fmt.Fprintf(stdout, "agentguard %s\nsandbox image: %s\n", version, config.DefaultImage())
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
	default:
		fmt.Fprintf(stderr, "agentguard: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		var ue usageError
		if errors.As(err, &ue) {
			fmt.Fprintf(stderr, "agentguard %s: %v\n", cmd, err)
			return 2
		}
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(stderr, "agentguard %s: %v\n", cmd, err)
		if code == 0 {
			code = 1
		}
	}
	return code
}

type usageError struct{ error }

func usagef(format string, args ...any) error { return usageError{fmt.Errorf(format, args...)} }

// parse parses flags that may appear before or between positional
// arguments. Everything after "--" is returned untouched in tail.
func parse(fs *flag.FlagSet, args []string) (positional, tail []string, err error) {
	fs.SetOutput(io.Discard)
	for i, a := range args {
		if a == "--" {
			tail = args[i+1:]
			args = args[:i]
			break
		}
	}
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, nil, err
			}
			return nil, nil, usageError{err}
		}
		args = fs.Args()
		if len(args) == 0 {
			return positional, tail, nil
		}
		positional = append(positional, args[0])
		args = args[1:]
	}
}

func cmdInit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	force := fs.Bool("force", false, "overwrite existing files")
	pos, _, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("unexpected argument %q", pos[0])
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	written, err := config.Init(cwd, *force)
	if err != nil {
		return err
	}
	if len(written) == 0 {
		fmt.Fprintf(out, "%s/ already exists; nothing changed (use --force to overwrite)\n", config.DirName)
		return nil
	}
	// The user just created these policies, so they are trusted as written.
	if err := config.Trust(cwd); err != nil {
		return err
	}
	fmt.Fprintln(out, "Created:")
	for _, w := range written {
		rel, _ := filepath.Rel(cwd, w)
		fmt.Fprintln(out, "  "+rel)
	}
	fmt.Fprintf(out, "\nNext:\n  agentguard check read .env\n  agentguard run --role developer -- npm test\n\nEdit %s/policies/*.yaml to change what each role may do,\nthen run `agentguard trust` to approve the change.\n", config.DirName)
	return nil
}

// load opens the workspace for the current directory and builds an engine
// whose decisions are audited.
func load(role string, source string) (*config.Workspace, *policy.Engine, *audit.Logger, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, nil, err
	}
	return loadAt(cwd, role, source)
}

func loadAt(dir, role, source string) (*config.Workspace, *policy.Engine, *audit.Logger, error) {
	ws, err := config.Find(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	if role == "" {
		role = ws.Config.DefaultRole
	}
	if role == "" {
		return nil, nil, nil, usagef("no --role given and no default_role configured")
	}
	p, err := ws.LoadPolicy(role)
	if err != nil {
		return nil, nil, nil, err
	}
	e, err := policy.NewEngine(p, ws.Root)
	if err != nil {
		return nil, nil, nil, err
	}
	logger := audit.NewLogger(ws.AuditPath())
	e.SetObserver(logger.Observer(source))
	return ws, e, logger, nil
}

func cmdCheck(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	role := fs.String("role", "", "role to check (default: config default_role)")
	asJSON := fs.Bool("json", false, "print the decision as JSON")
	server := fs.Bool("server", false, "use the server-mode system policies for the current directory")
	pos, tail, err := parse(fs, args)
	if err != nil {
		return 2, err
	}
	pos = append(pos, tail...)
	if len(pos) == 0 || len(pos) > 2 {
		return 2, usagef("usage: agentguard check [--role R] <read|write|execute|network> [resource]")
	}
	action, err := policy.ParseAction(pos[0])
	if err != nil {
		return 2, usageError{err}
	}
	resource := ""
	if len(pos) == 2 {
		resource = pos[1]
	} else if action != policy.ActionNetwork {
		return 2, usagef("%s needs a resource, e.g. agentguard check %s src/app.js", action, action)
	}
	var e *policy.Engine
	var logger *audit.Logger
	if *server {
		if *role != "" {
			return 2, usagef("--role cannot be combined with --server; the workspace decides the role")
		}
		cwd, _ := os.Getwd()
		_, e, logger, err = loadServerAt(cwd, "check")
	} else {
		_, e, logger, err = load(*role, "check")
	}
	if err != nil {
		return 2, err
	}
	d := e.Evaluate(action, resource)
	if err := logger.Err(); err != nil {
		// Fail closed: an unaudited decision is reported as an error.
		return 2, fmt.Errorf("cannot write audit log: %w", err)
	}
	if *asJSON {
		enc := json.NewEncoder(out)
		_ = enc.Encode(map[string]any{
			"role": d.Role, "action": d.Action, "resource": d.Resource, "path": d.Path,
			"decision": map[bool]string{true: "allow", false: "deny"}[d.Allowed],
			"reason":   d.Reason, "rule": d.Rule,
		})
	} else {
		verdict := "DENY"
		detail := d.Reason
		if d.Allowed {
			verdict = "ALLOW"
			detail = d.Rule
		}
		target := strings.TrimSpace(string(action) + " " + resource)
		fmt.Fprintf(out, "%s  %s  [role %s]\n", verdict, target, d.Role)
		if detail != "" {
			fmt.Fprintf(out, "  %s\n", detail)
		}
		if !d.Allowed && d.Rule != "" && d.Rule != detail {
			fmt.Fprintf(out, "  rule: %s\n", d.Rule)
		}
	}
	if d.Allowed {
		return 0, nil
	}
	return 1, nil
}

func cmdRun(args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	role := fs.String("role", "", "role to run as (default: config default_role)")
	image := fs.String("image", "", "sandbox image (default: config sandbox.image)")
	dryRun := fs.Bool("dry-run", false, "print the sandbox plan and docker command without running")
	verbose := fs.Bool("v", false, "print the sandbox plan before running")
	pos, argv, err := parse(fs, args)
	if err != nil {
		return 2, err
	}
	if len(argv) == 0 {
		argv = pos
	} else if len(pos) > 0 {
		return 2, usagef("unexpected argument %q before --", pos[0])
	}
	if len(argv) == 0 {
		return 2, usagef("usage: agentguard run [--role R] -- <command> [args...]")
	}
	ws, e, logger, err := load(*role, "run")
	if err != nil {
		return 2, err
	}
	// Refuse a denied command before touching Docker.
	if d := e.Check(policy.ActionExecute, argv[0]); !d.Allowed {
		e.Evaluate(policy.ActionExecute, argv[0])
		return 126, fmt.Errorf("%s: %s", argv[0], d.Reason)
	}

	img := ws.Config.Image()
	if *image != "" {
		img = *image
	}
	ctx := context.Background()
	opts := sandbox.Options{
		Image:     img,
		Memory:    ws.Config.Sandbox.Memory,
		CPUs:      ws.Config.Sandbox.CPUs,
		PidsLimit: ws.Config.Sandbox.PidsLimit,
		User:      ws.Config.Sandbox.User,
		Record:    logger.Observer("sandbox"),
	}
	if !*dryRun {
		if err := sandbox.Available(ctx); err != nil {
			return 1, err
		}
		img, err = sandbox.EnsureImage(ctx, img, fallbackFor(img), stderr)
		if err != nil {
			return 1, err
		}
		opts.Image = img
		opts.CommandPaths, err = sandbox.ResolveCommands(ctx, img, e.Policy().Commands.Allow, ws.CacheDir())
		if err != nil {
			return 1, err
		}
	} else {
		opts.CommandPaths = map[string]string{}
		for _, c := range e.Policy().Commands.Allow {
			opts.CommandPaths[c] = "<resolved in image>/" + c
		}
	}
	plan, err := sandbox.NewPlan(e, opts)
	if err != nil {
		return 1, err
	}
	defer plan.Cleanup()
	for _, w := range plan.Warnings {
		if !strings.Contains(w, "not found in image") || !*dryRun {
			fmt.Fprintf(stderr, "agentguard: warning: %s\n", w)
		}
	}
	if *dryRun || *verbose {
		printPlan(stderr, plan)
	}
	if *dryRun {
		fmt.Fprintln(stdout, "docker "+shellJoin(plan.DockerArgs(argv, false)))
		return 0, logger.Err()
	}
	if err := logger.Err(); err != nil {
		return 1, fmt.Errorf("cannot write audit log, refusing to run: %w", err)
	}

	// Let the terminal's signals reach docker (which forwards them to the
	// container) instead of killing agentguard and orphaning the container.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)

	code, err := plan.Run(ctx, argv, stdin, stdout, stderr)
	if err != nil {
		return code, err
	}
	return code, nil
}

func printPlan(w io.Writer, p *sandbox.Plan) {
	fmt.Fprintf(w, "Sandbox plan for role %q (image %s)\n", p.Engine.Policy().Role, p.Options.Image)
	fmt.Fprintf(w, "  user %d:%d, network %s, capabilities none, root filesystem read-only\n",
		p.UID, p.GID, map[bool]string{true: "enabled", false: "none"}[p.Network])
	for _, m := range p.Mounts {
		mode := "rw"
		if m.ReadOnly {
			mode = "ro"
		}
		switch m.Kind {
		case "workspace":
			fmt.Fprintf(w, "  mount %-2s %-34s (%s)\n", mode, m.Target, m.Note)
		case "hide":
			fmt.Fprintf(w, "  hide     %-34s (%s)\n", m.Target, m.Note)
		case "protect":
			fmt.Fprintf(w, "  mount ro %-34s (%s)\n", m.Target, m.Note)
		}
	}
	fmt.Fprintf(w, "  PATH: %s\n\n", strings.Join(p.Engine.Policy().Commands.Allow, " "))
}

func shellJoin(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if a != "" && strings.Trim(a, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=./:,@%+") == "" {
			out[i] = a
		} else {
			out[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
	}
	return strings.Join(out, " ")
}

func cmdAudit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	tail := fs.Int("tail", 15, "number of recent decisions to list")
	asJSON := fs.Bool("json", false, "print raw JSONL entries")
	role := fs.String("role", "", "only this role")
	deniedOnly := fs.Bool("denied", false, "only denied decisions")
	pos, _, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("unexpected argument %q", pos[0])
	}
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	ws, err := config.Find(cwd)
	if err != nil {
		return err
	}
	entries, err := audit.ReadFile(ws.AuditPath())
	if err != nil {
		return err
	}
	var filtered []audit.Entry
	for _, e := range entries {
		if (*role == "" || e.Role == *role) && (!*deniedOnly || e.Decision != "allow") {
			filtered = append(filtered, e)
		}
	}
	if *asJSON {
		enc := json.NewEncoder(out)
		for _, e := range filtered {
			if err := enc.Encode(e); err != nil {
				return err
			}
		}
		return nil
	}
	fmt.Fprintf(out, "Audit log: %s\n\n", ws.AuditPath())
	audit.Print(out, filtered, *tail)
	return nil
}

func cmdDemo(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	keep := fs.Bool("keep", false, "keep the demo project for exploring")
	noDocker := fs.Bool("no-docker", false, "only demonstrate the policy engine")
	image := fs.String("image", "", "sandbox image (default: built-in)")
	pos, _, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("unexpected argument %q", pos[0])
	}
	return demo.Run(context.Background(), demo.Options{Out: out, Keep: *keep, NoDocker: *noDocker, Image: *image})
}

// fallbackFor returns the local image to build when img cannot be pulled:
// only the official image has a built-in Dockerfile to fall back on.
func fallbackFor(img string) string {
	if config.IsDefaultImage(img) {
		return config.LocalImage
	}
	return ""
}
