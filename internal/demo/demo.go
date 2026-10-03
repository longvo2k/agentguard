// Package demo implements `agentguard demo`: it builds a throwaway project
// with secrets in it, then shows the policy engine and the Docker sandbox
// refusing access to them.
package demo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/longvo2k/agentguard/internal/audit"
	"github.com/longvo2k/agentguard/internal/config"
	"github.com/longvo2k/agentguard/internal/policy"
	"github.com/longvo2k/agentguard/internal/sandbox"
)

// Options control the demo.
type Options struct {
	Out      io.Writer
	Keep     bool   // keep the demo project instead of deleting it
	NoDocker bool   // only show the policy engine
	Image    string // sandbox image; default is the built-in one
}

// ErrUnexpected means an action that should have been blocked was not, or
// the reverse. The demo doubles as a self-test.
var ErrUnexpected = errors.New("demo: sandbox behaved unexpectedly")

const role = "developer"

var projectFiles = map[string]string{
	"src/app.js":            "const greet = (name) => `Hello, ${name}!`;\nconsole.log(greet('AgentGuard'));\n",
	"src/config/.env.local": "DATABASE_PASSWORD=hunter2\n",
	"tests/app.test.js":     "// tests go here\n",
	"logs/app.log":          "2026-01-01T00:00:00Z app started\n",
	".env":                  "OPENAI_API_KEY=sk-demo-not-a-real-key\nSTRIPE_SECRET=not-a-real-secret\n",
	"secrets/api-key.txt":   "sk-demo-1234567890\n",
}

// Run executes the demo.
func Run(ctx context.Context, opts Options) error {
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	base, err := os.MkdirTemp("", "agentguard-demo-")
	if err != nil {
		return err
	}
	project := filepath.Join(base, "demo")
	defer func() {
		if opts.Keep {
			fmt.Fprintf(out, "\nDemo project kept at %s\nTry:\n  cd %s\n  agentguard check read .env\n  agentguard run --role developer -- node src/app.js\n  agentguard audit\n", project, project)
			return
		}
		_ = os.RemoveAll(base)
	}()
	if err := createProject(project); err != nil {
		return err
	}
	if _, err := config.Init(project, false); err != nil {
		return err
	}
	ws, err := config.Open(project)
	if err != nil {
		return err
	}
	pol, err := ws.LoadPolicy(role)
	if err != nil {
		return err
	}
	logger := audit.NewLogger(ws.AuditPath())
	engine, err := policy.NewEngine(pol, project)
	if err != nil {
		return err
	}
	engine.SetObserver(logger.Observer("demo"))

	fmt.Fprintf(out, "AgentGuard demo: least-privilege sandboxing for AI coding agents\n\n")
	fmt.Fprintf(out, "Created a demo project with secrets in it:\n  %s\n", project)
	fmt.Fprintf(out, "  src/app.js  tests/  logs/app.log  .env  secrets/api-key.txt  src/config/.env.local\n\n")
	fmt.Fprintf(out, "Role %q may read src/ tests/ logs/, write src/ tests/, run git node npm.\n", role)
	fmt.Fprintf(out, "It has no network and is denied .env*, secrets/**, production/**.\n\n")

	failed := policySection(out, engine)

	if opts.NoDocker {
		fmt.Fprintf(out, "\n2. Sandbox enforcement: skipped (--no-docker)\n")
	} else if err := sandbox.Available(ctx); err != nil {
		fmt.Fprintf(out, "\n2. Sandbox enforcement: skipped (%v)\n", err)
		fmt.Fprintf(out, "   Install and start Docker to see the container refuse these actions.\n")
	} else {
		image := opts.Image
		if image == "" {
			image = ws.Config.Sandbox.Image
		}
		ok, err := sandboxSection(ctx, out, ws, engine, logger, image)
		if err != nil {
			return err
		}
		failed = failed || !ok
	}

	if err := logger.Err(); err != nil {
		return fmt.Errorf("audit log: %w", err)
	}
	entries, _ := audit.ReadFile(ws.AuditPath())
	s := audit.Summarize(entries)
	fmt.Fprintf(out, "\n3. Audit log\n   %d decisions recorded (%d allowed, %d denied) in .agentguard/audit.jsonl\n", s.Total, s.Allowed, s.Denied)
	if len(entries) > 0 {
		line, _ := json.Marshal(entries[len(entries)-1])
		fmt.Fprintf(out, "   last: %s\n", line)
	}
	if failed {
		return ErrUnexpected
	}
	fmt.Fprintf(out, "\nEvery denied action above was blocked outside the agent. No prompt asked it to behave.\n")
	return nil
}

func createProject(root string) error {
	for name, body := range projectFiles {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

type expectation struct {
	action   policy.Action
	resource string
	allow    bool
}

func policySection(out io.Writer, e *policy.Engine) (failed bool) {
	fmt.Fprintf(out, "1. Policy engine (what `agentguard check` answers)\n")
	cases := []expectation{
		{policy.ActionRead, "src/app.js", true},
		{policy.ActionWrite, "src/app.js", true},
		{policy.ActionRead, "logs/app.log", true},
		{policy.ActionExecute, "npm", true},
		{policy.ActionRead, ".env", false},
		{policy.ActionRead, "secrets/api-key.txt", false},
		{policy.ActionWrite, "logs/app.log", false},
		{policy.ActionRead, "src/../.env", false},
		{policy.ActionRead, "~/.ssh/id_rsa", false},
		{policy.ActionExecute, "curl", false},
		{policy.ActionNetwork, "api.example.com", false},
	}
	for _, c := range cases {
		d := e.Evaluate(c.action, c.resource)
		mark, verdict := "✓", "ALLOW"
		if !d.Allowed {
			mark, verdict = "✗", "DENY "
		}
		line := fmt.Sprintf("   %s %s %-8s %-22s", mark, verdict, c.action, c.resource)
		if d.Allowed {
			line += "  " + d.Rule
		} else {
			line += "  " + d.Reason
			if d.Rule != "" && !strings.HasPrefix(d.Rule, "commands.") && !strings.HasPrefix(d.Rule, "network.") {
				line += " (" + d.Rule + ")"
			}
		}
		if d.Allowed != c.allow {
			line += "   <-- UNEXPECTED"
			failed = true
		}
		fmt.Fprintln(out, strings.TrimRight(line, " "))
	}
	return failed
}

// probe runs inside the sandbox with only `node`, which the role allows. It
// tries each operation for real and reports the kernel's answer.
const probe = `
const fs = require('fs'), net = require('net');
const r = {};
const t = (k, f) => { try { f(); r[k] = 'ok'; } catch (e) { r[k] = e.code || String(e); } };
t('read src/app.js', () => fs.readFileSync('src/app.js'));
t('write src/app.js', () => fs.appendFileSync('src/app.js', '// edited by the agent\n'));
t('read logs/app.log', () => fs.readFileSync('logs/app.log'));
t('read .env', () => fs.readFileSync('.env'));
t('read secrets/api-key.txt', () => fs.readFileSync('secrets/api-key.txt'));
t('read src/config/.env.local', () => fs.readFileSync('src/config/.env.local'));
t('write logs/app.log', () => fs.appendFileSync('logs/app.log', 'tampered\n'));
t('read .agentguard/policies/developer.yaml', () => fs.readFileSync('.agentguard/policies/developer.yaml'));
const s = net.connect({host: '1.1.1.1', port: 443, timeout: 3000});
const done = (v) => { r['network'] = v; console.log(JSON.stringify(r)); process.exit(0); };
s.on('connect', () => done('ok')); s.on('error', (e) => done(e.code || String(e))); s.on('timeout', () => done('timeout'));
`

var errnoText = map[string]string{
	"ENOENT":      "not present in the sandbox (never mounted)",
	"EACCES":      "hidden behind an unreadable placeholder",
	"EROFS":       "mounted read-only",
	"ENETUNREACH": "the sandbox has no network",
	"timeout":     "connection timed out",
}

func sandboxSection(ctx context.Context, out io.Writer, ws *config.Workspace, e *policy.Engine, logger *audit.Logger, image string) (bool, error) {
	fmt.Fprintf(out, "\n2. Sandbox enforcement (a real Docker container, image %s)\n", image)
	if err := sandbox.EnsureImage(ctx, image, image == config.DefaultImage, out); err != nil {
		return false, err
	}
	cmds, err := sandbox.ResolveCommands(ctx, image, e.Policy().Commands.Allow, ws.CacheDir())
	if err != nil {
		return false, err
	}
	e.SetObserver(logger.Observer("run"))
	plan, err := sandbox.NewPlan(e, sandbox.Options{
		Image:        image,
		Memory:       ws.Config.Sandbox.Memory,
		CPUs:         ws.Config.Sandbox.CPUs,
		PidsLimit:    ws.Config.Sandbox.PidsLimit,
		CommandPaths: cmds,
		Record:       logger.Observer("sandbox"),
	})
	if err != nil {
		return false, err
	}
	defer plan.Cleanup()
	if err := makeWritableFor(ws.Root, plan.UID, plan.GID); err != nil {
		return false, err
	}

	var stdout, stderr bytes.Buffer
	code, err := plan.Run(ctx, []string{"node", "-e", probe}, nil, &stdout, &stderr)
	if err != nil || code != 0 {
		return false, fmt.Errorf("sandbox probe failed (exit %d): %v\n%s", code, err, stderr.String())
	}
	var r map[string]string
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		return false, fmt.Errorf("sandbox probe output %q: %w", stdout.String(), err)
	}

	var npmOut bytes.Buffer
	npmCode, npmErr := plan.Run(ctx, []string{"npm", "--version"}, nil, &npmOut, &npmOut)
	_, curlErr := plan.Run(ctx, []string{"curl", "https://example.com"}, nil, io.Discard, io.Discard)

	ok := true
	show := func(label string, allowed bool, result, detail string) {
		success := result == "ok"
		if success == allowed {
			if allowed {
				fmt.Fprintf(out, "   ✓ %s%s\n", label, detail)
			} else {
				why := errnoText[result]
				if why == "" {
					why = result
				}
				fmt.Fprintf(out, "   ✗ %s\n     Permission denied: %s\n", label, why)
			}
			return
		}
		ok = false
		fmt.Fprintf(out, "   !! %s: expected %s, got %s\n", label, map[bool]string{true: "success", false: "denial"}[allowed], result)
	}
	show("Read src/app.js", true, r["read src/app.js"], "")
	show("Write src/app.js", true, r["write src/app.js"], "")
	show("Read logs/app.log", true, r["read logs/app.log"], "")
	npmResult := "ok"
	if npmErr != nil || npmCode != 0 {
		npmResult = fmt.Sprintf("exit %d %v %s", npmCode, npmErr, strings.TrimSpace(npmOut.String()))
	}
	show("Execute npm", true, npmResult, " (npm "+strings.TrimSpace(npmOut.String())+")")
	show("Read .env", false, r["read .env"], "")
	show("Read secrets/api-key.txt", false, r["read secrets/api-key.txt"], "")
	show("Read src/config/.env.local (inside an allowed folder)", false, r["read src/config/.env.local"], "")
	show("Write logs/app.log", false, r["write logs/app.log"], "")
	show("Read .agentguard/policies/developer.yaml", false, r["read .agentguard/policies/developer.yaml"], "")
	show("Connect to the internet", false, r["network"], "")
	if errors.Is(curlErr, sandbox.ErrCommandDenied) {
		fmt.Fprintf(out, "   ✗ Execute curl\n     Permission denied: not in commands.allow, blocked before any container starts\n")
	} else {
		ok = false
		fmt.Fprintf(out, "   !! Execute curl: expected to be blocked, got %v\n", curlErr)
	}
	return ok, nil
}

// makeWritableFor gives the demo project to the sandbox uid when AgentGuard
// runs as root, because the sandbox itself never runs as root.
func makeWritableFor(root string, uid, gid int) error {
	if os.Getuid() != 0 {
		return nil
	}
	_ = os.Chmod(filepath.Dir(root), 0o755)
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == config.DirName {
			return fs.SkipDir
		}
		return os.Lchown(p, uid, gid)
	})
}
