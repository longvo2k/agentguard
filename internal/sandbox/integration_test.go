package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/longvo2k/agentguard/internal/config"
	"github.com/longvo2k/agentguard/internal/policy"
)

// These tests start real containers. They are skipped when Docker is not
// available or with -short. Set AGENTGUARD_TEST_IMAGE to use an existing
// image instead of building the default one.

// probe attempts each operation from inside the sandbox and reports the
// outcome as JSON, so the test can assert on what the kernel allowed.
const probe = `
const fs = require('fs'), net = require('net');
const out = {};
const tryIt = (name, fn) => { try { fn(); out[name] = 'ok'; } catch (e) { out[name] = e.code || String(e); } };
tryIt('read src/app.js', () => fs.readFileSync('src/app.js'));
tryIt('write src/app.js', () => fs.appendFileSync('src/app.js', '// edited in sandbox\n'));
tryIt('read logs/app.log', () => fs.readFileSync('logs/app.log'));
tryIt('write logs/app.log', () => fs.appendFileSync('logs/app.log', 'x'));
tryIt('read .env', () => fs.readFileSync('.env'));
tryIt('read secrets/api-key.txt', () => fs.readFileSync('secrets/api-key.txt'));
tryIt('read src/config/.env.local', () => fs.readFileSync('src/config/.env.local'));
tryIt('read .agentguard/config.yaml', () => fs.readFileSync('.agentguard/config.yaml'));
tryIt('read production/deploy.yaml', () => fs.readFileSync('production/deploy.yaml'));
tryIt('read via symlink', () => fs.readFileSync('src/key-link'));
tryIt('read /var/run/docker.sock', () => fs.statSync('/var/run/docker.sock'));
tryIt('write /etc/passwd', () => fs.appendFileSync('/etc/passwd', 'x'));
tryIt('write rootfs', () => fs.writeFileSync('/usr/local/x', 'x'));
tryIt('exec from /tmp', () => { fs.writeFileSync('/tmp/x.sh', '#!/bin/sh\necho hi'); fs.chmodSync('/tmp/x.sh', 0o755); require('child_process').execFileSync('/tmp/x.sh'); });
out.uid = process.getuid();
out.env = Object.keys(process.env).sort().join(',');
out.git_config = (() => { try { return fs.readFileSync('.git/config', 'utf8'); } catch (e) { return e.code; } })();
const s = net.connect({host: '1.1.1.1', port: 443, timeout: 3000});
const done = (r) => { out.network = r; console.log(JSON.stringify(out)); process.exit(0); };
s.on('connect', () => done('ok'));
s.on('error', (e) => done(e.code || String(e)));
s.on('timeout', () => done('timeout'));
`

func integrationImage(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping Docker integration test in -short mode")
	}
	ctx := context.Background()
	if err := Available(ctx); err != nil {
		t.Skipf("Docker not available: %v", err)
	}
	if img := os.Getenv("AGENTGUARD_TEST_IMAGE"); img != "" {
		ref, err := EnsureImage(ctx, img, "", os.Stderr)
		if err != nil {
			t.Fatal(err)
		}
		return ref
	}
	ref, err := EnsureImage(ctx, config.DefaultImage(), config.LocalImage, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

// chownForSandbox makes the workspace writable by the sandbox uid when the
// tests run as root (the sandbox never runs as root).
func chownForSandbox(t *testing.T, root string, uid, gid int) {
	t.Helper()
	if os.Getuid() != 0 {
		return
	}
	_ = os.Chmod(filepath.Dir(root), 0o755)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, uid, gid)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSandboxEnforcesPolicy(t *testing.T) {
	image := integrationImage(t)
	root := demoWorkspace(t)
	if err := os.Symlink("../secrets/api-key.txt", filepath.Join(root, "src", "key-link")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENTGUARD_TEST_SECRET", "hunter2")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, _ := policy.Parse([]byte(developerYAML))
	e, err := policy.NewEngine(p, root)
	if err != nil {
		t.Fatal(err)
	}
	cmds, err := ResolveCommands(ctx, image, p.Commands.Allow, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(e, Options{Image: image, CommandPaths: cmds, PidsLimit: 128, Memory: "512m"})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Cleanup()
	chownForSandbox(t, root, plan.UID, plan.GID)

	var stdout, stderr bytes.Buffer
	code, err := plan.Run(ctx, []string{"node", "-e", probe}, strings.NewReader(""), &stdout, &stderr)
	if err != nil || code != 0 {
		t.Fatalf("probe failed: code=%d err=%v\nstdout=%s\nstderr=%s", code, err, stdout.String(), stderr.String())
	}
	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("bad probe output %q: %v", stdout.String(), err)
	}

	want := map[string]string{
		"read src/app.js":              "ok",
		"write src/app.js":             "ok",
		"read logs/app.log":            "ok",
		"write logs/app.log":           "EROFS",
		"read .env":                    "ENOENT",
		"read secrets/api-key.txt":     "ENOENT",
		"read src/config/.env.local":   "EACCES",
		"read .agentguard/config.yaml": "ENOENT",
		"read production/deploy.yaml":  "ENOENT",
		"read via symlink":             "ENOENT",
		"read /var/run/docker.sock":    "ENOENT",
		"write /etc/passwd":            "EROFS|EACCES",
		"write rootfs":                 "EROFS",
		"exec from /tmp":               "EACCES",
		"network":                      "ENETUNREACH",
	}
	for k, v := range want {
		if s, _ := got[k].(string); !strings.Contains("|"+v+"|", "|"+s+"|") {
			t.Errorf("%s: got %v, want %s", k, got[k], v)
		}
	}
	if uid, _ := got["uid"].(float64); uid == 0 {
		t.Error("sandbox process runs as root")
	}
	if env, _ := got["env"].(string); strings.Contains(env, "AGENTGUARD_TEST_SECRET") {
		t.Errorf("host environment leaked: %s", env)
	}
	if gc, _ := got["git_config"].(string); strings.Contains(gc, "TOKEN") || !strings.Contains(gc, "repositoryformatversion") {
		t.Errorf("git config not sanitized: %q", gc)
	}

	// The write really reached the host, and the read-only file did not change.
	if data, _ := os.ReadFile(filepath.Join(root, "src/app.js")); !strings.Contains(string(data), "edited in sandbox") {
		t.Error("write to src/app.js did not reach the workspace")
	}
	if data, _ := os.ReadFile(filepath.Join(root, "logs/app.log")); string(data) != "started\n" {
		t.Errorf("logs/app.log changed: %q", data)
	}
}

func TestSandboxCommandGate(t *testing.T) {
	image := integrationImage(t)
	root := demoWorkspace(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, _ := policy.Parse([]byte(developerYAML))
	e, _ := policy.NewEngine(p, root)
	cmds, err := ResolveCommands(ctx, image, p.Commands.Allow, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(e, Options{Image: image, CommandPaths: cmds})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Cleanup()
	chownForSandbox(t, root, plan.UID, plan.GID)

	for _, argv := range [][]string{{"curl", "https://example.com"}, {"sh", "-c", "cat .env"}, {"/bin/sh"}, {"npm;sh"}} {
		_, err := plan.Run(ctx, argv, nil, &bytes.Buffer{}, &bytes.Buffer{})
		if !errors.Is(err, ErrCommandDenied) {
			t.Errorf("%v: expected ErrCommandDenied, got %v", argv, err)
		}
	}

	// npm runs, and only allowed commands are on PATH inside the sandbox.
	var out bytes.Buffer
	script := `const {execSync}=require('child_process');
for (const c of ['npm --version','git --version','curl --version','sh -c true','wget --version']) {
  try { execSync(c, {stdio:'pipe', shell: '/bin/sh'}); console.log(c.split(' ')[0]+'=found'); }
  catch (e) { console.log(c.split(' ')[0]+'=missing'); }
}`
	code, err := plan.Run(ctx, []string{"node", "-e", script}, nil, &out, &out)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%s", code, err, out.String())
	}
	res := out.String()
	for _, want := range []string{"npm=found", "git=found", "curl=missing", "wget=missing"} {
		if !strings.Contains(res, want) {
			t.Errorf("expected %s in:\n%s", want, res)
		}
	}
}

func TestSandboxGitIsReadOnlyEvenWithBroadWrite(t *testing.T) {
	image := integrationImage(t)
	root := demoWorkspace(t)
	writeFiles(t, root, map[string]string{".git/hooks/.keep": ""})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	p, _ := policy.Parse([]byte("role: broad\nfilesystem:\n  write: ['**']\ncommands:\n  allow: [node]\n"))
	e, _ := policy.NewEngine(p, root)
	cmds, err := ResolveCommands(ctx, image, p.Commands.Allow, "")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewPlan(e, Options{Image: image, CommandPaths: cmds})
	if err != nil {
		t.Fatal(err)
	}
	defer plan.Cleanup()
	chownForSandbox(t, root, plan.UID, plan.GID)
	script := `const fs=require('fs'); const r={};
for (const [k,f] of Object.entries({
  hook: () => fs.writeFileSync('.git/hooks/pre-commit', '#!/bin/sh\\ncurl evil'),
  policy: () => fs.writeFileSync('.agentguard/policies/broad.yaml', 'x'),
  plant: () => { fs.mkdirSync('src/.agentguard', {recursive: true}); },
  src: () => fs.writeFileSync('src/new.js', 'ok'),
})) { try { f(); r[k]='ok'; } catch (e) { r[k]=e.code; } }
console.log(JSON.stringify(r));`
	var out bytes.Buffer
	if code, err := plan.Run(ctx, []string{"node", "-e", script}, nil, &out, &out); err != nil || code != 0 {
		t.Fatalf("code=%d err=%v out=%s", code, err, out.String())
	}
	var r map[string]string
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatalf("%s: %v", out.String(), err)
	}
	if r["hook"] != "EROFS" || r["src"] != "ok" || r["policy"] == "ok" {
		t.Errorf("unexpected results %v", r)
	}
	// Planting a nested .agentguard inside the sandbox is possible (the path did
	// not exist at planning time), so discovery must refuse it afterwards.
	if r["plant"] == "ok" {
		if _, err := config.Find(filepath.Join(root, "src")); err == nil {
			t.Error("planted nested .agentguard accepted by config.Find")
		}
	}
}
