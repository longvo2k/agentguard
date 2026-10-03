package sandbox

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/longvo2k/agentguard/internal/policy"
)

const developerYAML = `
role: developer
filesystem:
  read: [src/**, tests/**, logs/**]
  write: [src/**, tests/**]
commands:
  allow: [git, node, npm]
network:
  enabled: false
deny: [.env*, secrets/**, production/**, ~/.ssh/**]
`

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func demoWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeFiles(t, root, map[string]string{
		"src/app.js":              "console.log('hi')\n",
		"src/config/.env.local":   "TOKEN=x\n",
		"src/certs/server.pem":    "-----BEGIN-----\n",
		"tests/.keep":             "",
		"logs/app.log":            "started\n",
		".env":                    "SECRET=1\n",
		"secrets/api-key.txt":     "sk-123\n",
		"production/deploy.yaml":  "",
		".git/HEAD":               "ref: refs/heads/main\n",
		".git/config":             "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = /tmp/evil\n\tbare = false\n[remote \"origin\"]\n\turl = https://user:ghp_TOKEN@github.com/x/y\n[credential]\n\thelper = store\n",
		".agentguard/config.yaml": "",
	})
	return root
}

func newPlan(t *testing.T, yml, root string, opts Options) (*Plan, []policy.Decision) {
	t.Helper()
	p, err := policy.Parse([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	e, err := policy.NewEngine(p, root)
	if err != nil {
		t.Fatal(err)
	}
	var decisions []policy.Decision
	e.SetObserver(func(d policy.Decision) { decisions = append(decisions, d) })
	if opts.Image == "" {
		opts.Image = "agentguard-sandbox:test"
	}
	if opts.CommandPaths == nil {
		opts.CommandPaths = map[string]string{"git": "/usr/bin/git", "node": "/usr/local/bin/node", "npm": "/usr/local/bin/npm"}
	}
	opts.Record = func(d policy.Decision) { decisions = append(decisions, d) }
	plan, err := NewPlan(e, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(plan.Cleanup)
	return plan, decisions
}

func mountByTarget(p *Plan) map[string]Mount {
	m := map[string]Mount{}
	for _, mt := range p.Mounts {
		m[mt.Target] = mt
	}
	return m
}

func TestDeveloperPlan(t *testing.T) {
	root := demoWorkspace(t)
	plan, decisions := newPlan(t, developerYAML, root, Options{})
	real, _ := filepath.EvalSymlinks(root)
	m := mountByTarget(plan)

	expect := map[string]bool{ // target -> read-only
		"/workspace/src":   false,
		"/workspace/tests": false,
		"/workspace/logs":  true,
		"/workspace/.git":  true,
	}
	for target, ro := range expect {
		mt, ok := m[target]
		if !ok {
			t.Errorf("missing mount %s", target)
			continue
		}
		if mt.ReadOnly != ro || mt.Kind != "workspace" {
			t.Errorf("%s: readOnly=%v kind=%s", target, mt.ReadOnly, mt.Kind)
		}
		if !strings.HasPrefix(mt.Source, real) {
			t.Errorf("%s: source %s outside workspace", target, mt.Source)
		}
	}
	for _, target := range []string{"/workspace/.env", "/workspace/secrets", "/workspace/production", "/workspace/.agentguard", "/workspace"} {
		if _, ok := m[target]; ok {
			t.Errorf("%s must not be mounted", target)
		}
	}
	for _, target := range []string{"/workspace/src/config/.env.local", "/workspace/src/certs/server.pem", "/workspace/.git/config"} {
		mt, ok := m[target]
		if !ok || mt.Kind != "hide" || !mt.ReadOnly {
			t.Errorf("%s should be hidden, got %+v", target, mt)
		}
	}

	// Hidden placeholders are mode 0000 and outside the workspace.
	hidden := m["/workspace/src/config/.env.local"]
	fi, err := os.Stat(hidden.Source)
	if err != nil || fi.Mode().Perm() != 0 || strings.HasPrefix(hidden.Source, real) {
		t.Errorf("placeholder %s: %v %v", hidden.Source, fi, err)
	}

	// The sanitized git config keeps format settings and drops secrets and programs.
	data, err := os.ReadFile(m["/workspace/.git/config"].Source)
	if err != nil {
		t.Fatal(err)
	}
	cfg := string(data)
	if !strings.Contains(cfg, "repositoryformatversion = 0") || strings.Contains(cfg, "TOKEN") ||
		strings.Contains(cfg, "fsmonitor") || strings.Contains(cfg, "credential") {
		t.Errorf("git config not sanitized:\n%s", cfg)
	}

	// Mounts are ordered so parents come before the paths hidden inside them.
	idx := map[string]int{}
	for i, mt := range plan.Mounts {
		idx[mt.Target] = i
	}
	if idx["/workspace/src"] > idx["/workspace/src/config/.env.local"] {
		t.Error("hide mount ordered before its parent mount")
	}

	if plan.Network {
		t.Error("network should be disabled")
	}
	var sawNetwork, sawHide bool
	for _, d := range decisions {
		if d.Action == policy.ActionNetwork && !d.Allowed {
			sawNetwork = true
		}
		if d.Resource == filepath.FromSlash("src/config/.env.local") && !d.Allowed {
			sawHide = true
		}
	}
	if !sawNetwork || !sawHide {
		t.Errorf("decisions not recorded: %+v", decisions)
	}
}

func TestDockerArgsAreLockedDown(t *testing.T) {
	root := demoWorkspace(t)
	t.Setenv("AGENTGUARD_TEST_SECRET", "hunter2")
	plan, _ := newPlan(t, developerYAML, root, Options{PidsLimit: 128, Memory: "512m"})
	args := plan.DockerArgs([]string{"npm", "test"}, false)
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"run --rm", "--network none", "--cap-drop ALL", "--security-opt no-new-privileges",
		"--read-only", "--pull=never", "--pids-limit 128", "--memory 512m",
		"PATH=" + ShimDir, "HOME=" + HomeDir, "npm_config_script_shell=/bin/sh", "--entrypoint " + ShimDir + "/npm agentguard-sandbox:test test",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("docker args missing %q", want)
		}
	}
	for _, bad := range []string{"docker.sock", "--privileged", "hunter2", "AGENTGUARD_TEST_SECRET", ".ssh", "-v ", "--volume", "--env-file", "seccomp=unconfined", "--network host"} {
		if strings.Contains(joined, bad) {
			t.Errorf("docker args must not contain %q:\n%s", bad, joined)
		}
	}
	for i, a := range args {
		if a == "--user" && (strings.HasPrefix(args[i+1], "0:") || args[i+1] == "0") {
			t.Errorf("container runs as root: %s", args[i+1])
		}
		if a == "--env" && !strings.Contains(args[i+1], "=") {
			t.Errorf("--env %s would inherit a host variable", args[i+1])
		}
	}
	if plan.UID == 0 || plan.GID == 0 {
		t.Error("plan uses root")
	}
}

func TestCommandShims(t *testing.T) {
	root := demoWorkspace(t)
	plan, _ := newPlan(t, developerYAML, root, Options{CommandPaths: map[string]string{"node": "/usr/local/bin/node", "npm": "/usr/local/bin/npm"}})
	bin := mountByTarget(plan)[ShimDir].Source
	entries, err := os.ReadDir(bin)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "node,npm" {
		t.Errorf("shims = %v", names)
	}
	if target, _ := os.Readlink(filepath.Join(bin, "npm")); target != "/usr/local/bin/npm" {
		t.Errorf("npm shim -> %s", target)
	}
	if len(plan.Warnings) == 0 || !strings.Contains(strings.Join(plan.Warnings, "\n"), `"git" is allowed but was not found`) {
		t.Errorf("expected warning about missing git, got %v", plan.Warnings)
	}
}

func TestReviewerMountsReadOnly(t *testing.T) {
	root := demoWorkspace(t)
	plan, _ := newPlan(t, "role: reviewer\nfilesystem:\n  read: [src/**, tests/**]\n  write: []\ncommands:\n  allow: [git]\n", root, Options{})
	for _, mt := range plan.Mounts {
		if !mt.ReadOnly {
			t.Errorf("reviewer has writable mount %+v", mt)
		}
	}
	if _, ok := mountByTarget(plan)["/workspace/logs"]; ok {
		t.Error("reviewer should not see logs")
	}
}

func TestBroadPatternHidesSensitiveFiles(t *testing.T) {
	root := demoWorkspace(t)
	plan, _ := newPlan(t, "role: broad\nfilesystem:\n  read: ['**']\n  write: [src/**]\n", root, Options{})
	m := mountByTarget(plan)
	if mt, ok := m["/workspace"]; !ok || !mt.ReadOnly {
		t.Fatalf("expected read-only root mount, got %+v", mt)
	}
	if mt, ok := m["/workspace/src"]; !ok || mt.ReadOnly {
		t.Errorf("expected nested writable src mount, got %+v", mt)
	}
	for _, target := range []string{"/workspace/.env", "/workspace/.agentguard", "/workspace/.git/config", "/workspace/src/config/.env.local"} {
		if mt, ok := m[target]; !ok || mt.Kind != "hide" {
			t.Errorf("%s should be hidden, got %+v", target, mt)
		}
	}
	if len(plan.Warnings) == 0 {
		t.Error("expected a warning about the whole-workspace mount")
	}
}

func TestSymlinkedMountSourceIsRefused(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFiles(t, outside, map[string]string{"id_rsa.txt": "key"})
	if err := os.Symlink(outside, filepath.Join(root, "src")); err != nil {
		t.Fatal(err)
	}
	plan, _ := newPlan(t, developerYAML, root, Options{})
	for _, mt := range plan.Mounts {
		if mt.Kind == "workspace" {
			t.Errorf("symlinked source mounted: %+v", mt)
		}
	}
}

func TestSpecialFilesAreHidden(t *testing.T) {
	// Unix socket paths are limited in length; use a short directory.
	short, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(short)
	writeFiles(t, short, map[string]string{"src/app.js": ""})
	l, err := net.Listen("unix", filepath.Join(short, "src", "s.sock"))
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	defer l.Close()
	plan, _ := newPlan(t, developerYAML, short, Options{})
	if mt, ok := mountByTarget(plan)["/workspace/src/s.sock"]; !ok || mt.Kind != "hide" {
		t.Errorf("socket not hidden: %+v", mt)
	}
}

func TestMissingDirectoriesAreSkipped(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"src/app.js": ""})
	plan, _ := newPlan(t, developerYAML, root, Options{})
	m := mountByTarget(plan)
	if _, ok := m["/workspace/tests"]; ok {
		t.Error("missing tests/ was mounted")
	}
	if _, ok := m["/workspace/src"]; !ok {
		t.Error("src/ not mounted")
	}
}

func TestUnsafeMountPathRejected(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"src/a,b/x.js": ""})
	// src/ is mounted as a whole, so only a hide target can carry the comma.
	// Force one by denying that directory.
	p, err := policy.Parse([]byte("role: dev\nfilesystem:\n  read: [src/**]\ndeny: ['a,b']\n"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := policy.NewEngine(p, root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPlan(e, Options{Image: "x"}); err == nil {
		t.Fatal("expected error for comma in mount path")
	}
}

func TestContainerUser(t *testing.T) {
	if _, _, err := containerUser("0:0"); err == nil {
		t.Error("root override accepted")
	}
	if _, _, err := containerUser("abc"); err == nil {
		t.Error("garbage override accepted")
	}
	uid, gid, err := containerUser("")
	if err != nil || uid == 0 || gid == 0 {
		t.Errorf("default user %d:%d %v", uid, gid, err)
	}
}

func TestGitInsideWritableMountIsReadOnly(t *testing.T) {
	root := demoWorkspace(t)
	writeFiles(t, root, map[string]string{"src/vendor/lib/.git": "gitdir: ../../../.git/modules/lib\n"})
	plan, _ := newPlan(t, "role: broad\nfilesystem:\n  write: ['**']\n", root, Options{})
	m := mountByTarget(plan)
	if mt, ok := m["/workspace"]; !ok || mt.ReadOnly {
		t.Fatalf("expected writable root mount, got %+v", mt)
	}
	for _, target := range []string{"/workspace/.git", "/workspace/src/vendor/lib/.git"} {
		if mt, ok := m[target]; !ok || !mt.ReadOnly || mt.Kind != "protect" {
			t.Errorf("%s should be re-mounted read-only, got %+v", target, mt)
		}
	}
	if mt := m["/workspace/.git/config"]; mt.Kind != "hide" {
		t.Errorf(".git/config should still be sanitized, got %+v", mt)
	}
	if mt := m["/workspace/.agentguard"]; mt.Kind != "hide" {
		t.Errorf(".agentguard should be hidden, got %+v", mt)
	}
}
