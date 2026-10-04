package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// isolate points every user-level directory at a fresh temp dir.
func isolate(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	t.Setenv("AGENTGUARD_HOME", h)
	return h
}

func TestInitAndFind(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	written, err := Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := Trust(root); err != nil {
		t.Fatal(err)
	}
	if len(written) != 5 { // config + 4 policies
		t.Fatalf("wrote %v", written)
	}
	for _, f := range []string{"config.yaml", "policies/developer.yaml", "policies/tester.yaml", "policies/reviewer.yaml"} {
		if _, err := os.Stat(filepath.Join(root, ".agentguard", f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}

	sub := filepath.Join(root, "src", "deep")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	ws, err := Find(sub)
	if err != nil {
		t.Fatal(err)
	}
	if ws.Root != root || ws.Scope != ScopeProject {
		t.Errorf("root = %s (%s), want %s", ws.Root, ws.Scope, root)
	}
	if ws.Config.DefaultRole != "developer" || ws.Config.Image() != DefaultImage() {
		t.Errorf("config = %+v", ws.Config)
	}
	p, err := ws.LoadPolicy("developer")
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != "developer" || p.Network.Enabled {
		t.Errorf("policy = %+v", p)
	}
	if got := len(ws.Roles()); got != 4 {
		t.Errorf("roles = %v", ws.Roles())
	}
}

func TestInitKeepsExistingFiles(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	if _, err := Init(root, false); err != nil {
		t.Fatal(err)
	}
	custom := filepath.Join(root, ".agentguard/policies/developer.yaml")
	if err := os.WriteFile(custom, []byte("role: developer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	written, err := Init(root, false)
	if err != nil || len(written) != 0 {
		t.Fatalf("second init wrote %v (%v)", written, err)
	}
	data, _ := os.ReadFile(custom)
	if string(data) != "role: developer\n" {
		t.Error("init overwrote a customized policy")
	}
	if written, _ := Init(root, true); len(written) != 5 {
		t.Errorf("forced init wrote %v", written)
	}
}

func TestFindNotInitialized(t *testing.T) {
	isolate(t)
	if _, err := Find(t.TempDir()); err == nil {
		t.Fatal("expected ErrNotInitialized")
	}
}

func TestLoadPolicyRejectsTraversalAndMismatch(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	if _, err := Init(root, false); err != nil {
		t.Fatal(err)
	}
	ws, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"../../etc/passwd", "Developer", "", "dev/../x"} {
		if _, err := ws.LoadPolicy(role); err == nil {
			t.Errorf("LoadPolicy(%q) succeeded", role)
		}
	}
	if err := os.WriteFile(ws.PolicyPath("ops"), []byte("role: admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ws.LoadPolicy("ops"); err == nil {
		t.Error("expected role mismatch error")
	}
	if _, err := ws.LoadPolicy("missing"); err == nil {
		t.Error("expected missing policy error")
	}
}

func TestConfigValidation(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	if _, err := Init(root, false); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, ".agentguard/config.yaml")
	for _, body := range []string{
		"version: 1\naudit_log: ../src/audit.jsonl\n",
		"version: 1\naudit_log: /tmp/audit.jsonl\n",
		"version: 2\n",
		"version: 1\nunknown: true\n",
	} {
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(root); err == nil {
			t.Errorf("config %q accepted", body)
		}
	}
}

func TestBuiltinPolicy(t *testing.T) {
	for _, r := range []string{"agent", "developer", "tester", "reviewer"} {
		if _, err := BuiltinPolicy(r); err != nil {
			t.Errorf("%s: %v", r, err)
		}
	}
	if _, err := BuiltinPolicy("admin"); err == nil {
		t.Error("expected error")
	}
}

func TestFindRefusesNestedWorkspaces(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	if _, err := Init(root, false); err != nil {
		t.Fatal(err)
	}
	// An agent with write access to src/ plants its own permissive policy.
	planted := filepath.Join(root, "src")
	if err := os.MkdirAll(filepath.Join(planted, ".agentguard"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(planted); err == nil {
		t.Fatal("nested .agentguard was accepted")
	}
}

func TestUntrustedAndChangedProjectsAreRefused(t *testing.T) {
	isolate(t)
	root := t.TempDir()
	if _, err := Init(root, false); err != nil {
		t.Fatal(err)
	}
	// A .agentguard/ that came from somewhere else (a cloned repository, or
	// planted by an agent) is not trusted.
	if _, err := Find(root); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("untrusted project accepted: %v", err)
	}
	if err := Trust(root); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(root); err != nil {
		t.Fatalf("trusted project refused: %v", err)
	}
	// Loosening a policy invalidates the trust until it is reviewed again.
	pol := filepath.Join(root, ".agentguard/policies/developer.yaml")
	data, _ := os.ReadFile(pol)
	if err := os.WriteFile(pol, append(data, []byte("  - .git/**\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if st, _ := TrustStatus(root); st != Changed {
		t.Errorf("trust status = %v, want Changed", st)
	}
	_, err := Find(root)
	if !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed policy accepted: %v", err)
	}
	if err := Trust(root); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(root); err != nil {
		t.Fatal(err)
	}
	if err := Untrust(root); err != nil {
		t.Fatal(err)
	}
	if _, err := Find(root); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("untrusted project accepted: %v", err)
	}
}

func TestUserScope(t *testing.T) {
	home := isolate(t)
	if _, err := Find(t.TempDir()); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("expected ErrNotInitialized, got %v", err)
	}
	written, err := InitUser(false)
	if err != nil || len(written) != 5 {
		t.Fatalf("InitUser wrote %v (%v)", written, err)
	}
	cfgDir, _ := UserConfigDir()
	if cfgDir != filepath.Join(home, "config") {
		t.Errorf("config dir = %s", cfgDir)
	}

	// Inside a git repository the repository root is the workspace.
	repo := t.TempDir()
	sub := filepath.Join(repo, "src", "pkg")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	ws, err := Find(sub)
	if err != nil {
		t.Fatal(err)
	}
	realRepo, _ := filepath.EvalSymlinks(repo)
	if ws.Root != realRepo || ws.Scope != ScopeUser || ws.ConfigDir != cfgDir {
		t.Errorf("ws = %+v", ws)
	}
	if ws.Config.DefaultRole != "agent" {
		t.Errorf("user default role = %q, want agent", ws.Config.DefaultRole)
	}
	if _, err := ws.LoadPolicy("agent"); err != nil {
		t.Fatal(err)
	}
	// Logs live in the user state dir, never in the project.
	state, _ := UserStateDir()
	if !strings.HasPrefix(ws.AuditPath(), state) || strings.HasPrefix(ws.AuditPath(), realRepo) {
		t.Errorf("audit path = %s", ws.AuditPath())
	}

	// Outside a repository the current directory is the workspace.
	plain := t.TempDir()
	ws, err = Find(plain)
	if err != nil {
		t.Fatal(err)
	}
	if realPlain, _ := filepath.EvalSymlinks(plain); ws.Root != realPlain {
		t.Errorf("root = %s, want %s", ws.Root, realPlain)
	}

	// A trusted project-level .agentguard/ wins over user policies.
	if _, err := Init(repo, false); err != nil {
		t.Fatal(err)
	}
	if err := Trust(repo); err != nil {
		t.Fatal(err)
	}
	if ws, err := Find(sub); err != nil || ws.Scope != ScopeProject {
		t.Errorf("project scope not preferred: %+v %v", ws, err)
	}
}

func TestHomeIsNeverAWorkspace(t *testing.T) {
	isolate(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	if _, err := InitUser(false); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{home, filepath.Dir(home)} {
		if _, err := Find(dir); err == nil || !strings.Contains(err.Error(), "home directory") {
			t.Errorf("Find(%s) = %v, want refusal", dir, err)
		}
	}
	if _, err := Init(home, false); err == nil {
		t.Error("Init in the home directory was accepted")
	}
	// The user's own AgentGuard directories cannot be a workspace either.
	agHome := os.Getenv("AGENTGUARD_HOME")
	if _, err := Find(filepath.Join(agHome, "config")); err == nil {
		t.Error("AgentGuard config dir accepted as a workspace")
	}
}

func TestImageDefaults(t *testing.T) {
	c := Default()
	if c.Image() != DefaultImage() || !IsDefaultImage(c.Sandbox.Image) {
		t.Errorf("default image = %q", c.Image())
	}
	c.Sandbox.Image = "agentguard-sandbox:0.1" // written by v0.1.0
	if c.Image() != DefaultImage() {
		t.Errorf("legacy image not mapped: %q", c.Image())
	}
	c.Sandbox.Image = "node:22"
	if c.Image() != "node:22" || IsDefaultImage("node:22") {
		t.Error("custom image not honored")
	}
	old := imageDigest
	imageDigest = "sha256:abc"
	defer func() { imageDigest = old }()
	if DefaultImage() != ImageRepo+"@sha256:abc" {
		t.Errorf("pinned image = %s", DefaultImage())
	}
}
