package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitAndFind(t *testing.T) {
	root := t.TempDir()
	written, err := Init(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 4 { // config + 3 policies
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
	if ws.Root != root {
		t.Errorf("root = %s, want %s", ws.Root, root)
	}
	if ws.Config.DefaultRole != "developer" || ws.Config.Sandbox.Image != DefaultImage {
		t.Errorf("config = %+v", ws.Config)
	}
	p, err := ws.LoadPolicy("developer")
	if err != nil {
		t.Fatal(err)
	}
	if p.Role != "developer" || p.Network.Enabled {
		t.Errorf("policy = %+v", p)
	}
	if got := len(ws.Roles()); got != 3 {
		t.Errorf("roles = %v", ws.Roles())
	}
}

func TestInitKeepsExistingFiles(t *testing.T) {
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
	if written, _ := Init(root, true); len(written) != 4 {
		t.Errorf("forced init wrote %v", written)
	}
}

func TestFindNotInitialized(t *testing.T) {
	if _, err := Find(t.TempDir()); err == nil {
		t.Fatal("expected ErrNotInitialized")
	}
}

func TestLoadPolicyRejectsTraversalAndMismatch(t *testing.T) {
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
	for _, r := range []string{"developer", "tester", "reviewer"} {
		if _, err := BuiltinPolicy(r); err != nil {
			t.Errorf("%s: %v", r, err)
		}
	}
	if _, err := BuiltinPolicy("admin"); err == nil {
		t.Error("expected error")
	}
}

func TestFindRefusesNestedWorkspaces(t *testing.T) {
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
