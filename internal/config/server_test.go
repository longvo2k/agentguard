package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serverEnv points the system directories at temp dirs. The ownership
// checks need real root-owned files, so these tests run only as root.
func serverEnv(t *testing.T) (sysDir string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("server-mode ownership checks need root")
	}
	isolate(t)
	base := t.TempDir()
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	sysDir = filepath.Join(base, "etc-agentguard")
	t.Setenv("AGENTGUARD_SYSTEM_DIR", sysDir)
	t.Setenv("AGENTGUARD_LOG_DIR", filepath.Join(base, "log"))
	return sysDir
}

func TestInitServerAndWorkspaces(t *testing.T) {
	sysDir := serverEnv(t)
	app := t.TempDir()
	inner := filepath.Join(app, "sub")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(); err != ErrNoServerConfig {
		t.Fatalf("LoadServer before setup = %v", err)
	}
	written, _, err := InitServer([]ServerWorkspace{{Path: app}})
	if err != nil {
		t.Fatal(err)
	}
	if len(written) != 5 {
		t.Errorf("wrote %v", written)
	}
	for _, f := range written {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o644 {
			t.Errorf("%s mode %v, want 0644", f, fi.Mode().Perm())
		}
	}
	// Re-running merges workspaces instead of replacing them.
	if _, _, err := InitServer([]ServerWorkspace{{Path: inner, Role: "reviewer"}}); err != nil {
		t.Fatal(err)
	}
	sc, err := LoadServer()
	if err != nil {
		t.Fatal(err)
	}
	if sc.Dir != sysDir || len(sc.Config.Server.Workspaces) != 2 {
		t.Fatalf("server config = %+v", sc.Config.Server)
	}

	ws, err := sc.WorkspaceFor(filepath.Join(app, "x", "y"))
	if err != nil {
		t.Fatal(err)
	}
	realApp, _ := filepath.EvalSymlinks(app)
	if ws.Root != realApp || ws.Scope != ScopeServer || ws.Config.DefaultRole != "agent" {
		t.Errorf("workspace = %+v", ws)
	}
	if !strings.HasPrefix(ws.AuditPath(), SystemLogDir()) {
		t.Errorf("audit path %s not in the system log dir", ws.AuditPath())
	}
	if p, err := ws.LoadPolicy("agent"); err != nil || p.Role != "agent" {
		t.Errorf("policy: %v", err)
	}
	// The innermost workspace wins, with its own role.
	if ws, err := sc.WorkspaceFor(inner); err != nil || ws.Config.DefaultRole != "reviewer" {
		t.Errorf("nested workspace: %+v %v", ws, err)
	}
	// Anything else is refused.
	if _, err := sc.WorkspaceFor(t.TempDir()); err == nil || !strings.Contains(err.Error(), "outside the workspaces") {
		t.Errorf("outside dir accepted: %v", err)
	}
	if _, err := sc.WorkspaceFor("/"); err == nil {
		t.Error("/ accepted")
	}
}

func TestServerConfigMustBeRootOwned(t *testing.T) {
	sysDir := serverEnv(t)
	if _, _, err := InitServer([]ServerWorkspace{{Path: t.TempDir()}}); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(sysDir, "policies", "agent.yaml")

	// Writable by others: the agent's user could loosen it.
	if err := os.Chmod(pol, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("world-writable policy accepted: %v", err)
	}
	if err := os.Chmod(pol, 0o644); err != nil {
		t.Fatal(err)
	}

	// Owned by another user.
	if err := os.Chown(pol, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Errorf("non-root-owned policy accepted: %v", err)
	}
	if err := os.Chown(pol, 0, 0); err != nil {
		t.Fatal(err)
	}

	// A symlink could point at a file the agent controls.
	link := filepath.Join(sysDir, "policies", "evil.yaml")
	if err := os.Symlink("/tmp/whatever", link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("symlink accepted: %v", err)
	}
	os.Remove(link)

	// A writable parent directory lets someone swap the whole directory.
	parent := filepath.Dir(sysDir)
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(); err == nil {
		t.Error("world-writable parent accepted")
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadServer(); err != nil {
		t.Fatalf("restored config refused: %v", err)
	}
}

func TestServerValidation(t *testing.T) {
	for _, s := range []Server{
		{},
		{Workspaces: []ServerWorkspace{{Path: "relative/app"}}},
		{Workspaces: []ServerWorkspace{{Path: "/"}}},
		{Workspaces: []ServerWorkspace{{Path: "/srv/app/../etc"}}},
		{Workspaces: []ServerWorkspace{{Path: "/srv/a,b"}}},
		{Workspaces: []ServerWorkspace{{Path: "/srv/app", Role: "Bad Role"}}},
		{Workspaces: []ServerWorkspace{{Path: "/srv/app"}}, DenyRead: []string{"etc/x"}},
	} {
		c := Default()
		s := s
		c.Server = &s
		if err := c.Validate(); err == nil {
			t.Errorf("accepted %+v", s)
		}
	}
}
