package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/longvo2k/agentguard/internal/audit"
	"github.com/longvo2k/agentguard/internal/config"
	"github.com/longvo2k/agentguard/internal/policy"
	"github.com/longvo2k/agentguard/internal/setup"
)

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// serverBinary is where server mode installs the binary the managed hook
// runs. It must be a root-owned path the agent's user cannot replace.
func serverBinary() string {
	if p := os.Getenv("AGENTGUARD_SERVER_BIN"); p != "" {
		return p
	}
	return "/usr/local/bin/agentguard"
}

func serverHookCommand(bin string) string {
	return setup.HookCommand(bin, false) + " --server"
}

// loadServerAt resolves the server workspace for dir. The role always comes
// from the root-owned configuration, never from flags or the environment,
// so whoever starts Claude Code cannot pick a looser role.
func loadServerAt(dir, source string) (*config.Workspace, *policy.Engine, *audit.Logger, error) {
	sc, err := config.LoadServer()
	if err != nil {
		return nil, nil, nil, err
	}
	ws, err := sc.WorkspaceFor(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	p, err := ws.LoadPolicy(ws.Config.DefaultRole)
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

// serverWorkspaces parses --workspace values of the form path[:role].
func serverWorkspaces(values []string) ([]config.ServerWorkspace, error) {
	var out []config.ServerWorkspace
	for _, v := range values {
		path, role, _ := strings.Cut(v, ":")
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(abs)
		if err != nil || !fi.IsDir() {
			return nil, fmt.Errorf("--workspace %s: not a directory", path)
		}
		if role != "" && !policy.ValidRole(role) {
			return nil, fmt.Errorf("--workspace %s: invalid role %q", path, role)
		}
		out = append(out, config.ServerWorkspace{Path: filepath.Clean(abs), Role: role})
	}
	return out, nil
}

func runServerSetup(out io.Writer, ask func(string) bool, workspaceArgs, domains []string, uninstall, purge bool) error {
	if os.Geteuid() != 0 {
		return errors.New("server mode writes root-owned files; run it with sudo")
	}
	if uninstall {
		return runServerUninstall(out, ask, purge)
	}
	workspaces, err := serverWorkspaces(workspaceArgs)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "AgentGuard server setup (%s)\n\n", version)

	// 1. A root-owned binary for the managed hook to run.
	bin := serverBinary()
	installed, err := setup.InstallBinary(bin)
	if err != nil {
		return fmt.Errorf("installing %s: %w", bin, err)
	}
	if installed {
		fmt.Fprintf(out, "✓ Installed %s (root-owned)\n", bin)
	} else {
		fmt.Fprintf(out, "✓ Using %s\n", bin)
	}

	// 2. System configuration and policies.
	if _, _, err := config.InitServer(workspaces); err != nil {
		return err
	}
	sc, err := config.LoadServer()
	if err != nil {
		return err
	}
	if len(domains) > 0 {
		for _, role := range serverRoles(sc) {
			path := filepath.Join(sc.Dir, "policies", role+".yaml")
			p, err := policy.LoadFile(path)
			if err != nil {
				return err
			}
			p.Network.Enabled = true
			p.Network.Allow = mergeUnique(p.Network.Allow, domains)
			if err := p.Validate(); err != nil {
				return err
			}
			if err := config.SavePolicy(sc.Dir, p); err != nil {
				return err
			}
		}
	}
	fmt.Fprintf(out, "✓ System policies in %s (root-owned; the agent cannot change them)\n", sc.Dir)
	for _, w := range sc.Config.Server.Workspaces {
		role := w.Role
		if role == "" {
			role = sc.Config.DefaultRole
		}
		fmt.Fprintf(out, "  workspace %s  role %s\n", w.Path, role)
	}

	// 3. Append-only audit logs: one per workspace, plus server.jsonl for
	// calls refused outside every workspace.
	logs := []string{config.ServerLogPath()}
	for _, w := range sc.Config.Server.Workspaces {
		logs = append(logs, config.AuditPathForServerWorkspace(w.Path))
	}
	for _, path := range logs {
		appendOnly, err := setup.PrepareLogFile(path)
		if err != nil {
			return err
		}
		note := "append-only"
		if !appendOnly {
			note = "chattr +a unavailable here, so not append-only"
		}
		fmt.Fprintf(out, "✓ Audit log %s (%s)\n", path, note)
	}

	// 4. Claude Code managed settings: hook, lock, sandbox.
	opts := setup.ManagedOptions{
		HookCommand: serverHookCommand(bin),
		DenyRead:    sc.Config.Server.DenyRead,
		SystemDir:   sc.Dir,
		LogDir:      config.SystemLogDir(),
	}
	for _, w := range sc.Config.Server.Workspaces {
		ws, err := sc.WorkspaceFor(w.Path)
		if err != nil {
			return err
		}
		p, err := ws.LoadPolicy(ws.Config.DefaultRole)
		if err != nil {
			return err
		}
		opts.Workspaces = append(opts.Workspaces, setup.ServerWorkspace{Root: ws.Root, Policy: p})
	}
	settings, warnings, err := setup.ManagedSettings(opts)
	if err != nil {
		return err
	}
	path, err := setup.WriteManagedSettings(settings)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "✓ Claude Code managed settings: %s\n", path)
	fmt.Fprintf(out, "  The AgentGuard hook cannot be disabled by users or projects. Every Bash\n")
	fmt.Fprintf(out, "  command runs in Claude Code's sandbox (bubblewrap): no reads of other\n")
	fmt.Fprintf(out, "  homes, /srv, /var/lib, credential stores or the secrets your policies deny;\n")
	fmt.Fprintf(out, "  network only to: %s\n", domainSummary(settings))
	for _, w := range warnings {
		fmt.Fprintf(out, "! %s\n", w)
	}

	// 5. Prerequisites for the sandbox.
	var missing []string
	for _, tool := range []string{"bwrap", "socat"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(out, "! Missing %s. Claude Code will refuse to start until you install them\n", strings.Join(missing, " and "))
		fmt.Fprintf(out, "  (Debian/Ubuntu: apt install bubblewrap socat; RHEL/Fedora: dnf install bubblewrap socat).\n")
	} else {
		fmt.Fprintf(out, "✓ bubblewrap and socat are installed\n")
	}

	fmt.Fprintf(out, "\nRun Claude Code as a dedicated unprivileged user (for example `claude-agent`)\n")
	fmt.Fprintf(out, "from inside a workspace. As root, every tool call is blocked.\n")
	fmt.Fprintf(out, "After editing %s, rerun `sudo agentguard setup --server`.\n", filepath.Join(sc.Dir, "config.yaml"))
	fmt.Fprintf(out, "Check with `agentguard doctor --server`.\n")
	return nil
}

func runServerUninstall(out io.Writer, ask func(string) bool, purge bool) error {
	removed, err := setup.RemoveManagedSettings()
	if err != nil {
		return err
	}
	if removed {
		fmt.Fprintf(out, "✓ Removed %s\n", setup.ManagedSettingsFile())
	} else {
		fmt.Fprintf(out, "- No AgentGuard managed settings to remove\n")
	}
	if !purge {
		fmt.Fprintf(out, "Policies and audit logs were kept (use --purge to delete them).\n")
		return nil
	}
	dirs := []string{config.SystemConfigDir(), config.SystemLogDir()}
	if !ask("Delete " + strings.Join(dirs, " and ") + "?") {
		return nil
	}
	for _, d := range dirs {
		if filepath.Base(d) != "agentguard" && os.Getenv("AGENTGUARD_SYSTEM_DIR") == "" {
			return fmt.Errorf("refusing to delete unexpected directory %s", d)
		}
		// Append-only logs must lose the flag before they can be deleted.
		if logs, _ := filepath.Glob(filepath.Join(d, "*.jsonl")); len(logs) > 0 {
			_ = exec.Command("chattr", append([]string{"-a"}, logs...)...).Run()
		}
		if err := os.RemoveAll(d); err != nil {
			return err
		}
		fmt.Fprintf(out, "✓ Deleted %s\n", d)
	}
	return nil
}

func serverRoles(sc *config.ServerConfig) []string {
	seen := map[string]bool{}
	var roles []string
	for _, w := range sc.Config.Server.Workspaces {
		r := w.Role
		if r == "" {
			r = sc.Config.DefaultRole
		}
		if !seen[r] {
			seen[r] = true
			roles = append(roles, r)
		}
	}
	return roles
}

func mergeUnique(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range append(append([]string{}, a...), b...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func domainSummary(settings map[string]any) string {
	d := settings["sandbox"].(map[string]any)["network"].(map[string]any)["allowedDomains"].([]string)
	if len(d) == 0 {
		return "no hosts"
	}
	return strings.Join(d, ", ")
}

// cmdServerDoctor checks a server installation.
func cmdServerDoctor(out io.Writer) (int, error) {
	problems := 0
	ok := func(f string, a ...any) { fmt.Fprintf(out, "✓ "+f+"\n", a...) }
	warn := func(f string, a ...any) { fmt.Fprintf(out, "! "+f+"\n", a...) }
	bad := func(f string, a ...any) { problems++; fmt.Fprintf(out, "✗ "+f+"\n", a...) }

	sc, err := config.LoadServer()
	if err != nil {
		bad("System configuration: %v", err)
	} else {
		ok("System configuration %s is root-owned", sc.Dir)
		for _, w := range sc.Config.Server.Workspaces {
			if fi, err := os.Stat(w.Path); err != nil || !fi.IsDir() {
				bad("Workspace %s does not exist", w.Path)
			} else {
				ok("Workspace %s", w.Path)
			}
		}
	}

	managed := setup.ManagedSettingsFile()
	data, err := os.ReadFile(managed)
	switch {
	case err != nil:
		bad("Claude Code managed settings %s missing (run `sudo agentguard setup --server`)", managed)
	case !setup.OwnedByRoot(managed):
		bad("%s must be root-owned and not writable by others", managed)
	case !strings.Contains(string(data), "hook claude --server"):
		bad("%s does not install the AgentGuard server hook", managed)
	default:
		ok("Claude Code managed settings %s", managed)
	}
	if bin := serverBinary(); !setup.OwnedByRoot(bin) {
		bad("%s must exist and be root-owned", bin)
	} else {
		ok("Hook binary %s is root-owned", bin)
	}
	for _, tool := range []string{"bwrap", "socat"} {
		if _, err := exec.LookPath(tool); err != nil {
			bad("%s is not installed; Claude Code will not start with the required sandbox", tool)
		} else {
			ok("%s installed", tool)
		}
	}
	if os.Geteuid() == 0 {
		warn("doctor is running as root; run Claude Code itself as an unprivileged user")
	}
	if problems > 0 {
		return 1, nil
	}
	return 0, nil
}
