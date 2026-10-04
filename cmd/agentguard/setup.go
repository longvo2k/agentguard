package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/longvo2k/agentguard/internal/config"
	"github.com/longvo2k/agentguard/internal/hook"
	"github.com/longvo2k/agentguard/internal/policy"
	"github.com/longvo2k/agentguard/internal/sandbox"
	"github.com/longvo2k/agentguard/internal/setup"
)

// cmdSetup performs the one-time, per-user installation. Every step is
// idempotent and is undone by `agentguard setup --uninstall`.
func cmdSetup(args []string, stdin io.Reader, out io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "accept every step without asking")
	skipImage := fs.Bool("skip-image", false, "do not pull the sandbox image")
	skipHook := fs.Bool("skip-hook", false, "do not install the Claude Code hook")
	uninstall := fs.Bool("uninstall", false, "remove the Claude Code hook")
	purge := fs.Bool("purge", false, "with --uninstall: also delete user policies, trust list, logs and cache")
	pos, _, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("unexpected argument %q", pos[0])
	}
	ask := asker(stdin, out, *yes)
	if *uninstall {
		return runUninstall(out, ask, *purge)
	}
	if *purge {
		return usagef("--purge only works with --uninstall")
	}

	fmt.Fprintf(out, "AgentGuard setup (%s)\n\n", version)

	// 1. User-level policies, used by every project without its own.
	cfgDir, err := config.UserConfigDir()
	if err != nil {
		return err
	}
	written, err := config.InitUser(false)
	if err != nil {
		return err
	}
	if len(written) > 0 {
		fmt.Fprintf(out, "✓ Created user policies in %s\n", cfgDir)
		fmt.Fprintf(out, "  Default role \"agent\": the whole project except secrets, .git and .claude; no network.\n")
	} else {
		fmt.Fprintf(out, "✓ User policies already in %s (kept as they are)\n", cfgDir)
	}

	// 2. Docker and the sandbox image, for `agentguard run`.
	ctx := context.Background()
	if err := sandbox.Available(ctx); err != nil {
		fmt.Fprintf(out, "! Docker: %v\n  The Claude Code hook works without Docker; `agentguard run` needs it.\n", err)
	} else if *skipImage {
		fmt.Fprintf(out, "- Sandbox image: skipped (--skip-image)\n")
	} else {
		ref, err := sandbox.EnsureImage(ctx, config.DefaultImage(), config.LocalImage, out)
		if err != nil {
			fmt.Fprintf(out, "! Sandbox image: %v\n", err)
		} else {
			fmt.Fprintf(out, "✓ Sandbox image ready: %s\n", ref)
		}
	}

	// 3. Claude Code hook.
	settings, err := setup.ClaudeSettingsPath()
	if err != nil {
		return err
	}
	switch {
	case *skipHook:
		fmt.Fprintf(out, "- Claude Code hook: skipped (--skip-hook)\n")
	case !setup.ClaudeDetected():
		fmt.Fprintf(out, "- Claude Code not found. After installing it, run `agentguard setup` again.\n")
	case ask(fmt.Sprintf("Install the AgentGuard hook into %s?", settings)):
		exe, err := setup.StableExecutable()
		if err != nil {
			return err
		}
		changed, err := setup.InstallClaudeHook(settings, setup.HookCommand(exe))
		if err != nil {
			return err
		}
		if changed {
			fmt.Fprintf(out, "✓ Claude Code hook installed (backup: %s.agentguard-backup)\n", settings)
		} else {
			fmt.Fprintf(out, "✓ Claude Code hook already installed\n")
		}
		fmt.Fprintf(out, "  Claude Code now asks AgentGuard before reading, editing or running anything.\n")
	default:
		fmt.Fprintf(out, "- Claude Code hook: not installed\n")
	}

	fmt.Fprintf(out, "\nDone. Check with `agentguard doctor`.\n")
	fmt.Fprintf(out, "Per-project policies: `agentguard init` in a project overrides the user policies.\n")
	fmt.Fprintf(out, "Undo everything: `agentguard setup --uninstall [--purge]`.\n")
	return nil
}

func runUninstall(out io.Writer, ask func(string) bool, purge bool) error {
	settings, err := setup.ClaudeSettingsPath()
	if err != nil {
		return err
	}
	changed, err := setup.UninstallClaudeHook(settings)
	if err != nil {
		return err
	}
	if changed {
		fmt.Fprintf(out, "✓ Removed the AgentGuard hook from %s\n", settings)
	} else {
		fmt.Fprintf(out, "- No AgentGuard hook in %s\n", settings)
	}
	if !purge {
		fmt.Fprintf(out, "User policies and logs were kept (use --purge to delete them).\n")
		return nil
	}
	var dirs []string
	for _, fn := range []func() (string, error){config.UserConfigDir, config.UserStateDir, config.UserCacheDir} {
		if d, err := fn(); err == nil {
			dirs = append(dirs, d)
		}
	}
	if !ask("Delete " + strings.Join(dirs, ", ") + "?") {
		fmt.Fprintln(out, "- Kept user files")
		return nil
	}
	for _, d := range dirs {
		// Only ever delete AgentGuard's own directories.
		agHome := os.Getenv("AGENTGUARD_HOME")
		if filepath.Base(d) != "agentguard" && (agHome == "" || filepath.Dir(d) != filepath.Clean(agHome)) {
			return fmt.Errorf("refusing to delete unexpected directory %s", d)
		}
		if err := os.RemoveAll(d); err != nil {
			return err
		}
		fmt.Fprintf(out, "✓ Deleted %s\n", d)
	}
	return nil
}

// asker returns a yes/no prompt. Without a terminal it declines unless
// --yes was given, so setup never changes things silently.
func asker(stdin io.Reader, out io.Writer, yes bool) func(string) bool {
	reader := bufio.NewReader(stdin)
	return func(q string) bool {
		if yes {
			return true
		}
		if !sandbox.IsTerminal(stdin) {
			fmt.Fprintf(out, "%s skipped (no terminal; rerun with --yes)\n", q)
			return false
		}
		fmt.Fprintf(out, "%s [Y/n] ", q)
		line, _ := reader.ReadString('\n')
		line = strings.ToLower(strings.TrimSpace(line))
		return line == "" || line == "y" || line == "yes"
	}
}

// cmdDoctor reports whether every piece is in place.
func cmdDoctor(args []string, out io.Writer) (int, error) {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	if _, _, err := parse(fs, args); err != nil {
		return 2, err
	}
	problems := 0
	ok := func(f string, a ...any) { fmt.Fprintf(out, "✓ "+f+"\n", a...) }
	warn := func(f string, a ...any) { fmt.Fprintf(out, "! "+f+"\n", a...) }
	bad := func(f string, a ...any) { problems++; fmt.Fprintf(out, "✗ "+f+"\n", a...) }

	exe, _ := setup.StableExecutable()
	ok("agentguard %s (%s)", version, exe)

	ctx := context.Background()
	if err := sandbox.Available(ctx); err != nil {
		warn("Docker: %v (needed for `agentguard run`, not for the hook)", err)
	} else {
		ok("Docker daemon reachable")
		switch img := config.DefaultImage(); {
		case sandbox.ImageExists(ctx, img):
			ok("Sandbox image %s", img)
		case sandbox.ImageExists(ctx, config.LocalImage):
			ok("Sandbox image %s (built locally)", config.LocalImage)
		default:
			warn("Sandbox image not present yet; it is pulled on first `agentguard run` (or run `agentguard setup`)")
		}
	}

	cfgDir, _ := config.UserConfigDir()
	if _, err := os.Stat(filepath.Join(cfgDir, "config.yaml")); err != nil {
		warn("No user policies in %s (run `agentguard setup`)", cfgDir)
	} else if roles, err := checkPolicies(cfgDir); err != nil {
		bad("User policies in %s: %v", cfgDir, err)
	} else {
		ok("User policies in %s: %s", cfgDir, strings.Join(roles, ", "))
	}

	cwd, _ := os.Getwd()
	ws, err := config.Find(cwd)
	switch {
	case errors.Is(err, config.ErrNotInitialized):
		warn("This directory is not covered by any policy")
	case err != nil:
		bad("This directory: %v", err)
	default:
		ok("This directory: %s policies (role %q), workspace %s", ws.Scope, ws.Config.DefaultRole, ws.Root)
		if _, err := ws.LoadPolicy(ws.Config.DefaultRole); err != nil {
			bad("Default role: %v", err)
		}
	}

	settings, _ := setup.ClaudeSettingsPath()
	if cmd, installed := setup.ClaudeHookInstalled(settings); installed {
		bin := strings.TrimSuffix(cmd, " hook claude")
		bin = strings.Trim(bin, "'")
		if _, err := os.Stat(bin); err != nil && filepath.IsAbs(bin) {
			bad("Claude Code hook points to %s, which does not exist (rerun `agentguard setup`)", bin)
		} else {
			ok("Claude Code hook installed in %s", settings)
		}
	} else if setup.ClaudeDetected() {
		warn("Claude Code found but the AgentGuard hook is not installed (run `agentguard setup`)")
	}

	if problems > 0 {
		return 1, nil
	}
	return 0, nil
}

func checkPolicies(dir string) ([]string, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "policies", "*.yaml"))
	var roles []string
	for _, f := range files {
		p, err := policy.LoadFile(f)
		if err != nil {
			return nil, err
		}
		roles = append(roles, p.Role)
	}
	return roles, nil
}

// cmdTrust approves (or revokes) the current project's .agentguard/.
func cmdTrust(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("trust", flag.ContinueOnError)
	revoke := fs.Bool("revoke", false, "remove this project from the trust list")
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
	root, found, err := config.ProjectRoot(cwd)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("no %s/ here or in any parent directory", config.DirName)
	}
	if *revoke {
		if err := config.Untrust(root); err != nil {
			return err
		}
		fmt.Fprintf(out, "✓ %s is no longer trusted\n", root)
		return nil
	}
	dir := filepath.Join(root, config.DirName)
	files, _ := filepath.Glob(filepath.Join(dir, "policies", "*.yaml"))
	fmt.Fprintf(out, "Policies in %s:\n", dir)
	for _, f := range files {
		p, err := policy.LoadFile(f)
		if err != nil {
			return fmt.Errorf("not trusting invalid policies: %w", err)
		}
		fmt.Fprintf(out, "  %-12s read %v  write %v  commands %v  network %v\n", p.Role,
			p.Filesystem.Read, p.Filesystem.Write, p.Commands.Allow, p.Network.Enabled)
	}
	if err := config.Trust(root); err != nil {
		return err
	}
	fmt.Fprintf(out, "✓ Trusted. Changing these files later requires `agentguard trust` again.\n")
	return nil
}

// cmdHook answers Claude Code's PreToolUse hook. Exit 0 allows the tool
// call; exit 2 blocks it and shows stderr to Claude.
func cmdHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("hook", flag.ContinueOnError)
	role := fs.String("role", os.Getenv("AGENTGUARD_ROLE"), "role to enforce (default: config default_role)")
	pos, _, err := parse(fs, args)
	if err != nil || len(pos) != 1 || pos[0] != "claude" {
		fmt.Fprintln(stderr, "usage: agentguard hook claude [--role R]  (reads a PreToolUse event on stdin)")
		return 2
	}
	in, err := hook.ParseClaude(stdin)
	if err != nil {
		fmt.Fprintf(stderr, "AgentGuard: %v\n", err)
		return 2
	}
	dir := in.Cwd
	if dir == "" {
		dir, _ = os.Getwd()
	}
	_, e, logger, err := loadAt(dir, *role, "hook")
	if errors.Is(err, config.ErrNotInitialized) {
		return 0 // AgentGuard is not set up for this directory
	}
	if err != nil {
		// Fail closed: a broken or untrusted configuration blocks the call.
		fmt.Fprintf(stderr, "AgentGuard: %v\n", err)
		return 2
	}
	v := hook.DecideClaude(e, in)
	if err := logger.Err(); err != nil {
		fmt.Fprintf(stderr, "AgentGuard: cannot write audit log, blocking: %v\n", err)
		return 2
	}
	if !v.Allowed {
		fmt.Fprintf(stderr, "AgentGuard blocked this %s call: %s. Do not try to work around this; if the user needs it, they can change the policy.\n", in.ToolName, v.Reason)
		return 2
	}
	return 0
}
