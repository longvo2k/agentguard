// Package sandbox turns a policy into a disposable Docker container.
//
// The container only sees what the policy allows: each allowed directory is
// bind-mounted (read-only unless writable), files that a deny or protection
// rule covers are hidden behind unreadable placeholders, the network is
// disabled unless enabled, and the process runs as a non-root user with no
// capabilities, a read-only root filesystem and no host environment.
package sandbox

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/longvo2k/agentguard/internal/policy"
)

const (
	// WorkspaceDir is where the workspace appears inside the container.
	WorkspaceDir = "/workspace"
	// HomeDir is the agent's (tmpfs) home directory.
	HomeDir = "/home/agent"
	// ShimDir holds the only commands placed on PATH.
	ShimDir = "/opt/agentguard/bin"
	// fallbackUID is used when AgentGuard itself runs as root, so the
	// container never does.
	fallbackUID = 1000
)

// Options configure a sandbox.
type Options struct {
	Image     string
	Memory    string
	CPUs      string
	PidsLimit int
	// CommandPaths maps allowed command names to their absolute path inside
	// the image (see ResolveCommands). Only these are placed on PATH.
	CommandPaths map[string]string
	// User overrides the container uid:gid. Default: the invoking user, or
	// 1000:1000 if that is root.
	User string
	// Record receives every mount and hide decision for the audit log.
	Record func(policy.Decision)
}

// Mount is one bind mount in the container.
type Mount struct {
	Source   string // host path
	Target   string // container path
	ReadOnly bool
	Kind     string // "workspace", "hide", "system"
	Note     string
}

// Plan is everything needed to start the container. Build it with NewPlan
// and release it with Cleanup.
type Plan struct {
	Engine   *policy.Engine
	Options  Options
	Network  bool
	UID, GID int
	Mounts   []Mount
	Warnings []string
	tempDir  string
}

// NewPlan computes the mounts for the engine's policy and workspace.
func NewPlan(e *policy.Engine, opts Options) (*Plan, error) {
	if opts.Image == "" {
		return nil, errors.New("sandbox image is not set")
	}
	if opts.Record == nil {
		opts.Record = func(policy.Decision) {}
	}
	p := &Plan{Engine: e, Options: opts}
	uid, gid, err := containerUser(opts.User)
	if err != nil {
		return nil, err
	}
	p.UID, p.GID = uid, gid
	if os.Getuid() == 0 && opts.User == "" {
		p.warn("agentguard is running as root; the sandbox runs as uid %d instead, so writable directories must be writable by that uid", fallbackUID)
	}

	p.Network = e.Evaluate(policy.ActionNetwork, "*").Allowed

	tmp, err := os.MkdirTemp("", "agentguard-")
	if err != nil {
		return nil, err
	}
	p.tempDir = tmp
	if err := p.planWorkspace(); err != nil {
		p.Cleanup()
		return nil, err
	}
	if err := p.planSystem(); err != nil {
		p.Cleanup()
		return nil, err
	}
	for _, m := range p.Mounts {
		for _, s := range []string{m.Source, m.Target} {
			if strings.ContainsAny(s, ",\"\n\r") {
				p.Cleanup()
				return nil, fmt.Errorf("refusing to mount %q: path contains characters that Docker's --mount syntax cannot express safely", s)
			}
		}
	}
	return p, nil
}

// Cleanup removes the temporary placeholder files.
func (p *Plan) Cleanup() {
	if p.tempDir == "" {
		return
	}
	_ = filepath.WalkDir(p.tempDir, func(path string, d fs.DirEntry, err error) error {
		_ = os.Chmod(path, 0o700)
		return nil
	})
	_ = os.Chmod(p.tempDir, 0o700)
	_ = os.Chmod(filepath.Join(p.tempDir, "hidden-dir"), 0o700)
	_ = os.RemoveAll(p.tempDir)
	p.tempDir = ""
}

func (p *Plan) warn(format string, args ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, args...))
}

func (p *Plan) record(action policy.Action, resource string, allowed bool, rule, reason string) {
	p.Options.Record(policy.Decision{
		Role:     p.Engine.Policy().Role,
		Action:   action,
		Resource: resource,
		Allowed:  allowed,
		Rule:     rule,
		Reason:   reason,
	})
}

type candidate struct {
	rel     string
	pattern string
	write   bool
}

// planWorkspace decides which workspace paths to mount and which to hide.
func (p *Plan) planWorkspace() error {
	e := p.Engine
	root := e.Root()

	var cands []candidate
	add := func(patterns []string, write bool) error {
		for _, pat := range patterns {
			prefix, exact, err := policy.MountPrefix(pat)
			if err != nil {
				return err
			}
			if !exact {
				where := prefix + "/"
				if prefix == "." {
					where = "the whole workspace"
				}
				p.warn("pattern %q is narrower than a directory mount; %s is mounted%s and `agentguard check` remains the precise authority", pat, where, map[bool]string{true: " writable", false: ""}[write])
			}
			cands = append(cands, candidate{rel: prefix, pattern: pat, write: write})
		}
		return nil
	}
	if err := add(e.ReadPatterns(), false); err != nil {
		return err
	}
	if err := add(e.WritePatterns(), true); err != nil {
		return err
	}

	// Keep only candidates that exist, are real (no symlinks in the prefix)
	// and are not themselves hidden.
	var valid []candidate
	for _, c := range cands {
		if hidden, rule := e.IsHidden(c.rel); hidden && c.rel != "." {
			p.record(actionFor(c.write), c.rel, false, rule, "mount skipped: path is denied")
			continue
		}
		abs := filepath.Join(root, c.rel)
		fi, err := os.Lstat(abs)
		if errors.Is(err, fs.ErrNotExist) {
			if c.rel == ".git" {
				continue // implicit grant for git; not every workspace is a repo
			}
			p.warn("%s does not exist, so it is not mounted (pattern %q)", c.rel, c.pattern)
			continue
		}
		if err != nil {
			return err
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return err
		}
		if real != abs {
			p.warn("%s is or contains a symlink; it is not mounted (pattern %q)", c.rel, c.pattern)
			p.record(actionFor(c.write), c.rel, false, "workspace boundary", "mount skipped: symlinked mount source")
			continue
		}
		if !fi.IsDir() && !fi.Mode().IsRegular() {
			p.warn("%s is not a regular file or directory; it is not mounted", c.rel)
			continue
		}
		valid = append(valid, c)
	}

	// Collapse: writable mounts that sit inside another writable mount, and
	// read-only mounts inside any mount, need no mount of their own. A
	// writable path inside a read-only one gets its own nested mount.
	var mounts []candidate
	seen := map[string]bool{}
	for _, c := range valid {
		key := fmt.Sprint(c.rel, c.write)
		if seen[key] {
			continue
		}
		seen[key] = true
		covered := false
		for _, o := range valid {
			if o.write && within(c.rel, o.rel) && (!c.write || o.rel != c.rel) {
				covered = true // inside a writable mount (or equal, for read-only)
			}
			if !c.write && !o.write && o.rel != c.rel && within(c.rel, o.rel) {
				covered = true // inside a broader read-only mount
			}
		}
		if !covered {
			mounts = append(mounts, c)
		}
	}
	sort.SliceStable(mounts, func(i, j int) bool { return depth(mounts[i].rel) < depth(mounts[j].rel) })

	hides := map[string]bool{}
	for _, c := range mounts {
		p.Mounts = append(p.Mounts, Mount{
			Source:   filepath.Join(root, c.rel),
			Target:   containerPath(c.rel),
			ReadOnly: !c.write,
			Kind:     "workspace",
			Note:     "pattern " + c.pattern,
		})
		p.record(actionFor(c.write), mountLabel(c.rel), true, patternRule(c), "mounted "+map[bool]string{true: "read-write", false: "read-only"}[c.write])
		if err := p.planHides(c.rel, c.write, hides); err != nil {
			return err
		}
	}
	if len(mounts) == 0 {
		p.warn("no workspace paths are mounted; the agent will see an empty /workspace")
	}
	return nil
}

// planHides walks a mounted path and hides every entry the policy denies.
func (p *Plan) planHides(rel string, writable bool, done map[string]bool) error {
	e := p.Engine
	root := e.Root()
	start := filepath.Join(root, rel)
	return filepath.WalkDir(start, func(abs string, d fs.DirEntry, err error) error {
		if err != nil {
			if abs == start {
				return err
			}
			p.warn("cannot inspect %s: %v; hiding it", abs, err)
			if d != nil && d.IsDir() {
				return p.hide(abs, true, "unreadable during planning", done)
			}
			return p.hide(abs, false, "unreadable during planning", done)
		}
		r, _ := filepath.Rel(root, abs)
		if r == "." {
			// The workspace root itself; its children are checked below.
			return nil
		}
		hidden, rule := e.IsHidden(r)
		mode := d.Type()
		switch {
		case mode&fs.ModeSymlink != 0:
			// Symlinks are resolved inside the container's mount namespace,
			// where only mounted (allowed) paths and placeholders exist, so a
			// link cannot reach a hidden or host file. Mounting over one would
			// follow it, so links are left alone.
			return nil
		case writable && strings.EqualFold(d.Name(), ".git") && (d.IsDir() || mode.IsRegular()) && !hidden:
			// git metadata inside a writable mount is re-mounted read-only:
			// hooks and config written by an agent would run on the host.
			target := containerPath(r)
			if !done[target] {
				done[target] = true
				p.Mounts = append(p.Mounts, Mount{Source: abs, Target: target, ReadOnly: true, Kind: "protect", Note: "protected: .git/** (write)"})
				p.record(policy.ActionWrite, r, false, "protected: .git/** (write)", "mounted read-only in sandbox")
			}
			return nil
		case hidden:
			if err := p.hide(abs, d.IsDir(), rule, done); err != nil {
				return err
			}
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		case mode&(fs.ModeSocket|fs.ModeNamedPipe|fs.ModeDevice|fs.ModeCharDevice) != 0:
			// A host socket bind-mounted into the container still talks to the
			// host service behind it (think docker.sock).
			return p.hide(abs, false, "special file (socket, pipe or device)", done)
		}
		return nil
	})
}

func (p *Plan) hide(abs string, dir bool, rule string, done map[string]bool) error {
	rel, _ := filepath.Rel(p.Engine.Root(), abs)
	target := containerPath(rel)
	if done[target] {
		return nil
	}
	done[target] = true
	if filepath.ToSlash(rel) == ".git/config" && !dir {
		// git refuses to run without a readable config, so substitute a copy
		// that keeps only repository-format settings and drops remotes,
		// credentials and headers (where tokens live).
		src, err := p.sanitizedGitConfig(abs)
		if err != nil {
			return err
		}
		p.Mounts = append(p.Mounts, Mount{Source: src, Target: target, ReadOnly: true, Kind: "hide", Note: rule + " (sanitized copy)"})
		p.record(policy.ActionRead, rel, false, rule, "replaced with sanitized copy in sandbox")
		return nil
	}
	src, err := p.placeholder(dir)
	if err != nil {
		return err
	}
	p.Mounts = append(p.Mounts, Mount{Source: src, Target: target, ReadOnly: true, Kind: "hide", Note: rule})
	p.record(policy.ActionRead, rel, false, rule, "hidden in sandbox")
	return nil
}

// placeholder returns an empty file or directory with mode 0000. Without
// CAP_DAC_OVERRIDE (all capabilities are dropped) even its owner gets
// "Permission denied", and the read-only mount stops chmod.
func (p *Plan) placeholder(dir bool) (string, error) {
	name := "hidden-file"
	if dir {
		name = "hidden-dir"
	}
	path := filepath.Join(p.tempDir, name)
	if _, err := os.Lstat(path); err == nil {
		return path, nil
	}
	if dir {
		if err := os.Mkdir(path, 0o700); err != nil {
			return "", err
		}
	} else if err := os.WriteFile(path, nil, 0o600); err != nil {
		return "", err
	}
	return path, os.Chmod(path, 0)
}

// gitCoreKeys are the [core] settings copied into the sanitized git config.
// Anything that names a program (fsmonitor, sshCommand, pager, editor,
// hooksPath) is dropped.
var gitCoreKeys = map[string]bool{
	"repositoryformatversion": true, "filemode": true, "bare": true,
	"logallrefupdates": true, "ignorecase": true, "precomposeunicode": true,
	"symlinks": true, "autocrlf": true, "eol": true,
}

func (p *Plan) sanitizedGitConfig(src string) (string, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return "", err
	}
	var out strings.Builder
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = strings.ToLower(strings.Trim(t, "[] \t"))
			if section == "core" || section == "extensions" {
				out.WriteString("[" + section + "]\n")
			}
			continue
		}
		key, _, _ := strings.Cut(t, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if (section == "core" && gitCoreKeys[key]) || section == "extensions" {
			if key != "" && !strings.HasPrefix(key, "#") && !strings.HasPrefix(key, ";") {
				out.WriteString("\t" + t + "\n")
			}
		}
	}
	dst := filepath.Join(p.tempDir, "git-config")
	if err := os.WriteFile(dst, []byte(out.String()), 0o644); err != nil {
		return "", err
	}
	return dst, nil
}

// planSystem adds the PATH shims and identity files.
func (p *Plan) planSystem() error {
	bin := filepath.Join(p.tempDir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		return err
	}
	for _, c := range p.Engine.Policy().Commands.Allow {
		target, ok := p.Options.CommandPaths[c]
		if !ok || !path.IsAbs(target) {
			p.warn("command %q is allowed but was not found in image %s", c, p.Options.Image)
			continue
		}
		if err := os.Symlink(target, filepath.Join(bin, c)); err != nil {
			return err
		}
	}
	p.Mounts = append(p.Mounts, Mount{Source: bin, Target: ShimDir, ReadOnly: true, Kind: "system", Note: "allowed commands only"})

	// Give the uid a name so tools that look it up (node's os.userInfo, git)
	// work on the read-only root filesystem.
	passwd := fmt.Sprintf("root:x:0:0:root:/root:/sbin/nologin\nagent:x:%d:%d:agent:%s:/sbin/nologin\n", p.UID, p.GID, HomeDir)
	group := fmt.Sprintf("root:x:0:\nagent:x:%d:\n", p.GID)
	if p.UID == 0 || p.GID == 0 {
		return errors.New("the sandbox must not run as root")
	}
	for name, body := range map[string]string{"passwd": passwd, "group": group} {
		f := filepath.Join(p.tempDir, name)
		if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
			return err
		}
		p.Mounts = append(p.Mounts, Mount{Source: f, Target: "/etc/" + name, ReadOnly: true, Kind: "system"})
	}
	sort.SliceStable(p.Mounts, func(i, j int) bool {
		return strings.Count(p.Mounts[i].Target, "/") < strings.Count(p.Mounts[j].Target, "/")
	})
	return nil
}

func containerUser(override string) (int, int, error) {
	if override != "" {
		u, g, ok := strings.Cut(override, ":")
		uid, err1 := strconv.Atoi(u)
		gid, err2 := strconv.Atoi(g)
		if !ok || err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("invalid sandbox user %q (want uid:gid)", override)
		}
		if uid == 0 || gid == 0 {
			return 0, 0, errors.New("the sandbox must not run as root")
		}
		return uid, gid, nil
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid <= 0 {
		uid, gid = fallbackUID, fallbackUID
	}
	if gid <= 0 {
		gid = uid
	}
	return uid, gid, nil
}

func actionFor(write bool) policy.Action {
	if write {
		return policy.ActionWrite
	}
	return policy.ActionRead
}

func patternRule(c candidate) string {
	if c.write {
		return "filesystem.write: " + c.pattern
	}
	return "filesystem.read: " + c.pattern
}

func mountLabel(rel string) string {
	if rel == "." {
		return "./"
	}
	return filepath.ToSlash(rel) + "/"
}

func containerPath(rel string) string {
	return path.Join(WorkspaceDir, filepath.ToSlash(rel))
}

// within reports whether rel is equal to or below base.
func within(rel, base string) bool {
	if base == "." || rel == base {
		return true
	}
	return strings.HasPrefix(rel, base+string(filepath.Separator))
}

func depth(rel string) int {
	if rel == "." {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator)) + 1
}
