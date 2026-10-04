package policy

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SensitivePatterns are denied for every role, case-insensitively, unless a
// policy lists the path under filesystem.allow_sensitive. They exist so a
// policy that forgets ".env" still does not leak it.
var SensitivePatterns = []string{
	".env*",
	"*.pem",
	"*.key",
	"*.p12",
	"*.pfx",
	"id_rsa*",
	"id_dsa*",
	"id_ecdsa*",
	"id_ed25519*",
	".ssh",
	".gnupg",
	".aws",
	".azure",
	".kube",
	".docker",
	".npmrc",
	".pypirc",
	".netrc",
	".git-credentials",
	".git/config", // remote URLs often embed access tokens
}

// ProtectedDir holds AgentGuard's own config, policies and audit log. It can
// never be read or written by an agent, whatever the policy says.
const ProtectedDir = ".agentguard"

// Decision is the result of evaluating one request.
type Decision struct {
	Role     string
	Action   Action
	Resource string // as requested
	Path     string // normalized workspace-relative path, for filesystem actions
	Allowed  bool
	Reason   string
	Rule     string // the rule that decided, if any
}

func (d Decision) String() string {
	verdict := "DENY"
	if d.Allowed {
		verdict = "ALLOW"
	}
	s := fmt.Sprintf("%s %s %s", verdict, d.Action, d.Resource)
	if d.Reason != "" {
		s += " (" + d.Reason + ")"
	}
	return s
}

type rule struct {
	pattern
	label string
}

// Engine evaluates requests for a single policy within a single workspace.
type Engine struct {
	policy                *Policy
	root                  string
	read, write           []rule
	deny, sensitive, safe []rule
	commands              map[string]bool
	observer              func(Decision)
	now                   func() time.Time
}

// NewEngine compiles a policy for the workspace rooted at root.
func NewEngine(p *Policy, root string) (*Engine, error) {
	if p == nil {
		return nil, errors.New("no policy")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	real, err := resolve(abs)
	if err != nil {
		return nil, fmt.Errorf("resolve workspace: %w", err)
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("workspace %s is not a directory", root)
	}
	if real == "/" {
		return nil, errors.New("refusing to use / as the workspace")
	}
	home, _ := os.UserHomeDir()
	e := &Engine{
		policy:   p,
		root:     real,
		commands: map[string]bool{},
		now:      time.Now,
	}
	compile := func(list []string, label string) []rule {
		var out []rule
		for _, raw := range list {
			pt, err := compilePattern(raw, home)
			if err != nil {
				continue // already validated; unreachable
			}
			out = append(out, rule{pattern: pt, label: fmt.Sprintf("%s: %s", label, raw)})
		}
		return out
	}
	e.read = compile(p.Filesystem.Read, "filesystem.read")
	e.write = compile(p.Filesystem.Write, "filesystem.write")
	e.deny = compile(p.Deny, "deny")
	e.sensitive = compile(SensitivePatterns, "built-in sensitive")
	e.safe = compile(p.Filesystem.AllowSensitive, "filesystem.allow_sensitive")
	for _, c := range p.Commands.Allow {
		e.commands[c] = true
	}
	if e.commands["git"] {
		// git cannot work without its metadata. Grant read-only access; write
		// access to .git is always refused (hooks and config run on the host).
		e.read = append(e.read, compile([]string{".git/**"}, "implicit (git is allowed)")...)
	}
	return e, nil
}

// SetObserver registers fn to be called with every decision, for auditing.
func (e *Engine) SetObserver(fn func(Decision)) { e.observer = fn }

// Policy returns the policy being enforced.
func (e *Engine) Policy() *Policy { return e.policy }

// Root returns the absolute, symlink-resolved workspace root.
func (e *Engine) Root() string { return e.root }

// Evaluate decides whether the role may perform action on resource and
// reports the decision to the observer.
func (e *Engine) Evaluate(action Action, resource string) Decision {
	d := e.Check(action, resource)
	if e.observer != nil {
		e.observer(d)
	}
	return d
}

// Check is Evaluate without notifying the observer.
func (e *Engine) Check(action Action, resource string) Decision {
	var d Decision
	switch action {
	case ActionRead, ActionWrite:
		d = e.evalPath(action, resource)
	case ActionExecute:
		d = e.evalExecute(resource)
	case ActionNetwork:
		d = e.evalNetwork(resource)
	default:
		d = Decision{Action: action, Resource: resource, Reason: "unknown action"}
	}
	if exp := e.policy.Metadata.ExpiresAt; exp != nil && !e.now().Before(*exp) {
		d.Allowed = false
		d.Reason = "policy expired at " + exp.Format(time.RFC3339)
		d.Rule = "metadata.expires_at"
	}
	d.Role = e.policy.Role
	d.Action = action
	d.Resource = resource
	return d
}

func (e *Engine) evalPath(action Action, resource string) Decision {
	d := Decision{}
	if resource == "" || strings.ContainsRune(resource, 0) {
		d.Reason = "invalid path"
		return d
	}
	p := resource
	if p == "~" || strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			d.Reason = "cannot expand ~"
			return d
		}
		p = home + strings.TrimPrefix(p, "~")
	} else if strings.HasPrefix(p, "~") {
		d.Reason = "~user paths are not supported"
		return d
	}
	if !filepath.IsAbs(p) {
		p = e.root + string(filepath.Separator) + p
	}

	// Lexical view: what the request looks like after cleaning "..".
	lexRel, lexInside := e.relInside(filepath.Clean(p))
	// Kernel view: what the path really refers to once symlinks are followed.
	real, err := resolve(p)
	if err != nil {
		d.Reason = "cannot resolve path: " + err.Error()
		return d
	}
	realRel, realInside := e.relInside(real)
	if !realInside {
		d.Rule = "workspace boundary"
		if lexInside {
			d.Reason = "symlink resolves outside the workspace"
		} else {
			d.Reason = "path is outside the workspace"
		}
		return d
	}
	if !e.matchHostDeny(real, &d) {
		return d
	}
	d.Path = realRel
	views := []string{realRel}
	if lexInside && lexRel != realRel {
		views = append(views, lexRel)
	}
	for _, rel := range views {
		v := e.checkRel(action, rel)
		if !v.Allowed {
			if rel == realRel && len(views) > 1 {
				v.Reason = fmt.Sprintf("resolves to %s: %s", realRel, v.Reason)
			}
			v.Path = realRel
			return v
		}
		d = v
	}
	d.Path = realRel
	return d
}

// matchHostDeny applies absolute deny patterns (e.g. "~/.ssh/**") to the
// resolved host path. It returns false if the path is denied.
func (e *Engine) matchHostDeny(real string, d *Decision) bool {
	segs := splitPath(filepath.ToSlash(real))
	for _, r := range e.deny {
		if r.absolute && r.match(segs, true) {
			d.Reason = "matches deny rule"
			d.Rule = r.label
			return false
		}
	}
	return true
}

// checkRel applies the rule order to a workspace-relative path:
// protected dirs, deny rules, built-in sensitive files, then allow rules.
func (e *Engine) checkRel(action Action, rel string) Decision {
	d := Decision{Path: rel}
	segs := splitPath(filepath.ToSlash(rel))
	if hasComponent(segs, ProtectedDir) {
		d.Reason, d.Rule = "AgentGuard configuration is never accessible to agents", "protected: .agentguard/**"
		return d
	}
	if action == ActionWrite && hasComponent(segs, ".git") {
		d.Reason, d.Rule = "git metadata is never writable (hooks and config execute on the host)", "protected: .git/** (write)"
		return d
	}
	if action == ActionWrite && hasComponent(segs, ".claude") {
		d.Reason, d.Rule = "agent configuration is never writable (it could disable AgentGuard's hook)", "protected: .claude/** (write)"
		return d
	}
	if r, ok := firstMatch(e.deny, segs, true); ok {
		d.Reason, d.Rule = "matches deny rule", r.label
		return d
	}
	if r, ok := firstMatch(e.sensitive, segs, true); ok {
		if _, safe := firstMatch(e.safe, segs, true); !safe {
			d.Reason, d.Rule = "built-in sensitive file", r.label
			return d
		}
	}
	allow := e.write
	if action == ActionRead {
		allow = append(append([]rule{}, e.read...), e.write...)
	}
	if r, ok := firstMatch(allow, segs, false); ok {
		d.Allowed, d.Reason, d.Rule = true, "", r.label
		return d
	}
	d.Reason = fmt.Sprintf("no filesystem.%s rule matches (default deny)", action)
	return d
}

// IsHidden reports whether a workspace-relative path must be hidden from the
// sandbox, i.e. it is denied for reading by a protection or deny rule
// regardless of allow rules. It does not notify the observer.
func (e *Engine) IsHidden(rel string) (bool, string) {
	segs := splitPath(filepath.ToSlash(rel))
	if hasComponent(segs, ProtectedDir) {
		return true, "protected: .agentguard/**"
	}
	if r, ok := firstMatch(e.deny, segs, true); ok {
		return true, r.label
	}
	if r, ok := firstMatch(e.sensitive, segs, true); ok {
		if _, safe := firstMatch(e.safe, segs, true); !safe {
			return true, r.label
		}
	}
	if !e.matchHostDeny(filepath.Join(e.root, rel), &Decision{}) {
		return true, "deny (absolute)"
	}
	return false, ""
}

// hasComponent reports whether any path segment equals name, ignoring case.
// Protected names apply at every depth so an agent cannot plant, say, a
// nested .agentguard/ that a later run would pick up.
func hasComponent(segs []string, name string) bool {
	for _, s := range segs {
		if strings.EqualFold(s, name) {
			return true
		}
	}
	return false
}

func firstMatch(rules []rule, segs []string, fold bool) (rule, bool) {
	for _, r := range rules {
		if !r.absolute && r.match(segs, fold) {
			return r, true
		}
	}
	return rule{}, false
}

func (e *Engine) evalExecute(name string) Decision {
	d := Decision{}
	switch {
	case strings.ContainsAny(name, `/\`):
		d.Reason = "commands must be bare names; paths are never allowed"
	case !commandRe.MatchString(name):
		d.Reason = "invalid command name (shell syntax is not interpreted)"
	case e.commands[name]:
		d.Allowed, d.Rule = true, "commands.allow: "+name
	default:
		d.Reason = "command is not in commands.allow (default deny)"
	}
	return d
}

func (e *Engine) evalNetwork(_ string) Decision {
	if e.policy.Network.Enabled {
		return Decision{Allowed: true, Rule: "network.enabled: true"}
	}
	return Decision{Reason: "network access is disabled for this role", Rule: "network.enabled: false"}
}

// ReadPatterns returns the patterns that grant read access, including write
// patterns and implicit grants. Used by the sandbox to plan mounts.
func (e *Engine) ReadPatterns() []string {
	return labels(append(append([]rule{}, e.read...), e.write...))
}

// WritePatterns returns the patterns that grant write access.
func (e *Engine) WritePatterns() []string { return labels(e.write) }

func labels(rules []rule) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.raw)
	}
	return out
}

// MountPrefix returns the workspace-relative directory or file that must be
// mounted to satisfy a pattern, and whether the mount is exactly as wide as
// the pattern. Name patterns and patterns starting with a glob need the
// whole workspace.
func MountPrefix(raw string) (prefix string, exact bool, err error) {
	pt, err := compilePattern(raw, "")
	if err != nil {
		return "", false, err
	}
	if !pt.anchored {
		return ".", false, nil
	}
	lit := pt.literalPrefix()
	if len(lit) == 0 {
		return ".", false, nil
	}
	exact = pt.isLiteral() || (len(lit) == len(pt.segs)-1 && pt.segs[len(pt.segs)-1] == "**")
	return filepath.Join(lit...), exact, nil
}

func (e *Engine) relInside(abs string) (string, bool) {
	rel, err := filepath.Rel(e.root, abs)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", false
	}
	return rel, true
}

// resolve returns the absolute path that p refers to, following symlinks in
// the same order the kernel does (so "link/.." means the parent of the link's
// target, not the directory holding the link). Components after the first
// one that does not exist are joined lexically, which lets callers evaluate
// writes to files that do not exist yet.
func resolve(p string) (string, error) {
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("resolve: %q is not absolute", p)
	}
	queue := strings.Split(p, "/")
	cur := "/"
	links := 0
	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		fi, err := os.Lstat(next)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return filepath.Join(append([]string{next}, queue...)...), nil
			}
			return "", err
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			cur = next
			continue
		}
		links++
		if links > 40 {
			return "", errors.New("too many levels of symbolic links")
		}
		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}
		if filepath.IsAbs(target) {
			cur = "/"
		}
		queue = append(strings.Split(target, "/"), queue...)
	}
	return cur, nil
}
