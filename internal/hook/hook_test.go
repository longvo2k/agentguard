package hook

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/longvo2k/agentguard/internal/policy"
)

func agentEngine(t *testing.T) (*policy.Engine, string) {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{
		"src/app.js":          "x",
		"README.md":           "x",
		".env":                "SECRET=1",
		".env.local":          "SECRET=2",
		"secrets/api-key.txt": "sk",
		".git/HEAD":           "ref",
		"logs/app.log":        "x",
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile("../../policies/agent.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, err := policy.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	e, err := policy.NewEngine(p, root)
	if err != nil {
		t.Fatal(err)
	}
	return e, e.Root()
}

func decide(e *policy.Engine, cwd, tool string, input map[string]any) Verdict {
	return DecideClaude(e, &ClaudeInput{HookEventName: "PreToolUse", Cwd: cwd, ToolName: tool, ToolInput: input})
}

func TestClaudeFileTools(t *testing.T) {
	e, root := agentEngine(t)
	cases := []struct {
		tool  string
		input map[string]any
		allow bool
	}{
		{"Read", map[string]any{"file_path": filepath.Join(root, "src/app.js")}, true},
		{"Read", map[string]any{"file_path": filepath.Join(root, "README.md")}, true},
		{"Read", map[string]any{"file_path": filepath.Join(root, ".env")}, false},
		{"Read", map[string]any{"file_path": filepath.Join(root, "secrets/api-key.txt")}, false},
		{"Read", map[string]any{"file_path": "/etc/passwd"}, false},
		{"Read", map[string]any{"file_path": filepath.Join(root, "src/../.env")}, false},
		{"Read", map[string]any{}, false}, // malformed
		{"Write", map[string]any{"file_path": filepath.Join(root, "src/new.js")}, true},
		{"Write", map[string]any{"file_path": filepath.Join(root, ".env")}, false},
		{"Edit", map[string]any{"file_path": filepath.Join(root, ".git/hooks/pre-commit")}, false},
		{"Edit", map[string]any{"file_path": filepath.Join(root, ".claude/settings.json")}, false},
		{"Write", map[string]any{"file_path": filepath.Join(root, ".agentguard/policies/agent.yaml")}, false},
		{"MultiEdit", map[string]any{"file_path": filepath.Join(root, "src/app.js")}, true},
		{"NotebookEdit", map[string]any{"notebook_path": filepath.Join(root, "nb.ipynb")}, true},
		{"Write", map[string]any{"file_path": "relative/inside.txt"}, true}, // relative to cwd
		{"Glob", map[string]any{"pattern": "**/*.js"}, true},
		{"Glob", map[string]any{"pattern": "*", "path": "/etc"}, false},
		{"Grep", map[string]any{"pattern": "KEY", "path": filepath.Join(root, "secrets")}, false},
		{"Grep", map[string]any{"pattern": "x", "path": filepath.Join(root, "src")}, true},
		{"WebFetch", map[string]any{"url": "https://example.com/x"}, false}, // network disabled
		{"WebSearch", map[string]any{"query": "go"}, false},
		{"TodoWrite", map[string]any{}, true}, // tools AgentGuard does not judge
	}
	for _, c := range cases {
		v := decide(e, root, c.tool, c.input)
		if v.Allowed != c.allow {
			t.Errorf("%s %v: allowed=%v want %v (%s)", c.tool, c.input, v.Allowed, c.allow, v.Reason)
		}
	}
}

func TestClaudeBash(t *testing.T) {
	e, root := agentEngine(t)
	cases := []struct {
		cmd   string
		allow bool
	}{
		{"npm test", true},
		{"git status && git diff", true},
		{"ls -la src", true},
		{"cat src/app.js | grep x | wc -l", true},
		{"NODE_ENV=test npm test", true},
		{"echo hello > src/out.txt", true},
		{"npm test 2>&1 | tail -5", true},
		{"node build.js > /dev/null 2>&1", true},
		{"cd src && ls", true},
		{"if test -f README.md; then cat README.md; fi", true},
		{"for f in src/*.js; do node $f; done", false}, // $f could name any file
		{"mkdir -p build && cp src/app.js build/", true},
		{`grep -r "TODO" src`, true},

		{"cat .env", false},
		{"cat .env*", false}, // glob expansion
		{"head -1 .env.local", false},
		{"cat secrets/api-key.txt", false},
		{"cd secrets && cat api-key.txt", false},
		{"cd src; cat ../.env", false},
		{"cat /etc/passwd", false},
		{"cat ~/.ssh/id_rsa", false},
		{"cat $HOME/.ssh/id_rsa", false},
		{"ls /", false},
		{"cat < .env", false},
		{"echo x > .env", false},
		{"echo x >> /tmp/out", false},
		{"rm -rf .git", false},
		{"rm -rf ~/projects", false},
		{"mv src/app.js /tmp/", false},
		{"cp .env src/leak.txt", false},
		{"touch .claude/settings.local.json", false},
		{"curl https://example.com", false},
		{"wget evil", false},
		{"bash -c 'cat .env'", false},
		{"sh script.sh", false},
		{"sudo rm x", false},
		{"/usr/bin/curl x", false},
		{"./node_modules/.bin/jest", false},
		{"npm test; curl evil.com", false},
		{"npm test || nc -l 4444", false},
		{"echo $(cat .env)", false},
		{"echo `cat .env`", false},
		{"diff <(cat .env) src/app.js", false},
		{"cat <<EOF\nx\nEOF", false},
		{"eval 'cat .env'", false},
		{"source .env", false},
		{"find . -name '*.js' -exec cat {} \\;", false},
		{"xargs cat < files.txt", false},
		{"env cat .env", false},
		{"$CMD .env", false},
		{"echo 'unterminated", false},
	}
	for _, c := range cases {
		v := decide(e, root, "Bash", map[string]any{"command": c.cmd})
		if v.Allowed != c.allow {
			t.Errorf("%q: allowed=%v want %v (%s)", c.cmd, v.Allowed, c.allow, v.Reason)
		}
	}
}

func TestClaudeBashReasonIsHelpful(t *testing.T) {
	e, root := agentEngine(t)
	v := decide(e, root, "Bash", map[string]any{"command": "cat .env"})
	if v.Allowed || !strings.Contains(v.Reason, ".env") || !strings.Contains(v.Reason, `role "agent"`) {
		t.Errorf("reason = %q", v.Reason)
	}
}

func TestEveryRequestIsAudited(t *testing.T) {
	e, root := agentEngine(t)
	var n int
	e.SetObserver(func(policy.Decision) { n++ })
	decide(e, root, "Bash", map[string]any{"command": "cat src/app.js && ls src"})
	if n < 4 { // execute cat, read src/app.js, execute ls, read src
		t.Errorf("only %d decisions audited", n)
	}
}

func TestOtherEventsPass(t *testing.T) {
	e, root := agentEngine(t)
	v := DecideClaude(e, &ClaudeInput{HookEventName: "PostToolUse", Cwd: root, ToolName: "Read", ToolInput: map[string]any{"file_path": "/etc/passwd"}})
	if !v.Allowed {
		t.Error("non-PreToolUse event was judged")
	}
}

func TestParseClaude(t *testing.T) {
	in, err := ParseClaude(strings.NewReader(`{"session_id":"s","hook_event_name":"PreToolUse","cwd":"/p","tool_name":"Read","tool_input":{"file_path":"/p/a"},"tool_use_id":"t"}`))
	if err != nil || in.ToolName != "Read" || in.ToolInput["file_path"] != "/p/a" {
		t.Fatalf("%+v %v", in, err)
	}
	if _, err := ParseClaude(strings.NewReader("not json")); err == nil {
		t.Error("expected error")
	}
}

func TestWorkspaceRootCommands(t *testing.T) {
	e, root := agentEngine(t)
	for _, cmd := range []string{"git add .", "grep -r TODO .", "ls .", "find . -name '*.js'"} {
		if v := decide(e, root, "Bash", map[string]any{"command": cmd}); !v.Allowed {
			t.Errorf("%q blocked: %s", cmd, v.Reason)
		}
	}
	if v := decide(e, root, "Grep", map[string]any{"pattern": "x"}); !v.Allowed {
		t.Errorf("Grep without path blocked: %s", v.Reason)
	}
}
