package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
deny:
  - .env*
  - secrets/**
  - production/**
  - ~/.ssh/**
`

// newWorkspace creates a demo-like workspace and returns its root.
func newWorkspace(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"src/app.js":              "console.log('hi')\n",
		"src/lib/util.js":         "",
		"src/config/.env.local":   "TOKEN=x\n",
		"tests/app.test.js":       "",
		"logs/app.log":            "started\n",
		".env":                    "SECRET=1\n",
		"secrets/api-key.txt":     "sk-123\n",
		"production/deploy.yaml":  "",
		"README.md":               "",
		".git/HEAD":               "ref: refs/heads/main\n",
		".git/config":             "[remote]\n",
		".agentguard/config.yaml": "",
	}
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func newEngine(t *testing.T, yml string, root string) *Engine {
	t.Helper()
	p, err := Parse([]byte(yml))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	e, err := NewEngine(p, root)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	return e
}

type tc struct {
	action   Action
	resource string
	allow    bool
}

func run(t *testing.T, e *Engine, cases []tc) {
	t.Helper()
	for _, c := range cases {
		d := e.Evaluate(c.action, c.resource)
		if d.Allowed != c.allow {
			t.Errorf("%s %q: got allowed=%v want %v (reason=%q rule=%q)", c.action, c.resource, d.Allowed, c.allow, d.Reason, d.Rule)
		}
	}
}

func TestReadWriteRules(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, developerYAML, root)
	run(t, e, []tc{
		// allowed reads
		{ActionRead, "src/app.js", true},
		{ActionRead, "src/lib/util.js", true},
		{ActionRead, "tests/app.test.js", true},
		{ActionRead, "logs/app.log", true},
		{ActionRead, "src", true},
		{ActionRead, "src/new-file.js", true}, // does not exist yet
		// denied reads
		{ActionRead, "README.md", false}, // default deny
		{ActionRead, "production/deploy.yaml", false},
		{ActionRead, "unknown/file", false},
		// allowed writes
		{ActionWrite, "src/app.js", true},
		{ActionWrite, "tests/new.test.js", true},
		// denied writes
		{ActionWrite, "logs/app.log", false}, // read-only
		{ActionWrite, "README.md", false},
		{ActionWrite, "production/deploy.yaml", false},
	})
}

func TestEnvProtection(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, developerYAML, root)
	run(t, e, []tc{
		{ActionRead, ".env", false},
		{ActionWrite, ".env", false},
		{ActionRead, ".env.production", false},
		{ActionRead, "src/config/.env.local", false}, // nested inside an allowed dir
		{ActionWrite, "src/.env", false},
		{ActionRead, ".ENV", false}, // case-insensitive filesystems
		{ActionRead, "src/.Env.Local", false},
	})
}

func TestSecretsProtection(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, developerYAML, root)
	run(t, e, []tc{
		{ActionRead, "secrets/api-key.txt", false},
		{ActionRead, "secrets", false},
		{ActionRead, "secrets/nested/deep/key", false},
		{ActionWrite, "secrets/api-key.txt", false},
		{ActionRead, "SECRETS/api-key.txt", false},
	})
}

func TestBuiltinSensitiveFiles(t *testing.T) {
	root := newWorkspace(t)
	// A careless policy that allows everything and denies nothing.
	e := newEngine(t, "role: careless\nfilesystem:\n  read: ['**']\n  write: ['**']\n", root)
	run(t, e, []tc{
		{ActionRead, "src/app.js", true},
		{ActionRead, ".env", false},
		{ActionRead, "src/server.pem", false},
		{ActionRead, "deploy/id_rsa", false},
		{ActionRead, ".aws/credentials", false},
		{ActionRead, ".npmrc", false},
		{ActionRead, ".git/config", false},
		{ActionWrite, ".git/hooks/pre-commit", false},
		{ActionRead, ".agentguard/config.yaml", false},
		{ActionWrite, ".agentguard/policies/careless.yaml", false},
		{ActionRead, ".AgentGuard/config.yaml", false},
		{ActionWrite, "src/.agentguard/policies/careless.yaml", false},
	})

	// allow_sensitive is an explicit, narrow opt-out.
	e = newEngine(t, "role: dev\nfilesystem:\n  read: ['**']\n  allow_sensitive: [.env.example]\n", root)
	run(t, e, []tc{
		{ActionRead, ".env.example", true},
		{ActionRead, ".env", false},
	})

	// The policy's own deny list still wins over allow_sensitive.
	e = newEngine(t, "role: dev\nfilesystem:\n  read: ['**']\n  allow_sensitive: [.env.example]\ndeny: [.env*]\n", root)
	run(t, e, []tc{{ActionRead, ".env.example", false}})
}

func TestWildcards(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, `
role: wild
filesystem:
  read: ["src/**/*.js", "docs/*.md", "*.txt", "./package.json"]
  write: ["tests/**/*.test.js"]
`, root)
	run(t, e, []tc{
		{ActionRead, "src/app.js", true},
		{ActionRead, "src/lib/util.js", true},
		{ActionRead, "src/lib/util.ts", false},
		{ActionRead, "docs/a.md", true},
		{ActionRead, "docs/sub/a.md", false}, // * does not cross /
		{ActionRead, "notes.txt", true},
		{ActionRead, "deep/dir/notes.txt", true}, // name pattern matches at any depth
		{ActionRead, "package.json", true},
		{ActionRead, "sub/package.json", false}, // ./ anchors to the root
		{ActionWrite, "tests/a/b.test.js", true},
		{ActionWrite, "tests/a/b.js", false},
		{ActionWrite, "src/app.js", false},
	})
}

func TestPathTraversal(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, developerYAML, root)
	run(t, e, []tc{
		{ActionRead, "src/../.env", false},
		{ActionRead, "src/../secrets/api-key.txt", false},
		{ActionRead, "src/../../etc/passwd", false},
		{ActionRead, "../outside.txt", false},
		{ActionRead, "src/./app.js", true},
		{ActionRead, "src/lib/../app.js", true},
		{ActionRead, "src/../src/app.js", true},
		{ActionWrite, "tests/../../../tmp/x", false},
		{ActionRead, "src/app.js\x00.png", false},
		{ActionRead, "", false},
	})
}

func TestAbsolutePaths(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, developerYAML, root)
	run(t, e, []tc{
		{ActionRead, filepath.Join(root, "src/app.js"), true},
		{ActionRead, filepath.Join(root, ".env"), false},
		{ActionRead, "/etc/passwd", false},
		{ActionRead, "~/.ssh/id_rsa", false},
		{ActionRead, "~", false},
		{ActionRead, "~root/.bashrc", false},
		{ActionWrite, "/tmp/evil", false},
	})
}

func TestSymlinks(t *testing.T) {
	root := newWorkspace(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "host-secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"src/env-link":     "../.env",
		"src/key-link":     "../secrets/api-key.txt",
		"src/secrets-dir":  "../secrets",
		"src/escape":       filepath.Join(outside, "host-secret"),
		"src/escape-dir":   outside,
		"src/ok-link":      "app.js",
		"src/logs-link":    "../logs",
		"src/lib/up":       "../../secrets/nested",
		"tests/loop-a":     "loop-b",
		"tests/loop-b":     "loop-a",
		".env-link-to-src": "src/app.js",
	}
	if err := os.MkdirAll(filepath.Join(root, "secrets/nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	e := newEngine(t, developerYAML, root)
	run(t, e, []tc{
		{ActionRead, "src/env-link", false},
		{ActionRead, "src/key-link", false},
		{ActionRead, "src/secrets-dir/api-key.txt", false},
		{ActionWrite, "src/secrets-dir/new.txt", false},
		{ActionRead, "src/escape", false},
		{ActionRead, "src/escape-dir/host-secret", false},
		{ActionWrite, "src/escape-dir/new-file", false},
		{ActionRead, "src/ok-link", true},
		{ActionRead, "src/logs-link/app.log", true},   // read allowed via logs/**
		{ActionWrite, "src/logs-link/app.log", false}, // but logs is read-only
		// Kernel semantics: up/.. is the parent of the link target (secrets),
		// not src/lib. A lexical cleaner would wrongly allow this.
		{ActionRead, "src/lib/up/../api-key.txt", false},
		{ActionRead, "tests/loop-a", false},
		{ActionRead, ".env-link-to-src", false}, // the name itself is denied
	})
	d := e.Evaluate(ActionRead, "src/escape")
	if !strings.Contains(d.Reason, "outside the workspace") {
		t.Errorf("escape reason = %q", d.Reason)
	}
}

func TestSymlinkedWorkspaceRoot(t *testing.T) {
	root := newWorkspace(t)
	link := filepath.Join(t.TempDir(), "ws")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	e := newEngine(t, developerYAML, link)
	run(t, e, []tc{
		{ActionRead, "src/app.js", true},
		{ActionRead, filepath.Join(link, "src/app.js"), true},
		{ActionRead, filepath.Join(link, ".env"), false},
	})
}

func TestCommands(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, developerYAML, root)
	run(t, e, []tc{
		{ActionExecute, "npm", true},
		{ActionExecute, "node", true},
		{ActionExecute, "git", true},
		{ActionExecute, "curl", false},
		{ActionExecute, "sh", false},
		{ActionExecute, "bash", false},
		{ActionExecute, "NPM", false}, // exact match only
		{ActionExecute, "/usr/bin/npm", false},
		{ActionExecute, "./npm", false},
		{ActionExecute, "../bin/npm", false},
		{ActionExecute, "npm;curl", false},
		{ActionExecute, "npm && curl evil", false},
		{ActionExecute, "$(curl)", false},
		{ActionExecute, "`id`", false},
		{ActionExecute, "", false},
	})
}

func TestNetwork(t *testing.T) {
	root := newWorkspace(t)
	run(t, newEngine(t, developerYAML, root), []tc{{ActionNetwork, "registry.npmjs.org", false}})
	run(t, newEngine(t, "role: net\nnetwork:\n  enabled: true\n", root), []tc{{ActionNetwork, "", true}})
}

func TestGitImplicitReadOnly(t *testing.T) {
	root := newWorkspace(t)
	run(t, newEngine(t, developerYAML, root), []tc{
		{ActionRead, ".git/HEAD", true},
		{ActionWrite, ".git/HEAD", false},
		{ActionWrite, ".git/hooks/post-checkout", false},
		{ActionWrite, "src/vendor/.git/config", false},
		{ActionRead, ".git/config", false}, // may hold tokens
	})
	// Without git, .git is not readable at all.
	run(t, newEngine(t, "role: t\nfilesystem:\n  read: [src/**]\ncommands:\n  allow: [node]\n", root), []tc{
		{ActionRead, ".git/HEAD", false},
	})
}

func TestReviewerCannotWrite(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, "role: reviewer\nfilesystem:\n  read: [src/**, tests/**]\n  write: []\ncommands:\n  allow: [git]\n", root)
	run(t, e, []tc{
		{ActionRead, "src/app.js", true},
		{ActionWrite, "src/app.js", false},
		{ActionWrite, "tests/x.js", false},
		{ActionExecute, "git", true},
		{ActionExecute, "npm", false},
	})
}

func TestExpiredPolicyDeniesEverything(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, developerYAML+"metadata:\n  source: test\n  expires_at: 2020-01-01T00:00:00Z\n", root)
	run(t, e, []tc{
		{ActionRead, "src/app.js", false},
		{ActionExecute, "npm", false},
	})
	e.now = func() time.Time { return time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC) }
	run(t, e, []tc{{ActionRead, "src/app.js", true}})
}

func TestObserverSeesEveryDecision(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, developerYAML, root)
	var got []Decision
	e.SetObserver(func(d Decision) { got = append(got, d) })
	e.Evaluate(ActionRead, "src/app.js")
	e.Evaluate(ActionRead, ".env")
	e.Evaluate(ActionExecute, "curl")
	if len(got) != 3 {
		t.Fatalf("observer saw %d decisions, want 3", len(got))
	}
	if got[0].Role != "developer" || !got[0].Allowed || got[1].Allowed || got[2].Allowed {
		t.Errorf("unexpected decisions: %+v", got)
	}
}

func TestIsHidden(t *testing.T) {
	root := newWorkspace(t)
	e := newEngine(t, developerYAML, root)
	for rel, want := range map[string]bool{
		".env":                  true,
		"src/config/.env.local": true,
		"secrets":               true,
		".agentguard":           true,
		".git/config":           true,
		"src/app.js":            false,
		"logs":                  false,
		".git/HEAD":             false,
	} {
		if got, _ := e.IsHidden(rel); got != want {
			t.Errorf("IsHidden(%q) = %v, want %v", rel, got, want)
		}
	}
}
