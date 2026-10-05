package policy

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/longvo2k/agentguard"
)

func TestParseRejectsBadPolicies(t *testing.T) {
	cases := map[string]string{
		"empty":         "",
		"unknown field": "role: dev\ndeney: [.env]\n",
		"bad role":      "role: Dev Ops\n",
		"missing role":  "filesystem:\n  read: [src/**]\n",
		"traversal":     "role: dev\nfilesystem:\n  read: [../**]\n",
		"dot segment":   "role: dev\nfilesystem:\n  read: [src/../.env]\n",
		"absolute read": "role: dev\nfilesystem:\n  read: [/etc/**]\n",
		"home read":     "role: dev\nfilesystem:\n  write: [~/.ssh/**]\n",
		"bad glob":      "role: dev\nfilesystem:\n  read: ['src/[']\n",
		"command path":  "role: dev\ncommands:\n  allow: [/bin/sh]\n",
		"command shell": "role: dev\ncommands:\n  allow: ['npm; curl']\n",
		"two documents": "role: a\n---\nrole: b\n",
		"wrong type":    "role: dev\nnetwork: yes\n",
		"empty pattern": "role: dev\nfilesystem:\n  read: ['']\n",
		"slash only":    "role: dev\nfilesystem:\n  read: ['./']\n",
	}
	for name, yml := range cases {
		if _, err := Parse([]byte(yml)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseAcceptsAbsoluteDeny(t *testing.T) {
	p, err := Parse([]byte("role: dev\ndeny: [~/.ssh/**, /etc/**]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Deny) != 2 {
		t.Fatalf("deny = %v", p.Deny)
	}
}

func TestBuiltinPoliciesAreValid(t *testing.T) {
	files, err := fs.Glob(agentguard.BuiltinPolicies, "policies/*.yaml")
	if err != nil || len(files) != 4 {
		t.Fatalf("expected 4 built-in policies, got %v (%v)", files, err)
	}
	for _, f := range files {
		data, _ := agentguard.BuiltinPolicies.ReadFile(f)
		p, err := Parse(data)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if !strings.HasSuffix(f, "/"+p.Role+".yaml") {
			t.Errorf("%s declares role %q", f, p.Role)
		}
	}
}

func TestParseAction(t *testing.T) {
	for _, s := range []string{"read", "write", "execute", "network"} {
		if _, err := ParseAction(s); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	if _, err := ParseAction("delete"); err == nil {
		t.Error("expected error for unknown action")
	}
}

func TestMountPrefix(t *testing.T) {
	cases := []struct {
		pattern string
		prefix  string
		exact   bool
	}{
		{"src/**", "src", true},
		{"src", ".", false}, // name pattern: any depth
		{"./src", "src", true},
		{"src/**/*.js", "src", false},
		{"docs/api/**", "docs/api", true},
		{"**", ".", false},
		{"*.txt", ".", false},
		{"./package.json", "package.json", true},
	}
	for _, c := range cases {
		prefix, exact, err := MountPrefix(c.pattern)
		if err != nil {
			t.Fatalf("%s: %v", c.pattern, err)
		}
		if prefix != c.prefix || exact != c.exact {
			t.Errorf("MountPrefix(%q) = %q,%v want %q,%v", c.pattern, prefix, exact, c.prefix, c.exact)
		}
	}
}

func TestSandboxGlobs(t *testing.T) {
	cases := map[string][]string{
		".env*":        {"/srv/app/.env*", "/srv/app/**/.env*"},
		"secrets/**":   {"/srv/app/secrets"},
		"./README.md":  {"/srv/app/README.md"},
		".git/config":  {"/srv/app/.git/config"},
		"src/**/*.pem": {"/srv/app/src/**/*.pem"},
		"~/.ssh/**":    {"~/.ssh"},
		"/etc/myapp/":  {"/etc/myapp"},
	}
	for in, want := range cases {
		got, err := SandboxGlobs(in, "/srv/app/")
		if err != nil || strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("SandboxGlobs(%q) = %v %v, want %v", in, got, err, want)
		}
	}
	if _, err := SandboxGlobs("../x", "/srv/app"); err == nil {
		t.Error("traversal accepted")
	}
}
