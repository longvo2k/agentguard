package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// A project's .agentguard/ is only honored when it is on the user's trust
// list with a matching digest of its config and policies. `agentguard init`
// trusts what it creates; anything else (a cloned repository's policies, a
// .agentguard/ planted by an agent in a writable directory, policies edited
// since) needs `agentguard trust` after review. This mirrors direnv's
// `allow`.

// ErrUntrusted means a project's .agentguard/ is not (or no longer) trusted.
var ErrUntrusted = errors.New("untrusted workspace")

// TrustState describes a workspace's standing on the trust list.
type TrustState int

const (
	Untrusted TrustState = iota
	Trusted
	Changed // trusted once, but the policies changed since
)

type trustFile struct {
	Version    int                   `json:"version"`
	Workspaces map[string]trustEntry `json:"workspaces"`
}

type trustEntry struct {
	Digest    string    `json:"digest"`
	TrustedAt time.Time `json:"trusted_at"`
}

func trustPath() (string, error) {
	d, err := UserStateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "trust.json"), nil
}

func loadTrust() (*trustFile, error) {
	tf := &trustFile{Version: 1, Workspaces: map[string]trustEntry{}}
	p, err := trustPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return tf, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, tf); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if tf.Workspaces == nil {
		tf.Workspaces = map[string]trustEntry{}
	}
	return tf, nil
}

func saveTrust(tf *trustFile) error {
	p, err := trustPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(tf, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".trust-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// PolicyDigest hashes config.yaml and policies/*.yaml in a config directory.
func PolicyDigest(configDir string) (string, error) {
	files, _ := filepath.Glob(filepath.Join(configDir, "policies", "*.yaml"))
	files = append(files, filepath.Join(configDir, "config.yaml"))
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		rel, _ := filepath.Rel(configDir, f)
		fmt.Fprintf(h, "%s\x00%d\x00", filepath.ToSlash(rel), len(data))
		h.Write(data)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Trust records the current policies of the project at root as trusted.
func Trust(root string) error {
	root = realPath(root)
	digest, err := PolicyDigest(filepath.Join(root, DirName))
	if err != nil {
		return err
	}
	tf, err := loadTrust()
	if err != nil {
		return err
	}
	tf.Workspaces[root] = trustEntry{Digest: digest, TrustedAt: time.Now().UTC()}
	return saveTrust(tf)
}

// Untrust removes root from the trust list.
func Untrust(root string) error {
	tf, err := loadTrust()
	if err != nil {
		return err
	}
	delete(tf.Workspaces, realPath(root))
	return saveTrust(tf)
}

// TrustStatus reports whether the project at root is trusted.
func TrustStatus(root string) (TrustState, error) {
	root = realPath(root)
	tf, err := loadTrust()
	if err != nil {
		return Untrusted, err
	}
	e, ok := tf.Workspaces[root]
	if !ok {
		return Untrusted, nil
	}
	digest, err := PolicyDigest(filepath.Join(root, DirName))
	if err != nil {
		return Untrusted, err
	}
	if digest != e.Digest {
		return Changed, nil
	}
	return Trusted, nil
}
