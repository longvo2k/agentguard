package setup

import (
	"os"
	"os/exec"
	"path/filepath"
)

func lookPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// StableExecutable returns a path to the running agentguard binary that
// survives upgrades: the copy found on PATH if it is the same file (for
// Homebrew that is /opt/homebrew/bin/agentguard, not the versioned Cellar
// path), otherwise the executable itself.
func StableExecutable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	if onPath, err := exec.LookPath("agentguard"); err == nil {
		if abs, err := filepath.Abs(onPath); err == nil {
			if real, err := filepath.EvalSymlinks(abs); err == nil && real == exe {
				return abs, nil
			}
		}
	}
	return exe, nil
}
