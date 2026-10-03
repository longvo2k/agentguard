package policy

import (
	"path/filepath"
	"testing"
)

func TestExamplePoliciesAreValid(t *testing.T) {
	files, _ := filepath.Glob("../../examples/policies/*.yaml")
	if len(files) == 0 {
		t.Fatal("no example policies found")
	}
	for _, f := range files {
		p, err := LoadFile(f)
		if err != nil {
			t.Error(err)
			continue
		}
		if want := filepath.Base(f); want != p.Role+".yaml" {
			t.Errorf("%s declares role %q", f, p.Role)
		}
	}
}
