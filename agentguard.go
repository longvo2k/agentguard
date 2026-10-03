// Package agentguard holds assets that are compiled into the agentguard
// binary. The CLI lives in cmd/agentguard and the logic in internal/.
package agentguard

import "embed"

// BuiltinPolicies contains the example role policies in policies/*.yaml.
//
//go:embed policies/*.yaml
var BuiltinPolicies embed.FS
