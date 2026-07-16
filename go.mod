module github.com/Wide-Moat/ocu-audit

// The module directive stays on line 1 so tools that derive the module path
// from the first line of go.mod (go-gremlins v0.6.0's modPkg() calls
// TrimPrefix("module ") on the first line, not a real go.mod parser) resolve
// the true path and attribute coverage correctly.

go 1.26.2
