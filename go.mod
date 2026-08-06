module github.com/Wide-Moat/ocu-audit

// The module directive stays on line 1 so tools that derive the module path
// from the first line of go.mod (go-gremlins v0.6.0's modPkg() calls
// TrimPrefix("module ") on the first line, not a real go.mod parser) resolve
// the true path and attribute coverage correctly. Keep the leading comment
// block off line 1 for that reason.
//
// Dependency-policy note: github.com/transparency-dev/merkle (Apache-2.0)
// provides the RFC-6962 log hasher and inclusion/consistency proofs; it
// passes the license gate and supply-chain gate (SBOM + signed releases).

go 1.26.5

require github.com/transparency-dev/merkle v0.0.2

require pgregory.net/rapid v1.3.0
