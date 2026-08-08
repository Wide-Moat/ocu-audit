// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package retention

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Wide-Moat/ocu-audit/internal/signer"
)

// checkpointDomainTag scopes the checkpoint's signed form (ADR-0045). The
// head envelope signs under "ocu-audit-head/v1"; distinct tags keep the two
// artifact classes unforgeable as each other under the one host-local key.
const checkpointDomainTag = "ocu-audit-retention/v1\x00"

// SegmentEntry is one sealed segment's inventory row.
type SegmentEntry struct {
	// Name is the segment file name (audit-NNNNNN.wal).
	Name string `json:"name"`
	// SHA256 is the whole-file digest of the sealed segment bytes.
	SHA256 []byte `json:"sha256"`
	// RecordCount is the number of committed records in the segment.
	RecordCount uint64 `json:"record_count"`
	// FirstIngestMillis / LastIngestMillis bound the segment's hash-bound
	// IngestTime stamps (the trusted clock rotation decisions read).
	FirstIngestMillis int64 `json:"first_ingest_millis"`
	LastIngestMillis  int64 `json:"last_ingest_millis"`
	// FirstGlobalIndex / LastGlobalIndex bound the segment's records in
	// commit order (Merkle leaf indexes).
	FirstGlobalIndex uint64 `json:"first_global_index"`
	LastGlobalIndex  uint64 `json:"last_global_index"`
	// SealedAtMillis is when the segment was sealed; RotatedAtMillis is when
	// its cold copy was verified complete (0 = still hot).
	SealedAtMillis  int64 `json:"sealed_at_millis"`
	RotatedAtMillis int64 `json:"rotated_at_millis"`
	// SealTips, SealTreeSize, and SealFrontier are the seal-point anchors
	// (store.SealSnapshot): when THIS segment rotates, they become the
	// checkpoint's top-level boot anchors. Segments rotate strictly in index
	// order, so the promotion is well-defined.
	SealTips     map[string]ChainTip `json:"seal_tips"`
	SealTreeSize uint64              `json:"seal_tree_size"`
	SealFrontier [][]byte            `json:"seal_frontier"`
}

// Checkpoint is the signed retention state (ADR-0045): the declared policy,
// the full segment inventory, and the boot anchors — per-source chain tips,
// Merkle tree size, and accumulator frontier at the rotation boundary — so a
// restart verifies the hot tier only and never reads the cold seam.
type Checkpoint struct {
	Policy   Policy         `json:"policy"`
	Segments []SegmentEntry `json:"segments"`
	// ChainTips maps each source to its last committed chain hash AND
	// sequence within the rotated (cold) prefix. The first hot record of a
	// source must link onto the hash and exceed the sequence; a source absent
	// here anchors on genesis.
	ChainTips map[string]ChainTip `json:"chain_tips"`
	// TreeSize and Frontier are the Merkle accumulator state at the rotation
	// boundary (merkletree.Frontier).
	TreeSize uint64   `json:"tree_size"`
	Frontier [][]byte `json:"frontier"`
}

// ChainTip is one source's chain state at the rotation boundary.
type ChainTip struct {
	Hash []byte `json:"hash"`
	Seq  uint64 `json:"seq"`
}

// SignedCheckpoint is the on-disk form: the checkpoint, its detached
// signature over SignBytes, and the signing public key for pin comparison.
type SignedCheckpoint struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	Signature  []byte     `json:"signature"`
	PublicKey  []byte     `json:"public_key"`
}

// SignBytes returns the canonical, injective, domain-tagged byte string the
// signature covers. Every variable-length field is length-prefixed and every
// list is length-counted, so two distinct checkpoints cannot share a signed
// form; map iteration is sorted for determinism.
func (c Checkpoint) SignBytes() []byte {
	var buf []byte
	u64 := func(v uint64) {
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], v)
		buf = append(buf, b[:]...)
	}
	i64 := func(v int64) { u64(uint64(v)) }
	field := func(v []byte) {
		u64(uint64(len(v)))
		buf = append(buf, v...)
	}

	buf = append(buf, []byte(checkpointDomainTag)...)
	u64(uint64(c.Policy.FloorYears))
	i64(int64(c.Policy.HotMax / time.Millisecond))
	i64(int64(c.Policy.SealInterval / time.Millisecond))

	u64(uint64(len(c.Segments)))
	for _, s := range c.Segments {
		field([]byte(s.Name))
		field(s.SHA256)
		u64(s.RecordCount)
		i64(s.FirstIngestMillis)
		i64(s.LastIngestMillis)
		u64(s.FirstGlobalIndex)
		u64(s.LastGlobalIndex)
		i64(s.SealedAtMillis)
		i64(s.RotatedAtMillis)
		tipSources := make([]string, 0, len(s.SealTips))
		for src := range s.SealTips {
			tipSources = append(tipSources, src)
		}
		sort.Strings(tipSources)
		u64(uint64(len(tipSources)))
		for _, src := range tipSources {
			field([]byte(src))
			field(s.SealTips[src].Hash)
			u64(s.SealTips[src].Seq)
		}
		u64(s.SealTreeSize)
		u64(uint64(len(s.SealFrontier)))
		for _, h := range s.SealFrontier {
			field(h)
		}
	}

	sources := make([]string, 0, len(c.ChainTips))
	for src := range c.ChainTips {
		sources = append(sources, src)
	}
	sort.Strings(sources)
	u64(uint64(len(sources)))
	for _, src := range sources {
		field([]byte(src))
		field(c.ChainTips[src].Hash)
		u64(c.ChainTips[src].Seq)
	}

	u64(c.TreeSize)
	u64(uint64(len(c.Frontier)))
	for _, h := range c.Frontier {
		field(h)
	}
	return buf
}

// WriteCheckpoint signs and persists the checkpoint at path as temp+rename
// with a directory fsync, 0600 — a crash mid-write never leaves a torn file
// at the final name, and a rotation step is durable before the next begins.
func WriteCheckpoint(path string, c Checkpoint, sgn *signer.Signer) error {
	sc := SignedCheckpoint{
		Checkpoint: c,
		Signature:  sgn.SignMessage(c.SignBytes()),
		PublicKey:  sgn.PublicKey(),
	}
	raw, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return fmt.Errorf("retention: marshal checkpoint: %w", err)
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".retention-checkpoint-*")
	if err != nil {
		return fmt.Errorf("retention: checkpoint temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("retention: checkpoint perms: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("retention: checkpoint write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("retention: checkpoint fsync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("retention: checkpoint close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("retention: checkpoint rename: %w", err)
	}
	return syncDir(dir)
}

// LoadCheckpoint reads, signature-verifies, and policy-gates the checkpoint.
// Refusals are fail-closed with distinct diagnostics: a bad signature, a
// pinned floor below the NFR-COMP-01 minimum (checked HERE, not only at
// policy construction, so a forged-but-signed file cannot ride a masked
// guard), and a configured floor below the pinned one (a retention SHRINK).
// Lengthening the floor is not a shrink and loads.
func LoadCheckpoint(path string, pinnedPub []byte, configured Policy) (Checkpoint, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured checkpoint path
	if err != nil {
		return Checkpoint{}, err
	}
	var sc SignedCheckpoint
	if err := json.Unmarshal(raw, &sc); err != nil {
		return Checkpoint{}, fmt.Errorf("retention: unmarshal checkpoint: %w", err)
	}
	if err := signer.VerifyMessage(pinnedPub, sc.Checkpoint.SignBytes(), sc.Signature); err != nil {
		return Checkpoint{}, fmt.Errorf("retention: checkpoint signature: %w", err)
	}
	if sc.Checkpoint.Policy.FloorYears < FloorYearsMinimum {
		return Checkpoint{}, fmt.Errorf("retention: checkpoint pins floor %d y, below the NFR-COMP-01 minimum %d y",
			sc.Checkpoint.Policy.FloorYears, FloorYearsMinimum)
	}
	if configured.FloorYears < sc.Checkpoint.Policy.FloorYears {
		return Checkpoint{}, fmt.Errorf("retention: configured floor %d y would shrink the pinned floor %d y; refusing (ADR-0045)",
			configured.FloorYears, sc.Checkpoint.Policy.FloorYears)
	}
	return sc.Checkpoint, nil
}

// syncDir fsyncs a directory so a rename inside it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir) // #nosec G304 -- operator-configured directory
	if err != nil {
		return fmt.Errorf("retention: open dir %q: %w", dir, err)
	}
	serr := d.Sync()
	cerr := d.Close()
	if serr != nil {
		return fmt.Errorf("retention: fsync dir %q: %w", dir, serr)
	}
	return cerr
}
