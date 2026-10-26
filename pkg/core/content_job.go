package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"

	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/tool/wordlist"
)

// Content a job pins (api RFC-061): packs by digest, named in the signed
// statement and in the payload, and lists the platform generated for the job
// inline. The sensor mounts only the packs the signed statement lists, checks
// each one against its pinned content keys, and composes the lists into one
// file in the task's own directory.

// Bounds of a job's content.
const (
	// MaxJobContentItems and MaxJobInputs bound the members of a payload.
	MaxJobContentItems = 8
	MaxJobInputs       = 8
	// MaxJobContentFiles bounds the files one pack item names.
	MaxJobContentFiles = 64
	// MaxJobInputBytes is the largest compressed inline list (256 KiB) and
	// MaxJobInputsTotal the most all of a job's inline lists may take.
	MaxJobInputBytes  = 256 << 10
	MaxJobInputsTotal = 512 << 10
	// MaxJobInputExpanded is the most one inline list may expand to: a
	// compressed bomb is refused, never fully read.
	MaxJobInputExpanded = 8 << 20
)

// Rules of a refusal for a job's content.
const RefusalRuleJobContent = "job_content"

// ErrContentUnavailable marks a job whose packs could not be delivered
// (network, timeout, HTTP error). The command fails with it and the platform
// requeues it; a pack that fails a check is a refusal, not this.
var ErrContentUnavailable = errors.New("content_unavailable")

// JobContent is one pack a job names (ScanCommandPayload.Content).
type JobContent struct {
	// Slot is the tool's content slot ("labels").
	Slot string `json:"slot"`
	// Kind is the content kind ("wordlist").
	Kind string `json:"kind,omitempty"`
	// Scope is "platform" or "tenant": which pinned key signs the pack.
	Scope string `json:"scope"`
	// Pack is the pack's name, a lower-case slug.
	Pack string `json:"pack"`
	// Digest is the pack's "sha256:<hex>" content address.
	Digest string `json:"digest"`
	// Size is the canonical archive's size in bytes.
	Size int64 `json:"size,omitempty"`
	// Files are the files of the pack the slot uses (wordlists).
	Files []string `json:"files,omitempty"`
	// MaxLines is the job's cap on the composed wordlist.
	MaxLines int `json:"max_lines,omitempty"`
	// Signature is the DSSE envelope of the pack statement.
	Signature json.RawMessage `json:"signature"`
}

// JobInput is a list generated for one job (ScanCommandPayload.Inputs): the
// tenant's own data, carried inside the signed payload, written only to the
// task directory and erased with it. It is never put in the content cache.
type JobInput struct {
	Slot    string `json:"slot"`
	Purpose string `json:"purpose"`
	// SHA256 is the lower-case hex SHA-256 of the list as it reads when
	// decompressed.
	SHA256 string `json:"sha256"`
	Lines  int    `json:"lines,omitempty"`
	// Data is the gzip-compressed list (standard base64 in JSON).
	Data []byte `json:"data_b64"`
}

// ContentRequest is what the content cache is asked to hold for a job.
type ContentRequest struct {
	// Shared: the job runs on a shared sensor and belongs to Tenant. Only
	// platform packs are delivered then.
	Shared bool
	Tenant string
	// Items are the job's packs, already checked against the signed
	// statement.
	Items []JobContent
}

// ResolvedContent is a job's content as the task gets it, per slot.
type ResolvedContent struct {
	Slots []ResolvedSlot
}

// ResolvedSlot is one slot's packs and inline lists.
type ResolvedSlot struct {
	Slot     string
	MaxLines int
	Packs    []ResolvedPack
	Inline   []ResolvedList
}

// ResolvedPack is a pack held by the cache, in use by the task.
type ResolvedPack struct {
	Digest string
	Source string
	// Path is the pack directory in the cache.
	Path  string
	Files []string
}

// ResolvedList is an inline list, decompressed and checked.
type ResolvedList struct {
	Purpose string
	SHA256  string
	Data    []byte
}

// ContentResolver delivers a job's packs: it makes the cache hold each one
// (fetching a missing one, verifying its digest and signature against the
// sensor's pinned keys) and marks it in use until release is called. It
// fails with ErrContentUnavailable when a pack cannot be delivered and with
// another error when one fails a check. *sensorkit's cache implements it.
type ContentResolver interface {
	ResolveContent(ctx context.Context, req ContentRequest) (rc *ResolvedContent, release func(), err error)
}

// ContentScanner is a scanner that runs jobs with content: its tool host
// composes the wordlists and grants the task its own packs only. A job that
// carries content or inline lists for any other scanner is refused.
type ContentScanner interface {
	Scanner
	TakesJobContent() bool
}

// SetContentResolver sets the cache the executor takes a job's packs from
// (nil refuses every job that names packs).
func (e *DefaultCommandExecutor) SetContentResolver(r ContentResolver) {
	if r == nil {
		e.content.Store(nil)
		return
	}
	e.content.Store(&r)
}

var (
	jobSlotRE   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	jobPackRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	jobDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	jobSHA256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NewContentRefusal is the refusal of a job whose content fails a check: it
// was never run (the layer is builtin, the rule job_content).
func NewContentRefusal(format string, args ...any) error { return contentRefusal(format, args...) }

func contentRefusal(format string, args ...any) error {
	return &LocalPolicyError{Layer: RefusalLayerBuiltin, Rule: RefusalRuleJobContent, Detail: fmt.Sprintf(format, args...)}
}

// checkJobContent checks the pack members and decodes the inline lists of a
// payload before anything is fetched or written. The packs must be exactly
// the ones the verified signed statement lists: a job that names content
// runs only when its statement was verified, so a pack the signer did not
// approve for this organization is never mounted.
func checkJobContent(cmd *Command, p *ScanCommandPayload, shared bool) ([]ResolvedList, error) {
	if len(p.Content) > MaxJobContentItems || len(p.Inputs) > MaxJobInputs {
		return nil, contentRefusal("a job carries at most %d packs and %d inline lists", MaxJobContentItems, MaxJobInputs)
	}
	if len(p.Content) > 0 {
		if !cmd.jobVerified {
			return nil, contentRefusal("the job names content packs and its signature was not verified: a job without a verified signed statement mounts no packs")
		}
		refs := make([]jobsig.ContentRef, len(p.Content))
		for i, c := range p.Content {
			refs[i] = jobsig.ContentRef{Slot: c.Slot, Digest: c.Digest}
		}
		if !slices.Equal(refs, cmd.signedContent) {
			return nil, contentRefusal("the packs the job names are not the packs its signed statement lists (%d signed, %d received)", len(cmd.signedContent), len(refs))
		}
	} else if len(cmd.signedContent) > 0 {
		return nil, contentRefusal("the signed statement lists %d pack(s) the job does not carry", len(cmd.signedContent))
	}
	seen := map[string]bool{}
	for i, c := range p.Content {
		switch {
		case !jobSlotRE.MatchString(c.Slot):
			return nil, contentRefusal("content %d: invalid slot", i)
		case !jobPackRE.MatchString(c.Pack):
			return nil, contentRefusal("content %d: invalid pack name", i)
		case !jobDigestRE.MatchString(c.Digest):
			return nil, contentRefusal("content %d: %q is not a sha256 digest", i, truncateBytes(c.Digest, 80))
		case c.Scope != "platform" && c.Scope != "tenant":
			return nil, contentRefusal("content %d: scope must be platform or tenant", i)
		case shared && c.Scope != "platform":
			// A shared sensor holds platform packs only: one copy for every
			// organization, nothing of one organization's in the cache.
			return nil, contentRefusal("content %d: a shared sensor mounts platform packs only", i)
		case len(c.Files) > MaxJobContentFiles || c.MaxLines < 0 || c.Size < 0:
			return nil, contentRefusal("content %d: too many files or a negative limit", i)
		case seen[c.Slot+"/"+c.Pack]:
			return nil, contentRefusal("content %d: pack %s is named twice for slot %s", i, c.Pack, c.Slot)
		}
		seen[c.Slot+"/"+c.Pack] = true
		for _, f := range c.Files {
			if !wordlist.CleanFilePath(f) {
				return nil, contentRefusal("content %d: %q is not a clean file path inside the pack", i, truncateBytes(f, 80))
			}
		}
	}
	var lists []ResolvedList
	total := 0
	for i, in := range p.Inputs {
		total += len(in.Data)
		switch {
		case !jobSlotRE.MatchString(in.Slot):
			return nil, contentRefusal("inline list %d: invalid slot", i)
		case !wordlist.Known(in.Purpose):
			return nil, contentRefusal("inline list %d: unknown purpose %q", i, truncateBytes(in.Purpose, 40))
		case !jobSHA256RE.MatchString(in.SHA256):
			return nil, contentRefusal("inline list %d: sha256 is not 64 lower-case hex digits", i)
		case len(in.Data) == 0 || len(in.Data) > MaxJobInputBytes || total > MaxJobInputsTotal:
			return nil, contentRefusal("inline list %d: larger than the %d KiB a job may carry compressed, or empty", i, MaxJobInputBytes>>10)
		}
		data, err := inflateInput(in.Data)
		if err != nil {
			return nil, contentRefusal("inline list %d: %v", i, err)
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != in.SHA256 {
			return nil, contentRefusal("inline list %d: its bytes are not the sha256 the job names", i)
		}
		lists = append(lists, ResolvedList{Purpose: in.Purpose, SHA256: in.SHA256, Data: data})
	}
	return lists, nil
}

// inflateInput decompresses an inline list, refusing one that expands past
// MaxJobInputExpanded.
func inflateInput(gz []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("not gzip data: %w", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, MaxJobInputExpanded+1))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	if len(out) > MaxJobInputExpanded {
		return nil, fmt.Errorf("expands to more than %d MiB", MaxJobInputExpanded>>20)
	}
	return out, nil
}

// prepareJobContent resolves a scan job's content for its scanner and puts it
// in opts. The returned release (never nil) must run when the job ends.
func (e *DefaultCommandExecutor) prepareJobContent(ctx context.Context, cmd *Command, p *ScanCommandPayload, scanner Scanner, opts *ScanOptions) (func(), error) {
	noop := func() {}
	if len(p.Content) == 0 && len(p.Inputs) == 0 && len(cmd.signedContent) == 0 {
		return noop, nil
	}
	shared := cmd.jobTenant != ""
	lists, err := checkJobContent(cmd, p, shared)
	if err != nil {
		return noop, err
	}
	if cs, ok := scanner.(ContentScanner); !ok || !cs.TakesJobContent() {
		return noop, contentRefusal("the job carries content and scanner %s cannot take it", p.Scanner)
	}
	rc := &ResolvedContent{}
	release := noop
	if len(p.Content) > 0 {
		rp := e.content.Load()
		if rp == nil {
			return noop, contentRefusal("the job names content packs and this sensor has no content cache")
		}
		resolved, rel, rerr := (*rp).ResolveContent(ctx, ContentRequest{Shared: shared, Tenant: cmd.jobTenant, Items: p.Content})
		if rerr != nil {
			return noop, rerr
		}
		if rel != nil {
			release = rel
		}
		if resolved != nil {
			rc = resolved
		}
	}
	// Inline lists join the slot they are for (a slot with only inline lists
	// gets its own entry).
	for i, in := range p.Inputs {
		idx := slices.IndexFunc(rc.Slots, func(s ResolvedSlot) bool { return s.Slot == in.Slot })
		if idx < 0 {
			rc.Slots = append(rc.Slots, ResolvedSlot{Slot: in.Slot})
			idx = len(rc.Slots) - 1
		}
		rc.Slots[idx].Inline = append(rc.Slots[idx].Inline, lists[i])
	}
	opts.Content = rc
	return release, nil
}
