package tool

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/openctemio/sdk-go/pkg/tool/wordlist"
)

// ContentSlot is a kind of content a tool reads: templates, rules,
// signatures, a wordlist, a vulnerability database (tool.yaml content;
// api RFC-061). A tool declares its slots and never fetches content
// itself: the sensor resolves each task's packs (by digest, from the
// platform) and the task gets read-only paths to exactly those.
type ContentSlot struct {
	// Slot names the slot in the tool ("templates").
	Slot string `json:"slot"`
	// Kind is what the content is: a known kind (nuclei-templates,
	// semgrep-rules, yara-rules, vuln-db, wordlist, signatures) or a
	// tool's own, namespaced (x-acme/rules). Packs bind to tools by kind.
	Kind string `json:"kind"`
	// Format is dir (default), file or archive.
	Format string `json:"format,omitempty"`
	// Default is bundled (the platform's managed pack of this kind is
	// used unless a step says otherwise) or none.
	Default string `json:"default,omitempty"`
	// Modes are the compositions the tool supports: default, custom and
	// merge (default: all three).
	Modes []string `json:"modes,omitempty"`
	// Selectors are the filters the tool understands: tags, ids,
	// severities, paths.
	Selectors []string `json:"selectors,omitempty"`
	// MaxBytes bounds a pack of this slot (0: the sensor's limit).
	MaxBytes int64 `json:"max_bytes,omitempty"`
	// Purpose is what a wordlist slot is for (wordlist.DNSLabels, ...):
	// the platform picks the list for it and the runtime normalises and
	// composes the job's lists into one file whose path the tool reads
	// ({{content.<slot>}}). Only for kind wordlist.
	Purpose string `json:"purpose,omitempty"`
	// MaxLines bounds the composed wordlist (0: the runtime's default).
	// Only for kind wordlist.
	MaxLines int `json:"max_lines,omitempty"`
}

// Content compositions (api RFC-061 §3.3).
const (
	ContentDefault = "default"
	ContentCustom  = "custom"
	ContentMerge   = "merge"
)

// TaskContent is one slot's content for a task, resolved by the sensor.
type TaskContent struct {
	Slot string `json:"slot"`
	// Mode is default, custom or merge.
	Mode string `json:"mode,omitempty"`
	// Packs are the packs, in order (a merge: custom after default).
	Packs []ContentPack `json:"packs,omitempty"`
	// Selectors filter the content (tags, ids, severities, paths).
	Selectors map[string][]string `json:"selectors,omitempty"`
	// Files are the files of each pack a wordlist slot uses, by pack digest:
	// relative to the pack, clean, no ".." (from the signed job). A pack of
	// a wordlist slot with no entry here is handed to the tool as a
	// directory.
	Files map[string][]string `json:"files,omitempty"`
	// MaxLines is the job's cap on a composed wordlist (0: none beyond the
	// slot's).
	MaxLines int `json:"max_lines,omitempty"`
	// Inline are lists the platform generated for this job (wordlist
	// slots): carried in the signed job, written only to the task's own
	// directory, never to the content cache. The tool host composes them
	// with the packs' Files into the one file the tool reads and clears
	// them; they never reach the tool's process.
	Inline []InlineList `json:"-"`
}

// InlineList is one list that travels inside the job.
type InlineList struct {
	// Purpose is the list's purpose (wordlist.Known).
	Purpose string
	// SHA256 is the lower-case hex SHA-256 of Data.
	SHA256 string
	// Data is the list, one entry per line.
	Data []byte
}

// ContentPack is one immutable pack.
type ContentPack struct {
	// Digest is the pack's content address ("sha256:<hex>").
	Digest string `json:"digest"`
	// Source is where the pack came from (platform, tenant).
	Source string `json:"source,omitempty"`
	// Path is where the sensor keeps it, read-only for the task. Set by
	// the sensor's content cache, never taken from a job.
	Path string `json:"path,omitempty"`
}

// ContentPaths are the paths of a slot's packs in the task (none when the
// task has no content for it).
func (t Task) ContentPaths(slot string) []string {
	for _, c := range t.Content {
		if c.Slot == slot {
			out := make([]string, 0, len(c.Packs))
			for _, p := range c.Packs {
				if p.Path != "" {
					out = append(out, p.Path)
				}
			}
			return out
		}
	}
	return nil
}

var (
	slotRE        = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	contentKindRE = regexp.MustCompile(`^([a-z][a-z0-9-]{1,40}|x-[a-z0-9-]{1,32}/[a-z][a-z0-9-]{1,40})$`)
	packDigestRE  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// KnownContentKinds are the kinds the platform manages packs for; a
// tool's own kind is namespaced (x-<vendor>/<kind>).
var KnownContentKinds = []string{"nuclei-templates", "semgrep-rules", "yara-rules", "vuln-db", "wordlist", "signatures"}

var (
	contentFormats   = []string{"dir", "file", "archive"}
	contentDefaults  = []string{"bundled", "none"}
	contentModes     = []string{ContentDefault, ContentCustom, ContentMerge}
	contentSelectors = []string{"tags", "ids", "severities", "paths"}
)

const maxContentSlots = 8

func validateContent(slots []ContentSlot, add func(ptr, format string, args ...any)) {
	if len(slots) > maxContentSlots {
		add("/content", "at most %d slots", maxContentSlots)
	}
	seen := map[string]bool{}
	for i, c := range slots {
		ptr := fmt.Sprintf("/content/%d", i)
		if !slotRE.MatchString(c.Slot) {
			add(ptr+"/slot", "must match %s", slotRE)
		} else if seen[c.Slot] {
			add(ptr+"/slot", "%s is declared twice", c.Slot)
		}
		seen[c.Slot] = true
		if !contentKindRE.MatchString(c.Kind) || (!slices.Contains(KnownContentKinds, c.Kind) && !strings.HasPrefix(c.Kind, "x-")) {
			add(ptr+"/kind", "a known kind (%s) or a namespaced one (x-<vendor>/<kind>)", strings.Join(KnownContentKinds, ", "))
		}
		if c.Format != "" && !slices.Contains(contentFormats, c.Format) {
			add(ptr+"/format", "must be one of %s", strings.Join(contentFormats, ", "))
		}
		if c.Default != "" && !slices.Contains(contentDefaults, c.Default) {
			add(ptr+"/default", "must be one of %s", strings.Join(contentDefaults, ", "))
		}
		for j, m := range c.Modes {
			if !slices.Contains(contentModes, m) {
				add(fmt.Sprintf("%s/modes/%d", ptr, j), "must be one of %s", strings.Join(contentModes, ", "))
			}
		}
		for j, s := range c.Selectors {
			if !slices.Contains(contentSelectors, s) {
				add(fmt.Sprintf("%s/selectors/%d", ptr, j), "must be one of %s", strings.Join(contentSelectors, ", "))
			}
		}
		if c.MaxBytes < 0 || c.MaxBytes > 16<<30 {
			add(ptr+"/max_bytes", "must be between 0 and 16 GiB")
		}
		if c.Kind != "wordlist" && (c.Purpose != "" || c.MaxLines != 0) {
			add(ptr+"/purpose", "purpose and max_lines are for kind wordlist only")
		}
		if c.Purpose != "" && !wordlist.Known(c.Purpose) {
			add(ptr+"/purpose", "must be one of %s", strings.Join(wordlist.Purposes, ", "))
		}
		if c.MaxLines < 0 || c.MaxLines > 10_000_000 {
			add(ptr+"/max_lines", "must be between 0 and 10000000")
		}
	}
}

// Slot returns a declared content slot.
func (m Manifest) Slot(name string) (ContentSlot, bool) {
	for _, c := range m.Content {
		if c.Slot == name {
			return c, true
		}
	}
	return ContentSlot{}, false
}

// CleanPackFile reports whether f is a relative, slash-separated path that
// stays inside the pack (wordlist.CleanFilePath).
func CleanPackFile(f string) bool { return wordlist.CleanFilePath(f) }

// CheckTaskContent checks a task's content against the manifest: every
// slot declared, its mode supported, its selectors understood, every pack
// a sha256 digest whose path is an absolute path beneath root (the
// sensor's content cache). It returns the paths to grant the task.
func CheckTaskContent(m Manifest, task Task, root string) ([]string, error) {
	var paths []string
	for _, c := range task.Content {
		slot, ok := m.Slot(c.Slot)
		if !ok {
			return nil, Invalid("content slot %q is not declared by %s", c.Slot, m.Name)
		}
		if c.Mode != "" && len(slot.Modes) > 0 && !slices.Contains(slot.Modes, c.Mode) {
			return nil, Invalid("content slot %q does not support mode %q", c.Slot, c.Mode)
		}
		for sel := range c.Selectors {
			if !slices.Contains(slot.Selectors, sel) {
				return nil, Invalid("content slot %q does not take the %q selector", c.Slot, sel)
			}
		}
		if len(c.Inline) > 0 && slot.Kind != "wordlist" {
			return nil, Invalid("content slot %q: only a wordlist slot takes lists from the job", c.Slot)
		}
		for _, l := range c.Inline {
			if l.Purpose != "" && !wordlist.Known(l.Purpose) {
				return nil, Invalid("content slot %q: unknown wordlist purpose %q", c.Slot, l.Purpose)
			}
		}
		if len(c.Files) > 0 && slot.Kind != "wordlist" {
			return nil, Invalid("content slot %q: only a wordlist slot names files of a pack", c.Slot)
		}
		for d, files := range c.Files {
			if !packDigestRE.MatchString(d) {
				return nil, Invalid("content slot %q: %q is not a sha256 digest", c.Slot, d)
			}
			for _, f := range files {
				if !CleanPackFile(f) {
					return nil, Invalid("content slot %q: %q is not a clean file path inside the pack", c.Slot, f)
				}
			}
		}
		for _, p := range c.Packs {
			if !packDigestRE.MatchString(p.Digest) {
				return nil, Invalid("content slot %q: %q is not a sha256 digest", c.Slot, p.Digest)
			}
			if p.Path == "" {
				continue
			}
			clean := filepath.Clean(p.Path)
			rel, err := filepath.Rel(root, clean)
			if root == "" || !filepath.IsAbs(clean) || err != nil || rel == "." || strings.HasPrefix(rel, "..") {
				return nil, Invalid("content slot %q: a pack path must lie beneath the sensor's content cache", c.Slot)
			}
			paths = append(paths, clean)
		}
	}
	return paths, nil
}
