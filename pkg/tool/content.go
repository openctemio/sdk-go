package tool

import (
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
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
