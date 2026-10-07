package conformance

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// Bump is the semantic version part a descriptor change needs.
type Bump int

// Bumps, in order.
const (
	BumpNone Bump = iota
	BumpPatch
	BumpMinor
	BumpMajor
)

func (b Bump) String() string {
	return [...]string{"none", "patch", "minor", "major"}[b]
}

// Diff is what changed between two versions of a tool descriptor.
type Diff struct {
	// Breaking changes: a workflow, a pinned node or a stored setting
	// that worked with the old version can fail with the new one.
	Breaking []string
	// Additions: new capabilities, inputs, outputs or settings.
	Additions []string
	// Required is the smallest version bump the changes need.
	Required Bump
	// Problems are the reasons the new version is not acceptable: a name
	// change, or a version that does not bump enough.
	Problems []string
}

// OK reports whether the new descriptor is an acceptable successor.
func (d Diff) OK() bool { return len(d.Problems) == 0 }

// DiffManifests compares two versions of a tool's descriptor. A change
// that narrows what the tool takes or emits (an implemented capability, a
// consumed or produced type, a param mapping, a supported value or bound,
// an output shape), adds a required config key, removes a config key,
// raises the tier or adds a side effect is breaking and needs a major
// bump; an addition needs a minor bump; any other change to the descriptor
// needs at least a patch bump.
func DiffManifests(oldM, newM tool.Manifest) Diff {
	oldM, newM = oldM.Normalized(), newM.Normalized()
	var d Diff
	brk := func(format string, args ...any) { d.Breaking = append(d.Breaking, fmt.Sprintf(format, args...)) }
	add := func(format string, args ...any) { d.Additions = append(d.Additions, fmt.Sprintf(format, args...)) }

	if oldM.Name != newM.Name {
		d.Problems = append(d.Problems, fmt.Sprintf("the name changed (%s to %s): that is another tool", oldM.Name, newM.Name))
	}
	if oldM.Class != newM.Class {
		brk("class changed from %s to %s", oldM.Class, newM.Class)
	}
	if rank(newM.MinimumTier()) > rank(oldM.MinimumTier()) {
		brk("minimum tier raised from %s to %s", oldM.MinimumTier(), newM.MinimumTier())
	}
	if newM.Safety != nil {
		for _, se := range newM.Safety.SideEffects {
			if oldM.Safety == nil || !slices.Contains(oldM.Safety.SideEffects, se) {
				brk("side effect %s added", se)
			}
		}
	}
	setDiff(oldM.Consumes, newM.Consumes, func(s string) { brk("no longer consumes %s", s) }, func(s string) { add("consumes %s", s) })
	setDiff(oldM.Produces, newM.Produces, func(s string) { brk("no longer produces %s", s) }, func(s string) { add("produces %s", s) })

	for _, oi := range oldM.Implements {
		ni, ok := newM.Implementation(oi.Capability)
		if !ok {
			brk("no longer implements %s", oi.Capability)
			continue
		}
		if oi.OutputShape != ni.OutputShape {
			brk("%s output shape changed from %q to %q", oi.Capability, oi.OutputShape, ni.OutputShape)
		}
		for name, op := range oi.Params {
			np, ok := ni.Params[name]
			if !ok {
				brk("%s no longer takes the param %s", oi.Capability, name)
				continue
			}
			if len(op.Values) == 0 && len(np.Values) > 0 {
				brk("%s param %s now supports only %s", oi.Capability, name, strings.Join(np.Values, ", "))
			}
			for _, v := range op.Values {
				if len(np.Values) > 0 && !slices.Contains(np.Values, v) {
					brk("%s param %s no longer supports %q", oi.Capability, name, v)
				}
			}
			if narrowedMin(op.Min, np.Min) || narrowedMax(op.Max, np.Max) {
				brk("%s param %s bounds narrowed", oi.Capability, name)
			}
		}
		for name := range ni.Params {
			if _, ok := oi.Params[name]; !ok {
				add("%s takes the param %s", oi.Capability, name)
			}
		}
	}
	for _, ni := range newM.Implements {
		if _, ok := oldM.Implementation(ni.Capability); !ok {
			add("implements %s", ni.Capability)
		}
	}
	oldKeys, oldReq := configKeys(oldM.Config)
	newKeys, newReq := configKeys(newM.Config)
	for _, k := range oldKeys {
		if !slices.Contains(newKeys, k) {
			brk("config key %s removed", k)
		}
	}
	for _, k := range newKeys {
		if !slices.Contains(oldKeys, k) {
			add("config key %s added", k)
		}
	}
	for _, k := range newReq {
		if !slices.Contains(oldReq, k) {
			brk("config key %s is now required", k)
		}
	}

	switch {
	case len(d.Breaking) > 0:
		d.Required = BumpMajor
	case len(d.Additions) > 0:
		d.Required = BumpMinor
	case changedIgnoringVersion(oldM, newM):
		d.Required = BumpPatch
	}
	if d.Required > BumpNone {
		got, err := versionBump(oldM.Version, newM.Version)
		switch {
		case err != nil:
			d.Problems = append(d.Problems, err.Error())
		case got < d.Required:
			d.Problems = append(d.Problems, fmt.Sprintf("the changes need a %s version bump; %s to %s is a %s bump", d.Required, oldM.Version, newM.Version, got))
		}
	}
	return d
}

func rank(t tool.Tier) int { return map[tool.Tier]int{tool.T0: 0, tool.T1: 1, tool.T2: 2}[t] }

func setDiff(oldS, newS []string, removed, added func(string)) {
	for _, s := range oldS {
		if !slices.Contains(newS, s) {
			removed(s)
		}
	}
	for _, s := range newS {
		if !slices.Contains(oldS, s) {
			added(s)
		}
	}
}

func narrowedMin(o, n *int) bool { return n != nil && (o == nil || *n > *o) }
func narrowedMax(o, n *int) bool { return n != nil && (o == nil || *n < *o) }

// configKeys are the top-level keys and the required keys of a config
// schema.
func configKeys(raw json.RawMessage) (keys, required []string) {
	var s struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	_ = json.Unmarshal(raw, &s)
	for k := range s.Properties {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys, s.Required
}

func changedIgnoringVersion(a, b tool.Manifest) bool {
	a.Version, b.Version = "", ""
	return a.Digest() != b.Digest()
}

// versionBump is the bump from old to new; an error when new is not
// newer.
func versionBump(oldV, newV string) (Bump, error) {
	o, err1 := semver(oldV)
	n, err2 := semver(newV)
	if err1 != nil || err2 != nil {
		return BumpNone, fmt.Errorf("versions %q and %q are not both semantic versions", oldV, newV)
	}
	switch {
	case n[0] > o[0]:
		return BumpMajor, nil
	case n[0] == o[0] && n[1] > o[1]:
		return BumpMinor, nil
	case n[0] == o[0] && n[1] == o[1] && n[2] > o[2]:
		return BumpPatch, nil
	case n == o:
		return BumpNone, nil
	}
	return BumpNone, fmt.Errorf("version %s is older than %s", newV, oldV)
}

func semver(v string) ([3]int, error) {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("not MAJOR.MINOR.PATCH")
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, fmt.Errorf("not a number")
		}
		out[i] = n
	}
	return out, nil
}
