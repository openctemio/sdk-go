// Package pack reads and checks a tool pack: the unit in which tools are
// versioned, built, signed and delivered to sensors.
//
// A pack is a directory with a pack.yaml (apiVersion openctem.io/pack/v1)
// and the tools it carries, each a tool.yaml plus its program (the tool
// contract, package tool). The same pack.yaml describes a first-party pack
// built into a sensor profile image and a third-party pack shipped as its
// own OCI image: built-in tools and outside tools use one format.
//
// pack.yaml states only what no tool.yaml can: which tools travel together,
// the third-party engines they bundle (with a sha256 per platform), the
// platforms, the SDK and protocol the pack needs, the base image of a pack
// image, and the pack's tier. Capabilities, inputs, outputs, credentials,
// network and resources stay in each tool.yaml; Describe derives the pack
// view from them. The tier is a claim the loader checks: it must equal the
// highest minimum tier of the pack's tools, so a reader of pack.yaml sees
// the truth and a pack cannot hide an active tool behind a passive label.
//
// The specification is docs/tool-packs.md; the machine-readable form is
// schema/pack.v1.schema.json in package tool.
//
// Stability: Beta (docs/STABILITY.md).
package pack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"github.com/openctemio/sdk-go/pkg/sdk"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// APIVersion is the pack manifest version this package reads.
const APIVersion = "openctem.io/pack/v1"

// FileName is the pack manifest's file name in a pack directory.
const FileName = "pack.yaml"

// MaxManifestBytes bounds pack.yaml.
const MaxManifestBytes = 64 << 10

// Limits of a pack.
const (
	MaxTools   = 32
	MaxEngines = 32
)

// Platforms a pack may name.
var Platforms = []string{"linux/amd64", "linux/arm64"}

var (
	nameRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
	versionRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]{1,64})?(\+[0-9A-Za-z.-]{1,64})?$`)
	sha256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// A base image is pinned by digest: a tag can move under a signed pack.
	baseRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9._/:-]{0,254}@sha256:[0-9a-f]{64}$`)
	licenseRE = regexp.MustCompile(`^[A-Za-z0-9.+() -]{1,128}$`)
)

// Pack is pack.yaml.
type Pack struct {
	// APIVersion is APIVersion.
	APIVersion string `json:"apiVersion"`
	// Name is the pack's name: ^[a-z][a-z0-9-]{1,62}$.
	Name string `json:"name"`
	// Version is the pack's semantic version (no leading v). Any change
	// to the pack's files needs a new version.
	Version     string `json:"version"`
	Description string `json:"description,omitempty"`
	// Publisher is who publishes the pack, as a namespace
	// (^[a-z][a-z0-9-]{1,62}$). A catalog binds it to the signing
	// identity; the loader treats it as text.
	Publisher string `json:"publisher"`
	// License is the SPDX license expression of the pack's own files.
	// Each engine carries its own.
	License string `json:"license"`
	// Tier is the pack's tier: T0 passive, T1 active, T2 intrusive. It
	// must equal the highest minimum tier of the pack's tools.
	Tier tool.Tier `json:"tier"`
	// Tools are the tools the pack carries.
	Tools []ToolRef `json:"tools"`
	// Engines are the third-party programs the pack bundles. Every
	// engine a tool names (tool.yaml engine.name) is listed here.
	Engines []Engine `json:"engines,omitempty"`
	// Platforms are the platforms the pack is built for.
	Platforms []string `json:"platforms"`
	// Requires is what a sensor needs to run the pack.
	Requires Requires `json:"requires"`
	// Image is how a pack image is built; absent for a pack that is only
	// built into a sensor profile image.
	Image *Image `json:"image,omitempty"`
}

// ToolRef names one tool of the pack.
type ToolRef struct {
	// Name is the tool's name (tool.yaml name).
	Name string `json:"name"`
	// Path is the tool's directory relative to pack.yaml; default: Name.
	// It stays inside the pack directory.
	Path string `json:"path,omitempty"`
}

// Engine is one third-party program a pack bundles.
type Engine struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// License is the engine's SPDX license expression.
	License string `json:"license"`
	// URL is where the engine is downloaded from at build time (https).
	URL string `json:"url,omitempty"`
	// SHA256 is the hex sha256 of the downloaded file per platform; when
	// set it covers every platform of the pack.
	SHA256 map[string]string `json:"sha256,omitempty"`
}

// Requires is what a sensor needs to run a pack.
type Requires struct {
	// SDK is the oldest sensor SDK (semantic version, no leading v) that
	// understands every key the pack and its tools use.
	SDK string `json:"sdk"`
	// Protocol is the adapter protocol major the pack's tools speak.
	Protocol int `json:"protocol"`
}

// Image is how `openctem tool build` builds a pack image.
type Image struct {
	// Base is the base image, pinned by digest (ref@sha256:<hex>).
	Base string `json:"base"`
}

// Error is one problem in a pack. Path is a JSON pointer into pack.yaml,
// or a tool's file for a problem found in a tool.
type Error struct {
	Path    string
	Message string
}

func (e Error) Error() string {
	if e.Path == "" {
		return e.Message
	}
	return e.Path + ": " + e.Message
}

// Errors are every problem found in a pack.
type Errors []Error

func (e Errors) Error() string {
	parts := make([]string, len(e))
	for i, m := range e {
		parts[i] = m.Error()
	}
	return "invalid pack: " + strings.Join(parts, "; ")
}

// Load reads pack.yaml (YAML or JSON) strictly: unknown keys, duplicate
// keys and more than one document are errors. The result is validated on
// its own (Validate); Check validates it against its tools.
func Load(data []byte) (Pack, error) {
	if len(data) > MaxManifestBytes {
		return Pack{}, Errors{{Message: fmt.Sprintf("larger than %d bytes", MaxManifestBytes)}}
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return Pack{}, Errors{{Message: "not YAML: " + err.Error()}}
	}
	var extra any
	if err := dec.Decode(&extra); err == nil {
		return Pack{}, Errors{{Message: "more than one YAML document"}}
	}
	if _, ok := doc.(map[string]any); !ok {
		return Pack{}, Errors{{Message: "not a mapping"}}
	}
	js, err := json.Marshal(doc)
	if err != nil {
		return Pack{}, Errors{{Message: "not representable as JSON: " + err.Error()}}
	}
	var p Pack
	jd := json.NewDecoder(bytes.NewReader(js))
	jd.DisallowUnknownFields()
	if err := jd.Decode(&p); err != nil {
		return Pack{}, Errors{{Message: decodeMessage(err)}}
	}
	if p.APIVersion != APIVersion {
		return Pack{}, Errors{{Path: "/apiVersion", Message: fmt.Sprintf("must be %q", APIVersion)}}
	}
	if err := p.Validate(); err != nil {
		return Pack{}, err
	}
	return p, nil
}

func decodeMessage(err error) string {
	msg := err.Error()
	if f, ok := strings.CutPrefix(msg, "json: unknown field "); ok {
		return "unknown key " + f + " (pack.yaml keys: apiVersion, name, version, description, publisher, license, tier, tools, engines, platforms, requires, image)"
	}
	if strings.Contains(msg, "cannot unmarshal number") && strings.Contains(msg, "of type string") {
		return strings.TrimPrefix(msg, "json: ") + " (YAML reads an unquoted all-digit value as a number: quote it)"
	}
	return strings.TrimPrefix(msg, "json: ")
}

// Validate checks the rules of pack.yaml that need no tool.
func (p Pack) Validate() error {
	var errs Errors
	add := func(path, format string, args ...any) {
		errs = append(errs, Error{Path: path, Message: fmt.Sprintf(format, args...)})
	}
	if !nameRE.MatchString(p.Name) {
		add("/name", "%q must match ^[a-z][a-z0-9-]{1,62}$", p.Name)
	}
	if !versionRE.MatchString(p.Version) {
		add("/version", "%q is not a semantic version (1.2.3, no leading v)", p.Version)
	}
	if len(p.Description) > 1024 {
		add("/description", "longer than 1024 characters")
	}
	if !nameRE.MatchString(p.Publisher) {
		add("/publisher", "%q must match ^[a-z][a-z0-9-]{1,62}$ (a namespace)", p.Publisher)
	}
	if !licenseRE.MatchString(p.License) {
		add("/license", "required: an SPDX license expression such as Apache-2.0")
	}
	switch p.Tier {
	case tool.T0, tool.T1, tool.T2:
	default:
		add("/tier", "%q must be T0 (passive), T1 (active) or T2 (intrusive)", p.Tier)
	}
	if len(p.Tools) == 0 || len(p.Tools) > MaxTools {
		add("/tools", "between 1 and %d tools", MaxTools)
	}
	seen := map[string]bool{}
	for i, t := range p.Tools {
		where := fmt.Sprintf("/tools/%d", i)
		if !nameRE.MatchString(t.Name) {
			add(where+"/name", "%q must match ^[a-z][a-z0-9-]{1,62}$", t.Name)
		}
		if seen[t.Name] {
			add(where+"/name", "%q listed twice", t.Name)
		}
		seen[t.Name] = true
		if t.Path != "" && !localPath(t.Path) {
			add(where+"/path", "%q must be a relative path inside the pack directory (no .., no leading /)", t.Path)
		}
	}
	if len(p.Platforms) == 0 {
		add("/platforms", "required: one or more of %s", strings.Join(Platforms, ", "))
	}
	for i, pl := range p.Platforms {
		if !slices.Contains(Platforms, pl) {
			add(fmt.Sprintf("/platforms/%d", i), "%q is not one of %s", pl, strings.Join(Platforms, ", "))
		}
		if slices.Index(p.Platforms, pl) != i {
			add(fmt.Sprintf("/platforms/%d", i), "%q listed twice", pl)
		}
	}
	if len(p.Engines) > MaxEngines {
		add("/engines", "at most %d engines", MaxEngines)
	}
	engines := map[string]bool{}
	for i, e := range p.Engines {
		where := fmt.Sprintf("/engines/%d", i)
		if !nameRE.MatchString(e.Name) {
			add(where+"/name", "%q must match ^[a-z][a-z0-9-]{1,62}$", e.Name)
		}
		if engines[e.Name] {
			add(where+"/name", "%q listed twice", e.Name)
		}
		engines[e.Name] = true
		if e.Version == "" || len(e.Version) > 64 {
			add(where+"/version", "required (at most 64 characters)")
		}
		if !licenseRE.MatchString(e.License) {
			add(where+"/license", "required: the engine's SPDX license expression")
		}
		if e.URL != "" && (!strings.HasPrefix(e.URL, "https://") || len(e.URL) > 2048 || strings.ContainsAny(e.URL, " \t\r\n")) {
			add(where+"/url", "must be an https URL")
		}
		if len(e.SHA256) > 0 {
			for _, pl := range p.Platforms {
				if _, ok := e.SHA256[pl]; !ok {
					add(where+"/sha256", "no sha256 for %s (a pinned engine covers every platform of the pack)", pl)
				}
			}
			for _, pl := range sortedKeys(e.SHA256) {
				if !slices.Contains(p.Platforms, pl) {
					add(where+"/sha256/"+pl, "not a platform of the pack")
				} else if !sha256RE.MatchString(e.SHA256[pl]) {
					add(where+"/sha256/"+pl, "must be 64 lowercase hex characters")
				}
			}
		}
	}
	if !versionRE.MatchString(p.Requires.SDK) {
		add("/requires/sdk", "required: the oldest sensor SDK version that runs the pack (1.2.3)")
	} else if semver.Compare("v"+sdk.Version, "v"+p.Requires.SDK) < 0 {
		add("/requires/sdk", "needs SDK %s; this is %s", p.Requires.SDK, sdk.Version)
	}
	if p.Requires.Protocol != 1 {
		add("/requires/protocol", "must be 1 (adapter protocol v1)")
	}
	if p.Image != nil && !baseRE.MatchString(p.Image.Base) {
		add("/image/base", "%q must be an image reference pinned by digest (name@sha256:<64 hex>)", p.Image.Base)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

// localPath reports whether p is a clean relative path that stays inside
// its directory.
func localPath(p string) bool {
	if p == "." {
		return true
	}
	return filepath.IsLocal(p) && filepath.ToSlash(filepath.Clean(p)) == p && !strings.Contains(p, "\\")
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ToolPath is the directory of a tool relative to pack.yaml.
func (r ToolRef) ToolPath() string {
	if r.Path != "" {
		return r.Path
	}
	return r.Name
}

// Check validates the pack against its tools, given in any order:
//   - the tools are exactly the ones pack.yaml lists;
//   - the pack's tier equals the highest minimum tier of its tools
//     (tool.Manifest.MinimumTier: declared tier, capability floors, side
//     effects);
//   - every tool speaks the pack's protocol and needs no newer SDK than
//     the pack requires;
//   - every engine a tool names is listed in engines.
func (p Pack) Check(tools []tool.Manifest) error {
	var errs Errors
	add := func(path, format string, args ...any) {
		errs = append(errs, Error{Path: path, Message: fmt.Sprintf(format, args...)})
	}
	byName := map[string]tool.Manifest{}
	for _, m := range tools {
		byName[m.Name] = m
	}
	listed := map[string]bool{}
	highest := tool.T0
	var highestBy []string
	engines := map[string]bool{}
	for _, e := range p.Engines {
		engines[e.Name] = true
	}
	for i, ref := range p.Tools {
		listed[ref.Name] = true
		m, ok := byName[ref.Name]
		if !ok {
			add(fmt.Sprintf("/tools/%d", i), "no tool named %q at %s/tool.yaml", ref.Name, ref.ToolPath())
			continue
		}
		mt := m.MinimumTier()
		switch {
		case tierRank(mt) > tierRank(highest):
			highest, highestBy = mt, []string{m.Name}
		case mt == highest:
			highestBy = append(highestBy, m.Name)
		}
		if m.Protocol.Min > p.Requires.Protocol || (m.Protocol.Max != 0 && m.Protocol.Max < p.Requires.Protocol) {
			add(fmt.Sprintf("/tools/%d", i), "%s speaks protocol %d..%d, not %d", m.Name, m.Protocol.Min, m.Protocol.Max, p.Requires.Protocol)
		}
		if m.SDK != nil && m.SDK.Min != "" && versionRE.MatchString(strings.TrimPrefix(m.SDK.Min, "v")) &&
			semver.Compare("v"+strings.TrimPrefix(m.SDK.Min, "v"), "v"+p.Requires.SDK) > 0 {
			add("/requires/sdk", "%s needs SDK %s or newer; the pack requires only %s", m.Name, m.SDK.Min, p.Requires.SDK)
		}
		if m.Engine != nil && !engines[m.Engine.Name] {
			add("/engines", "%s runs the engine %q, which engines does not list", m.Name, m.Engine.Name)
		}
	}
	for _, m := range tools {
		if !listed[m.Name] {
			add("/tools", "tool %q is in the pack but not listed", m.Name)
		}
	}
	if len(errs) == 0 && p.Tier != highest {
		add("/tier", "is %s but the pack's tools need %s (%s): set tier: %s", p.Tier, highest, strings.Join(highestBy, ", "), highest)
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func tierRank(t tool.Tier) int {
	switch t {
	case tool.T0:
		return 0
	case tool.T1:
		return 1
	case tool.T2:
		return 2
	}
	return -1
}

// Dir is a pack read from a directory.
type Dir struct {
	// Root is the pack directory.
	Root string
	// Pack is its pack.yaml.
	Pack Pack
	// Tools are its tools, in pack.yaml order.
	Tools []tool.Manifest
	// ToolDirs are the tools' directories, in the same order.
	ToolDirs []string
}

// LoadDir reads a pack directory: pack.yaml and the tool.yaml of every
// tool it lists, then checks them together. A tool directory reached
// through a symbolic link is refused: the pack is what its directory
// holds.
func LoadDir(root string) (*Dir, error) {
	path := filepath.Join(root, FileName)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxManifestBytes+1))
	_ = f.Close()
	if err != nil {
		return nil, err
	}
	p, err := Load(data)
	if err != nil {
		return nil, err
	}
	d := &Dir{Root: root, Pack: p}
	var errs Errors
	for i, ref := range p.Tools {
		dir := filepath.Join(root, filepath.FromSlash(ref.ToolPath()))
		if err := noSymlinks(root, ref.ToolPath()); err != nil {
			errs = append(errs, Error{Path: fmt.Sprintf("/tools/%d/path", i), Message: err.Error()})
			continue
		}
		m, err := tool.LoadManifestFile(filepath.Join(dir, "tool.yaml"))
		if err != nil {
			errs = append(errs, Error{Path: fmt.Sprintf("/tools/%d", i), Message: fmt.Sprintf("%s/tool.yaml: %v", ref.ToolPath(), err)})
			continue
		}
		d.Tools = append(d.Tools, m)
		d.ToolDirs = append(d.ToolDirs, dir)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	if err := p.Check(d.Tools); err != nil {
		return nil, err
	}
	return d, nil
}

// noSymlinks refuses a tool path any element of which is a symbolic link.
func noSymlinks(root, rel string) error {
	cur := root
	for _, part := range strings.Split(rel, "/") {
		if part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: no such directory (a tool lives at <path>/tool.yaml)", rel)
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link", rel)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", rel)
		}
	}
	return nil
}

// Canonical is the pack manifest's canonical JSON.
func (p Pack) Canonical() ([]byte, error) { return json.Marshal(p) }

// Digest is "sha256:" + the hex sha256 of the canonical JSON.
func (p Pack) Digest() string {
	b, err := p.Canonical()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Description is the pack as the platform and a catalog show it: pack.yaml
// plus what its tools declare.
type Description struct {
	Name         string      `json:"name"`
	Version      string      `json:"version"`
	Publisher    string      `json:"publisher"`
	Tier         tool.Tier   `json:"tier"`
	Digest       string      `json:"digest"`
	Platforms    []string    `json:"platforms"`
	Requires     Requires    `json:"requires"`
	Capabilities []string    `json:"capabilities"`
	Credentials  []string    `json:"credentials,omitempty"`
	Network      []string    `json:"network"`
	VendorHosts  []string    `json:"vendor_hosts,omitempty"`
	Engines      []Engine    `json:"engines,omitempty"`
	Tools        []ToolEntry `json:"tools"`
}

// ToolEntry is one tool in a Description.
type ToolEntry struct {
	Name         string    `json:"name"`
	Version      string    `json:"version"`
	Digest       string    `json:"digest"`
	MinimumTier  tool.Tier `json:"minimum_tier"`
	Capabilities []string  `json:"capabilities,omitempty"`
}

// Describe derives the pack view from pack.yaml and its tools.
func (d *Dir) Describe() Description {
	out := Description{
		Name: d.Pack.Name, Version: d.Pack.Version, Publisher: d.Pack.Publisher, Tier: d.Pack.Tier,
		Digest: d.Pack.Digest(), Platforms: d.Pack.Platforms, Requires: d.Pack.Requires, Engines: d.Pack.Engines,
		Capabilities: []string{}, Network: []string{}, Tools: []ToolEntry{},
	}
	add := func(list *[]string, v string) {
		if v != "" && !slices.Contains(*list, v) {
			*list = append(*list, v)
		}
	}
	for _, m := range d.Tools {
		e := ToolEntry{Name: m.Name, Version: m.Version, Digest: m.Digest(), MinimumTier: m.MinimumTier()}
		for _, im := range m.Implements {
			e.Capabilities = append(e.Capabilities, im.Capability)
			add(&out.Capabilities, im.Capability)
		}
		for _, c := range m.Permissions.Credentials {
			add(&out.Credentials, c.Name)
		}
		add(&out.Network, string(m.Permissions.Network))
		for _, h := range m.Permissions.VendorHosts {
			add(&out.VendorHosts, h)
		}
		out.Tools = append(out.Tools, e)
	}
	sort.Strings(out.Capabilities)
	sort.Strings(out.Credentials)
	sort.Strings(out.Network)
	sort.Strings(out.VendorHosts)
	return out
}
