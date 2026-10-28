package toolcli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/pack"
)

// Base images a scaffold's pack.yaml names, pinned by digest. A pack image
// is the base plus one layer with the pack's files.
const (
	pythonBaseImage = "public.ecr.aws/docker/library/python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"
	staticBaseImage = "gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab"
)

// packDir returns the pack directory an argument names: a directory with a
// pack.yaml, or a pack.yaml file. A directory without one is a tool.
func packDir(arg string) (string, bool) {
	if arg == "" {
		arg = "."
	}
	st, err := os.Stat(arg)
	if err != nil {
		return "", false
	}
	dir := arg
	if !st.IsDir() {
		if filepath.Base(arg) != pack.FileName {
			return "", false
		}
		dir = filepath.Dir(arg)
	}
	if _, err := os.Stat(filepath.Join(dir, pack.FileName)); err != nil {
		return "", false
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return dir, true
}

// printPackError prints every problem of a pack, one per line.
func printPackError(w io.Writer, dir string, err error) {
	var pe pack.Errors
	if errors.As(err, &pe) {
		for _, e := range pe {
			_, _ = fmt.Fprintf(w, "%s: %s\n", filepath.Join(dir, pack.FileName), e.Error())
		}
		return
	}
	_, _ = fmt.Fprintf(w, "%s: %v\n", dir, err)
}

func validatePack(dir string, stdout io.Writer) int {
	d, err := pack.LoadDir(dir)
	if err != nil {
		printPackError(stdout, dir, err)
		_, _ = fmt.Fprintln(stdout, "INVALID")
		return ExitFail
	}
	for i, m := range d.Tools {
		path := filepath.Join(d.ToolDirs[i], "tool.yaml")
		for _, l := range conformance.LintDescriptor(m) {
			_, _ = fmt.Fprintf(stdout, "%s: %s\n", path, l)
		}
		_, _ = fmt.Fprintf(stdout, "%s %s: valid (%s)\n", m.Name, m.Version, m.Digest())
	}
	_, _ = fmt.Fprintf(stdout, "pack %s %s (%s, %d tools): valid (%s)\n", d.Pack.Name, d.Pack.Version, d.Pack.Tier, len(d.Tools), d.Pack.Digest())
	return ExitOK
}

func testPack(dir string, opts conformance.ContractOptions, update bool, stdout io.Writer) int {
	d, err := pack.LoadDir(dir)
	if err != nil {
		printPackError(stdout, dir, err)
		_, _ = fmt.Fprintln(stdout, "FAIL")
		return ExitFail
	}
	code := ExitOK
	for i, m := range d.Tools {
		_, _ = fmt.Fprintf(stdout, "== %s\n", m.Name)
		if Test(filepath.Join(d.ToolDirs[i], "tool.yaml"), opts, update, stdout) != ExitOK {
			code = ExitFail
		}
	}
	return code
}

func describePack(dir string, asJSON bool, stdout, stderr io.Writer) int {
	d, err := pack.LoadDir(dir)
	if err != nil {
		printPackError(stderr, dir, err)
		return ExitFail
	}
	desc := d.Describe()
	if asJSON {
		out, _ := json.Marshal(desc)
		_, _ = fmt.Fprintln(stdout, string(out))
		return ExitOK
	}
	_, _ = fmt.Fprintf(stdout, "pack %s %s by %s (%s)\ndigest %s\nplatforms %s\nrequires sdk %s, protocol %d\n",
		desc.Name, desc.Version, desc.Publisher, desc.Tier, desc.Digest, strings.Join(desc.Platforms, ", "), desc.Requires.SDK, desc.Requires.Protocol)
	for _, t := range desc.Tools {
		_, _ = fmt.Fprintf(stdout, "tool %s %s (%s) %s\n", t.Name, t.Version, t.MinimumTier, strings.Join(t.Capabilities, ", "))
	}
	if len(desc.Credentials) > 0 {
		_, _ = fmt.Fprintf(stdout, "credentials %s\n", strings.Join(desc.Credentials, ", "))
	}
	_, _ = fmt.Fprintf(stdout, "network %s\n", strings.Join(desc.Network, ", "))
	for _, e := range desc.Engines {
		_, _ = fmt.Fprintf(stdout, "engine %s %s (%s)\n", e.Name, e.Version, e.License)
	}
	return ExitOK
}

// packYAML is the pack.yaml of a scaffold: a pack of the one new tool, in
// the scaffold's own directory.
func packYAML(kind string, m tool.Manifest) string {
	var b strings.Builder
	b.WriteString("# The pack is what is versioned, built into an image, signed and delivered\n")
	b.WriteString("# to sensors (docs/tool-packs.md). Each tool keeps its facts in tool.yaml.\n")
	fmt.Fprintf(&b, "apiVersion: %s\nname: %s\nversion: 0.1.0\n", pack.APIVersion, m.Name)
	b.WriteString("# Your namespace in a catalog, and the license of the pack's own files.\n")
	b.WriteString("publisher: example\nlicense: Apache-2.0\n")
	b.WriteString("# The highest minimum tier of the tools (T0 passive, T1 active, T2 intrusive);\n")
	b.WriteString("# openctem tool validate says when it no longer matches.\n")
	fmt.Fprintf(&b, "tier: %s\ntools:\n  - name: %s\n    path: .\n", m.MinimumTier(), m.Name)
	if m.Engine != nil {
		b.WriteString("# Every program a tool runs as its engine. Add url and a sha256 per\n# platform for a program the build downloads.\n")
		fmt.Fprintf(&b, "engines:\n  - name: %s\n    version: 0.1.0\n    license: Apache-2.0\n", m.Engine.Name)
	}
	b.WriteString("platforms: [linux/amd64, linux/arm64]\n")
	fmt.Fprintf(&b, "requires:\n  sdk: %s\n  protocol: %d\n", scaffoldSDKVersion(), tool.ProtocolVersion)
	switch kind {
	case KindPython:
		fmt.Fprintf(&b, "image:\n  base: %s\n", pythonBaseImage)
	case KindGo:
		fmt.Fprintf(&b, "image:\n  base: %s\n", staticBaseImage)
	default:
		b.WriteString("# image:\n#   base: <an image with what bin/ needs, pinned by digest: name@sha256:...>\n")
	}
	return b.String()
}
