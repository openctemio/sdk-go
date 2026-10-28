package toolcli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/openctemio/sdk-go/pkg/tool/pack"
)

// buildOptions are the inputs of one pack image build.
type buildOptions struct {
	Platforms []string // default: the pack's
	Base      string   // default: pack.yaml image.base
	Output    string   // OCI image layout directory
	Push      string   // registry reference to push to
	Remote    []remote.Option
}

func cmdBuild(args []string, stdout, stderr io.Writer) int {
	fs := flags("build", stderr)
	platforms := fs.String("platform", "", "comma-separated platforms to build (default: the pack's platforms)")
	base := fs.String("base", "", "base image pinned by digest (default: pack.yaml image.base)")
	output := fs.String("output", "", "write the image as an OCI image layout in this directory")
	push := fs.String("push", "", "push the image to this registry reference (repository[:tag])")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 1 || (*output == "") == (*push == "") {
		_, _ = fmt.Fprint(stderr, usage)
		_, _ = fmt.Fprintln(stderr, "build needs exactly one of --output or --push")
		return ExitUsage
	}
	dir, ok := packDir(first(pos))
	if !ok {
		_, _ = fmt.Fprintf(stderr, "%s has no pack.yaml (openctem tool init writes one; see docs/tool-packs.md)\n", orDot(first(pos)))
		return ExitUsage
	}
	opts := buildOptions{Base: *base, Output: *output, Push: *push,
		Remote: []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}}
	if *platforms != "" {
		opts.Platforms = strings.Split(*platforms, ",")
	}
	digest, err := buildPack(dir, opts, stdout)
	if err != nil {
		var pe pack.Errors
		if errors.As(err, &pe) {
			printPackError(stdout, dir, err)
		} else {
			_, _ = fmt.Fprintf(stdout, "build: %v\n", err)
		}
		_, _ = fmt.Fprintln(stdout, "FAIL")
		return ExitFail
	}
	where := *output
	if *push != "" {
		where = *push
	}
	_, _ = fmt.Fprintf(stdout, "built %s@%s\nsign and pin this digest, never a tag: cosign sign <repository>@%s\n", where, digest, digest)
	return ExitOK
}

func orDot(s string) string {
	if s == "" {
		return "."
	}
	return s
}

// buildPack builds the pack image: for each platform, the base image's
// manifest for that platform plus one layer with the pack (pack.Layer),
// with the pack's labels, no entrypoint or command, a non-root user and no
// timestamps; all platforms in one image index. The build is
// reproducible: the same pack and base give the same index digest. It
// returns that digest.
func buildPack(dir string, o buildOptions, stdout io.Writer) (v1.Hash, error) {
	d, err := pack.LoadDir(dir)
	if err != nil {
		return v1.Hash{}, err
	}
	baseRef := o.Base
	if baseRef == "" {
		if d.Pack.Image == nil {
			return v1.Hash{}, errors.New("pack.yaml has no image.base and no --base was given")
		}
		baseRef = d.Pack.Image.Base
	}
	if !strings.Contains(baseRef, "@sha256:") {
		return v1.Hash{}, fmt.Errorf("base %q must be pinned by digest (name@sha256:<hex>)", baseRef)
	}
	platforms := o.Platforms
	if len(platforms) == 0 {
		platforms = d.Pack.Platforms
	}
	for _, p := range platforms {
		if !slices.Contains(d.Pack.Platforms, p) {
			return v1.Hash{}, fmt.Errorf("platform %q is not one of the pack's (%s)", p, strings.Join(d.Pack.Platforms, ", "))
		}
	}
	ref, err := name.ParseReference(baseRef)
	if err != nil {
		return v1.Hash{}, fmt.Errorf("base %q: %w", baseRef, err)
	}
	desc, err := remote.Get(ref, o.Remote...)
	if err != nil {
		return v1.Hash{}, fmt.Errorf("fetch base %s: %w", baseRef, err)
	}
	labels := d.Labels()
	var adds []mutate.IndexAddendum
	for _, p := range platforms {
		img, err := baseFor(desc, p)
		if err != nil {
			return v1.Hash{}, err
		}
		tarBytes, err := d.Layer(p)
		if err != nil {
			return v1.Hash{}, err
		}
		layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(tarBytes)), nil
		})
		if err != nil {
			return v1.Hash{}, err
		}
		img, err = mutate.Append(img, mutate.Addendum{Layer: layer, History: v1.History{
			CreatedBy: "openctem tool build", Comment: fmt.Sprintf("pack %s %s", d.Pack.Name, d.Pack.Version)}})
		if err != nil {
			return v1.Hash{}, err
		}
		cf, err := img.ConfigFile()
		if err != nil {
			return v1.Hash{}, err
		}
		cfg := cf.Config.DeepCopy()
		if cfg.Labels == nil {
			cfg.Labels = map[string]string{}
		}
		for k, v := range labels {
			cfg.Labels[k] = v
		}
		// The sensor starts each tool from its tool.yaml; nothing in the
		// image starts by itself, and nothing runs as root.
		cfg.Entrypoint, cfg.Cmd = nil, nil
		cfg.WorkingDir = pack.ImageRoot
		cfg.User = "65532:65532"
		img, err = mutate.Config(img, *cfg)
		if err != nil {
			return v1.Hash{}, err
		}
		img, err = mutate.CreatedAt(img, v1.Time{})
		if err != nil {
			return v1.Hash{}, err
		}
		os, arch, _ := strings.Cut(p, "/")
		adds = append(adds, mutate.IndexAddendum{Add: img, Descriptor: v1.Descriptor{
			Platform: &v1.Platform{OS: os, Architecture: arch}}})
		_, _ = fmt.Fprintf(stdout, "%s: %d-byte pack layer\n", p, len(tarBytes))
	}
	idx := mutate.IndexMediaType(mutate.AppendManifests(empty.Index, adds...), types.OCIImageIndex)
	idx = mutate.Annotations(idx, labels).(v1.ImageIndex)
	digest, err := idx.Digest()
	if err != nil {
		return v1.Hash{}, err
	}
	if o.Output != "" {
		p, err := layout.Write(o.Output, empty.Index)
		if err != nil {
			return v1.Hash{}, err
		}
		if err := p.AppendIndex(idx, layout.WithAnnotations(map[string]string{
			"org.opencontainers.image.ref.name": d.Pack.Version})); err != nil {
			return v1.Hash{}, err
		}
	}
	if o.Push != "" {
		ref, err := name.ParseReference(o.Push)
		if err != nil {
			return v1.Hash{}, fmt.Errorf("push %q: %w", o.Push, err)
		}
		if err := remote.WriteIndex(ref, idx, o.Remote...); err != nil {
			return v1.Hash{}, fmt.Errorf("push %s: %w", o.Push, err)
		}
	}
	return digest, nil
}

// baseFor is the base image for one platform: from an index, its manifest
// for that platform; a single image only when it is that platform.
func baseFor(desc *remote.Descriptor, platform string) (v1.Image, error) {
	os, arch, _ := strings.Cut(platform, "/")
	want := v1.Platform{OS: os, Architecture: arch}
	if desc.MediaType.IsIndex() {
		idx, err := desc.ImageIndex()
		if err != nil {
			return nil, err
		}
		im, err := idx.IndexManifest()
		if err != nil {
			return nil, err
		}
		for _, m := range im.Manifests {
			if m.Platform != nil && m.Platform.OS == want.OS && m.Platform.Architecture == want.Architecture &&
				(want.Architecture != "arm64" || m.Platform.Variant == "" || m.Platform.Variant == "v8") {
				return idx.Image(m.Digest)
			}
		}
		return nil, fmt.Errorf("the base image has no %s manifest", platform)
	}
	img, err := desc.Image()
	if err != nil {
		return nil, err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	if cf.OS != want.OS || cf.Architecture != want.Architecture {
		return nil, fmt.Errorf("the base image is %s/%s, not %s (use a multi-platform base or --platform)", cf.OS, cf.Architecture, platform)
	}
	return img, nil
}
