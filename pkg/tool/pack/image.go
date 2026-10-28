package pack

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ImageRoot is where a pack image holds the pack directory: pack.yaml at
// ImageRoot/pack.yaml and each tool under it. A sensor reads the pack from
// there, never from the image's entrypoint or command.
const ImageRoot = "/opt/openctem/pack"

// BuildDir is the directory of per-platform files in a pack: the content
// of BuildDir/<os>-<arch>/ replaces or adds files at the same paths in that
// platform's image (a compiled program per architecture). BuildDir itself
// never enters an image.
const BuildDir = ".build"

// Labels a pack image carries in its config (and its index annotations).
const (
	LabelName      = "io.openctem.pack.name"
	LabelVersion   = "io.openctem.pack.version"
	LabelPublisher = "io.openctem.pack.publisher"
	LabelTier      = "io.openctem.pack.tier"
	// LabelDigest is the pack manifest digest (Pack.Digest): a sensor
	// checks the pack.yaml it finds against it.
	LabelDigest = "io.openctem.pack.digest"
)

// Limits of a pack layer.
const (
	MaxLayerFiles = 10000
	MaxLayerBytes = 512 << 20
)

// Labels returns the labels of the pack's image.
func (d *Dir) Labels() map[string]string {
	return map[string]string{
		LabelName: d.Pack.Name, LabelVersion: d.Pack.Version, LabelPublisher: d.Pack.Publisher,
		LabelTier: string(d.Pack.Tier), LabelDigest: d.Pack.Digest(),
		"org.opencontainers.image.title": d.Pack.Name, "org.opencontainers.image.version": d.Pack.Version,
		"org.opencontainers.image.licenses": d.Pack.License,
	}
}

// skipped are names that never enter a pack layer, at any depth.
var skipped = map[string]bool{".git": true, "__pycache__": true, ".DS_Store": true}

type layerFile struct {
	src  string // path on disk
	mode fs.FileMode
	size int64
}

// Layer returns the pack's layer for one platform ("linux/amd64"): an
// uncompressed tar of the pack directory under ImageRoot, with the
// platform's BuildDir overlay applied. The tar is deterministic: entries
// sorted, owned by root, no timestamps, file modes reduced to 0644 or 0755
// (directories 0755). Only regular files and directories are taken; a
// symbolic link, device or other special file anywhere in the pack is an
// error, as is a pack over MaxLayerFiles files or MaxLayerBytes bytes.
func (d *Dir) Layer(platform string) ([]byte, error) {
	files := map[string]layerFile{}
	dirs := map[string]bool{}
	if err := collect(d.Root, "", files, dirs, true); err != nil {
		return nil, err
	}
	overlay := filepath.Join(d.Root, BuildDir, strings.ReplaceAll(platform, "/", "-"))
	if st, err := os.Lstat(overlay); err == nil {
		if !st.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", overlay)
		}
		if err := collect(overlay, "", files, dirs, false); err != nil {
			return nil, err
		}
	}
	if len(files) > MaxLayerFiles {
		return nil, fmt.Errorf("the pack has %d files; at most %d", len(files), MaxLayerFiles)
	}
	var total int64
	for _, f := range files {
		total += f.size
	}
	if total > MaxLayerBytes {
		return nil, fmt.Errorf("the pack holds %d bytes; at most %d", total, MaxLayerBytes)
	}
	// Every directory is an explicit entry: ImageRoot and its parents, and
	// each directory of the pack (the walk records every parent of a file).
	root := strings.TrimPrefix(ImageRoot, "/")
	all := map[string]bool{}
	for p := root; p != "." && p != ""; p = path.Dir(p) {
		all[p] = true
	}
	for rel := range dirs {
		all[path.Join(root, rel)] = true
	}
	dirs = all
	names := make([]string, 0, len(dirs)+len(files))
	for n := range dirs {
		names = append(names, n+"/")
	}
	for rel := range files {
		names = append(names, path.Join(root, rel))
	}
	sort.Strings(names)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, n := range names {
		if strings.HasSuffix(n, "/") {
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: n, Mode: 0o755, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
				return nil, err
			}
			continue
		}
		f := files[strings.TrimPrefix(n, root+"/")]
		mode := int64(0o644)
		if f.mode&0o111 != 0 {
			mode = 0o755
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: n, Mode: mode, Size: f.size, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}); err != nil {
			return nil, err
		}
		if err := copyFile(tw, f); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// collect walks dir and records its regular files (relative slash paths)
// and directories. At the pack root, BuildDir is left out.
func collect(dir, rel string, files map[string]layerFile, dirs map[string]bool, packRoot bool) error {
	entries, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(rel)))
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		if skipped[name] || (packRoot && rel == "" && name == BuildDir) {
			continue
		}
		r := path.Join(rel, name)
		info, err := e.Info()
		if err != nil {
			return err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			return fmt.Errorf("%s is a symbolic link; a pack holds regular files only", r)
		case info.IsDir():
			dirs[r] = true
			if len(dirs) > MaxLayerFiles {
				return fmt.Errorf("more than %d directories", MaxLayerFiles)
			}
			if err := collect(dir, r, files, dirs, packRoot); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			files[r] = layerFile{src: filepath.Join(dir, filepath.FromSlash(r)), mode: info.Mode().Perm(), size: info.Size()}
			if len(files) > MaxLayerFiles {
				return fmt.Errorf("the pack has more than %d files", MaxLayerFiles)
			}
		default:
			return fmt.Errorf("%s is not a regular file or directory", r)
		}
	}
	return nil
}

func copyFile(w io.Writer, f layerFile) error {
	in, err := os.Open(f.src)
	if err != nil {
		return err
	}
	defer in.Close()
	n, err := io.Copy(w, io.LimitReader(in, f.size))
	if err != nil {
		return err
	}
	if n != f.size {
		return fmt.Errorf("%s changed while the layer was written", f.src)
	}
	return nil
}
