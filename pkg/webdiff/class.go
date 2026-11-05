package webdiff

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Shapes of a candidate's last segment.
const (
	// ShapeBare: "/dir/x".
	ShapeBare = "bare"
	// ShapeSlash: "/dir/x/".
	ShapeSlash = "slash"
	// ShapeDot: "/dir/.x".
	ShapeDot = "dot"
	// shapeExt prefixes the extension shapes: "ext:php" for "/dir/x.php".
	shapeExt = "ext:"
)

// maxExtLen bounds an extension that makes a shape of its own; a longer
// one is read as a bare name.
const maxExtLen = 16

// Split splits a candidate path into its directory (ending in "/"), its last
// segment (with its trailing slash, if any) and its shape.
func Split(p string) (dir, name, shape string) {
	trimmed := strings.TrimSuffix(p, "/")
	i := strings.LastIndexByte(trimmed, '/')
	dir, name = trimmed[:i+1], p[i+1:]
	if dir == "" {
		dir = "/"
	}
	return dir, name, ShapeOf(name)
}

// ShapeOf is the shape of a last segment: slash when it ends in "/", dot
// when it starts with ".", ext:<e> when it has an extension of letters and
// digits (lower-cased), else bare.
func ShapeOf(name string) string {
	switch {
	case strings.HasSuffix(name, "/"):
		return ShapeSlash
	case strings.HasPrefix(name, "."):
		return ShapeDot
	}
	if i := strings.LastIndexByte(name, '.'); i > 0 && i < len(name)-1 && len(name)-i-1 <= maxExtLen {
		ext := strings.ToLower(name[i+1:])
		for _, r := range ext {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
				return ShapeBare
			}
		}
		return shapeExt + ext
	}
	return ShapeBare
}

// baselineName is a random name of the shape.
func baselineName(r, shape string) string {
	switch {
	case shape == ShapeSlash:
		return r + "/"
	case shape == ShapeDot:
		return "." + r
	case strings.HasPrefix(shape, shapeExt):
		return r + "." + strings.TrimPrefix(shape, shapeExt)
	}
	return r
}

type classKey struct{ dir, shape string }

// class is the baseline of one (directory, shape).
type class struct {
	gen     int
	samples []Sig
	// lenBand and simBand are the noise bands: the most a missing path's
	// normalised length and simhash vary.
	lenBand, simBand int
	// loose: the baseline bodies disagree too much to compare (titles
	// differ, simhashes far apart); only status, redirect pattern and
	// content-type family are compared.
	loose bool
	// skip is the gap reason when the class cannot be compared at all.
	skip string
}

// maxSimSpread is the simhash spread of baseline bodies past which they are
// not compared.
const maxSimSpread = 24

// class returns the calibrated baseline of (dir, shape), calibrating it when
// it is new or of an older generation.
func (p *Prober) class(ctx context.Context, dir, shape string) (*class, error) {
	k := classKey{dir, shape}
	if c, ok := p.classes[k]; ok && c.gen == p.gen {
		return c, nil
	}
	c := &class{gen: p.gen}
	for len(c.samples) < baselineSamples {
		r := p.name()
		bn := baselineName(r, shape)
		bp := dir + bn
		// The same token forms as a candidate's (candidateTokens): the
		// whole name, then the name without its extension.
		resp, err := p.fetchRetry(ctx, bp, candidateTokens(bn))
		if err != nil {
			if errors.Is(err, ErrStopped) || ctx.Err() != nil {
				return nil, err
			}
			c.skip = GapUnstableBaseline // the baseline could not be taken
			break
		}
		if resp.refused != "" {
			if err := p.refusal(resp); err != nil {
				return nil, err
			}
			c.skip = GapScopeFiltered
			break
		}
		if resp.edge.State.Stops() {
			return nil, p.stop(GapEdgeProtected)
		}
		if throttledAnswer(resp) {
			// Still rate-limited after the retries: a baseline taken now
			// would be a rate-limit page.
			return nil, p.stop(GapThrottled)
		}
		c.samples = append(c.samples, resp.sig)
	}
	if c.skip == "" {
		c.derive()
	}
	p.classes[k] = c
	if dir == "/" && shape == ShapeBare && c.skip == "" {
		p.rootChecks(c)
	}
	return c, nil
}

// rootChecks reads the origin-wide behavior from the root's bare
// baseline: a login wall, and a catch-all (a random path answers like /).
func (p *Prober) rootChecks(c *class) {
	b := c.samples[0]
	if b.Status == http.StatusUnauthorized || (isRedirect(b.Status) && loginPattern(b.Location)) {
		p.gaps[GapAuthWall] = max(p.gaps[GapAuthWall], 1)
	}
	if p.root != nil && b.Status >= 200 && b.Status < 300 && c.compare(*p.root) == Same {
		p.catchAll = true
	}
}

// derive computes the bands of a calibrated class, or marks it skipped when
// its samples disagree on status, redirect pattern or content-type family.
func (c *class) derive() {
	b := c.samples[0]
	for _, s := range c.samples[1:] {
		if s.Status != b.Status || s.Location != b.Location || s.Family != b.Family {
			c.skip = GapUnstableBaseline
			return
		}
	}
	minL, maxL, sum := b.Length, b.Length, 0
	maxD := 0
	for i, s := range c.samples {
		minL, maxL, sum = min(minL, s.Length), max(maxL, s.Length), sum+s.Length
		for _, t := range c.samples[i+1:] {
			maxD = max(maxD, Distance(s.SimHash, t.SimHash))
		}
		if s.Title != b.Title {
			c.loose = true
		}
	}
	mean := sum / len(c.samples)
	c.lenBand = maxL - minL + max(32, mean/50)
	c.simBand = maxD + 3
	if maxD > maxSimSpread {
		c.loose = true
	}
}

// compare is the verdict of an answer against the class: different on
// status, redirect pattern or content-type family; then, unless the class is
// loose, different when its length is outside the band of every sample and
// its simhash is too, or its title differs.
func (c *class) compare(s Sig) Verdict {
	b := c.samples[0]
	if s.Status != b.Status || s.Location != b.Location || s.Family != b.Family {
		return Different
	}
	if c.loose {
		return Same
	}
	if s.Title != b.Title {
		return Different
	}
	lenOut, simOut := true, true
	for _, t := range c.samples {
		if abs(s.Length-t.Length) <= c.lenBand {
			lenOut = false
		}
		if Distance(s.SimHash, t.SimHash) <= c.simBand {
			simOut = false
		}
	}
	if lenOut && simOut {
		return Different
	}
	return Same
}

// consistent reports whether the repeat of a different answer is the same
// answer: status, redirect pattern and family equal, and the body within
// the class's bands of the first (or the same hash).
func (c *class) consistent(a, b Sig) bool {
	if a.Status != b.Status || a.Location != b.Location || a.Family != b.Family {
		return false
	}
	if a.Hash == b.Hash {
		return true
	}
	band := max(c.lenBand, 32+a.Length/50)
	return abs(a.Length-b.Length) <= band || Distance(a.SimHash, b.SimHash) <= max(c.simBand, 3)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
