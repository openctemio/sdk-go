package ctlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/contract/ctlookup"
)

// ErrTargetMismatch: a lookup job's input asks about another domain than
// the job's signed target.
var ErrTargetMismatch = errors.New("ctlog: the input's domain is not the job's target")

// Job answers one lookup job (pkg/lookupjob Handler) of capability
// lookup.ct@1 for tenantID. target is the job's signed target; the input
// must ask about exactly that domain.
func (c *Client) Job(ctx context.Context, tenantID, target string, input json.RawMessage) (any, error) {
	var in ctlookup.Input
	dec := json.NewDecoder(bytes.NewReader(input))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("%w: input: %w", ctlookup.ErrInvalid, err)
	}
	in, err := ctlookup.CheckInput(in)
	if err != nil {
		return nil, err
	}
	t, err := ctlookup.NormalizeDomain(target)
	if err != nil || t != in.Domain {
		return nil, ErrTargetMismatch
	}
	if tenantID == "" {
		return nil, errors.New("ctlog: a lookup job needs its organization")
	}
	return c.Lookup(ctx, tenantID, in)
}
