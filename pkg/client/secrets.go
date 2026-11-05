package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/openctemio/contract/secretref"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sealedmsg"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// ErrSecretsNotKeyBound is the error of a fetch by a client without a
// key-bound signing identity: a reply key in a bearer-authenticated body
// is not bound to the sensor, so such a client never asks.
var ErrSecretsNotKeyBound = errors.New("secrets: only a key-bound sensor (signed requests) fetches secrets")

// secretsRetries is how often a transient failure of a fetch is retried:
// every attempt sends the same bytes and the same reply key.
const secretsRetries = 2

// Secrets fetches, for one task of command cmdID, the values of refs (ids
// of set, the job's verified secret list) from POST
// /commands/{id}/secrets (contract secretref). The request body is
// marshaled once and sent as exactly those bytes in a request the
// client's key-bound identity signs; it carries the lease epoch the
// client holds for the command and a single-use reply key. The answer is
// opened with that key under secretref.Info, checked against set
// (secretref.Answer.Check) and returned; the private key is dropped. The
// values are never logged or kept. Any failure (no lease, a refusal, a
// gateway 404, an answer that does not open or check) is an error: the
// caller uses no platform value then.
func (c *Client) Secrets(ctx context.Context, cmdID, task string, set secretref.Set, refs []string) (*secretref.Answer, error) {
	if !c.signed {
		return nil, ErrSecretsNotKeyBound
	}
	cmd, err := uuid.Parse(cmdID)
	if err != nil {
		return nil, errors.New("secrets: the command id is not a UUID")
	}
	sensor, err := uuid.Parse(c.sensorID)
	if err != nil {
		return nil, errors.New("secrets: this sensor has no platform sensor id")
	}
	epoch := int64(c.leases.epoch(cmdID))
	if epoch < 1 {
		return nil, errors.New("secrets: no lease is held on the command")
	}
	if err := set.Validate(); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	for _, id := range refs {
		if _, ok := set.Lookup(id); !ok {
			return nil, fmt.Errorf("secrets: %s is not a ref of the job", id)
		}
	}
	key, err := sealedmsg.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("secrets: reply key: %w", err)
	}
	pub := key.Public().Bytes()
	req := secretref.FetchRequest{LeaseEpoch: epoch, Task: task, Refs: refs,
		ReplyKey: base64.RawURLEncoding.EncodeToString(pub)}
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	var sa secretref.SealedAnswer
	path := protov2.PathPrefix + protov2.CommandsPath + "/" + url.PathEscape(cmdID) + "/" + protov2.SecretsAction
	hdr, err := c.v2JSONBody(ctx, http.MethodPost, path, body, &sa, nil, secretsRetries)
	if err != nil {
		return nil, err
	}
	if mt, _, perr := mime.ParseMediaType(hdr.Get("Content-Type")); perr != nil || mt != secretref.ContentType {
		return nil, errors.New("secrets: the answer is not a sealed secrets answer")
	}
	if err := sa.Validate(pub); err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	sealed, err := sa.SealedBytes()
	if err != nil {
		return nil, fmt.Errorf("secrets: %w", err)
	}
	info := secretref.Info(sensor.String(), cmd.String(), epoch, body)
	// The single-use key lives only in this call: it is never stored, and
	// nothing references it once the answer is open.
	pt, err := sealedmsg.OpenWithKey(key, info, sealed)
	if err != nil {
		return nil, errors.New("secrets: the answer does not open with this request's key")
	}
	var ans secretref.Answer
	err = json.Unmarshal(pt, &ans)
	clear(pt)
	if err != nil {
		return nil, errors.New("secrets: the opened answer cannot be read")
	}
	if err := ans.Check(set, cmd.String(), epoch, refs, time.Now()); err != nil {
		core.ZeroAnswer(&ans)
		return nil, fmt.Errorf("secrets: %w", err)
	}
	return &ans, nil
}

var _ core.SecretsFetcher = (*Client)(nil)
