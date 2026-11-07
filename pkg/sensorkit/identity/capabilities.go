package identity

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// ErrPlatformUnsignedPairing: the platform's hello says it does not sign
// pairing answers, so this sensor could never save what an approval grants.
// It is found before a pairing request starts, so no administrator approves
// a request that cannot complete.
//
//nolint:staticcheck // ST1005: the sentence is shown to the operator as is
var ErrPlatformUnsignedPairing = errors.New("pairing: this platform does not sign pairing answers (its hello lacks " +
	protov2.FeaturePairingAnswerSigned + "), and this sensor saves only what the platform signed. Upgrade the platform to " +
	pairing.MinPlatformSignedGrant + " or later, or pair with a sensor release from before signed pairing answers " +
	"(built on SDK v0.47.x, for example OpenCTEM sensor v0.39.x)")

// checkPairingCapabilities reads what the platform advertises before a new
// pairing request starts (once per Pair call): GET hello, without
// credentials the platform knows (the request is signed with this
// sensor's key, which is not registered yet). A platform that answers with
// its features and does not list FeaturePairingAnswerSigned cannot pair
// this sensor: ErrPlatformUnsignedPairing. Any other answer (a platform that
// serves hello only to paired sensors, an error) proves nothing, and
// pairing goes on: the signed grant is still verified on the approval
// answer. The capabilities are public facts, a hint only: a forged list
// cannot make the sensor accept an unsigned answer.
func checkPairingCapabilities(ctx context.Context, pc *pairClient, o *PairOptions) error {
	if o.capsChecked {
		return nil
	}
	o.capsChecked = true
	var hello protov2.Hello
	if err := pc.do(ctx, *o, http.MethodGet, protov2.HelloPath, nil, http.StatusOK, &hello); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	if hello.Protocol == 0 && len(hello.Features) == 0 {
		// Not a hello (an empty or foreign document): unknown.
		return nil
	}
	if !slices.Contains(hello.Features, protov2.FeaturePairingAnswerSigned) {
		return ErrPlatformUnsignedPairing
	}
	return nil
}
