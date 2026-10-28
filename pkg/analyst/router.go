package analyst

import "errors"

// ModelTier is the size of model a playbook asks for.
type ModelTier string

// Tiers. Routine work goes to the small tier; the large tier handles hard
// cases and escalations.
const (
	TierSmall ModelTier = "small"
	TierLarge ModelTier = "large"
)

// ModelChoice is a provider and a model name.
type ModelChoice struct {
	Provider Provider
	Model    string
}

// Router picks the model of a run. The platform's model policy (allowlist,
// region, the organization's own key) is applied before a worker routes: a
// router only chooses among what the job allows.
type Router interface {
	Route(tier ModelTier) (ModelChoice, error)
}

// ErrNoModel is returned when no model is configured for a tier.
var ErrNoModel = errors.New("analyst: no model for this tier")

// TierRouter maps each tier to one model. A missing large model falls back
// to the small one (never the other way round: a hard case must not silently
// run on nothing).
type TierRouter struct {
	Small ModelChoice
	Large ModelChoice
}

// Route implements Router.
func (t TierRouter) Route(tier ModelTier) (ModelChoice, error) {
	switch tier {
	case TierLarge:
		if t.Large.Provider != nil {
			return t.Large, nil
		}
		if t.Small.Provider != nil {
			return t.Small, nil
		}
	case TierSmall, "":
		if t.Small.Provider != nil {
			return t.Small, nil
		}
	}
	return ModelChoice{}, ErrNoModel
}
