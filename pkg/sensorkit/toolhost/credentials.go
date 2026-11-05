package toolhost

import (
	"context"
	"regexp"
	"slices"

	"github.com/openctemio/contract/secretref"

	"github.com/openctemio/sdk-go/internal/toolwire"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Credentials of one task (contract secretref). A tool receives only the
// slots its manifest declares (permissions.credentials), inside its run
// message (the stdin pipe), never in its environment or argv. A slot is
// filled, in order:
//
//   - by the platform's value, when the job's verified secret list names a
//     ref for the slot, the slot's local policy is not "only", and the
//     task passes the gates below;
//   - else by the operator's local value (RunOptions.Credentials), when
//     the slot's local policy allows it: "allow" or "only" from the signed
//     list; "never" on a shared sensor whatever the job says;
//   - else not at all, and a required slot fails the task (secret_missing).
//
// A fetch that fails, a refusal or a gateway answer gives no platform
// value and changes nothing else: no other source is tried.
//
// Gates on platform values: a task that may reach any public host
// (network egress-proxy) gets none; a provider key goes only to a task of
// network vendor of a tool its provider lists; on a shared sensor a task
// gets none without Landlock (an organization's sensor delivers and says
// so). A delivered provider key (platform or local) adds its audience
// (secretref.Provider.Audience) to the hosts a vendor task may reach: a
// keyed host is reachable only when its key was delivered. A key its
// provider's rules refuse is dropped, naming the slot only.

// secretsFetchTask is the audit name of a task's fetch when the task id is
// not a valid one.
const secretsFetchTask = "task"

var fetchTaskRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// taskSecrets is what one task receives.
type taskSecrets struct {
	creds []toolwire.Credential
	// values are the delivered values (scrubbed from every output).
	values []string
	// keyed are the audiences of delivered provider keys (vendor hosts).
	keyed []string
	// lines say what was not delivered or how (never a value).
	lines []LogLine
}

// providerFor is the registry provider of a tool slot: the ref's provider
// for a provider key ref, else the provider whose id is the slot (a local
// key in a provider slot); only when the provider lists the tool.
func providerFor(m tool.Manifest, slot string, ref *secretref.Ref) (secretref.Provider, bool) {
	id := slot
	if ref != nil {
		if ref.Kind != secretref.KindProviderKey {
			return secretref.Provider{}, false
		}
		id = ref.Ref
	}
	p, ok := secretref.LookupProvider(id)
	if !ok || !slices.Contains(p.Tools, m.Name) {
		return secretref.Provider{}, false
	}
	return p, true
}

// secretsFor resolves the credentials of one task of m. A *tool.Error
// fails the task (a required slot without a value).
func (h *Host) secretsFor(ctx context.Context, m tool.Manifest, task tool.Task, local map[string]string) (*taskSecrets, *tool.Error) {
	out := &taskSecrets{}
	if len(m.Permissions.Credentials) == 0 {
		return out, nil
	}
	js := core.JobSecretsFrom(ctx)
	set, hasSet := js.Set()
	// Whether this task may receive platform values at all.
	platform, why := hasSet, ""
	switch {
	case !hasSet:
	case m.Permissions.Network == tool.NetEgressProxy:
		platform, why = false, "the tool may reach any public host (network egress-proxy), so it receives no platform secrets"
	case h.backend().Status().Landlock == 0 && (h.Shared || js.Shared()):
		platform, why = false, "a shared sensor delivers platform secrets only to tasks confined by Landlock, and Landlock is not available"
	}
	platformLine := func(slot string) {
		if why != "" {
			out.lines = append(out.lines, LogLine{Level: "warn", Msg: "platform secret not delivered: " + why,
				Fields: map[string]any{"tool": m.Name, "slot": slot}})
		}
	}

	type slotPlan struct {
		req    tool.CredentialReq
		ref    *secretref.Ref
		policy string
		ask    bool
	}
	plans := make([]slotPlan, 0, len(m.Permissions.Credentials))
	var ask []string
	for _, req := range m.Permissions.Credentials {
		sp := slotPlan{req: req, policy: core.LocalSecretPolicy(js, req.Name, h.Shared)}
		if hasSet {
			if r, ok := set.ForSlot(req.Name); ok && r.Consumer == secretref.ConsumerTool && secretref.KnownKind(r.Kind) {
				sp.ref = &r
			}
		}
		if sp.ref != nil && sp.policy != secretref.LocalOnly {
			switch _, provider := providerFor(m, req.Name, sp.ref); {
			case !platform:
				platformLine(req.Name)
			case !provider:
				out.lines = append(out.lines, LogLine{Level: "warn", Msg: "platform secret not delivered: the slot's provider does not list this tool",
					Fields: map[string]any{"tool": m.Name, "slot": req.Name}})
			case m.Permissions.Network != tool.NetVendor:
				out.lines = append(out.lines, LogLine{Level: "warn", Msg: "platform secret not delivered: a provider key goes only to a tool of network vendor",
					Fields: map[string]any{"tool": m.Name, "slot": req.Name}})
			default:
				sp.ask = true
				ask = append(ask, sp.ref.ID)
			}
		}
		plans = append(plans, sp)
	}

	platformValues := map[string]string{}
	if len(ask) > 0 {
		if h.backend().Status().Landlock == 0 {
			out.lines = append(out.lines, LogLine{Level: "warn", Msg: "platform secrets are delivered to a task that Landlock does not confine (not available on this host)",
				Fields: map[string]any{"tool": m.Name}})
		}
		name := task.ID
		if !fetchTaskRE.MatchString(name) {
			name = secretsFetchTask
		}
		ans, err := js.Fetch(ctx, name, ask)
		if err != nil {
			out.lines = append(out.lines, LogLine{Level: "warn", Msg: "the organization's secrets could not be fetched; the task runs without them",
				Fields: map[string]any{"tool": m.Name, "error": err.Error()}})
		} else {
			for _, sec := range ans.Secrets {
				ref, ok := set.Lookup(sec.ID)
				if !ok || ref.Kind != secretref.KindProviderKey {
					continue
				}
				if v, err := secretref.DecodeProviderKey(ref, sec.Value); err == nil {
					platformValues[ref.Slot] = v.Key
				}
			}
			core.ZeroAnswer(ans)
		}
	}

	provenance := map[string]string{}
	for _, sp := range plans {
		slot := sp.req.Name
		v, from := "", ""
		if sp.ask {
			v, from = platformValues[slot], "platform"
		}
		if v == "" && (sp.policy == secretref.LocalAllow || sp.policy == secretref.LocalOnly) {
			v, from = local[slot], "local"
		}
		if v != "" {
			if p, ok := providerFor(m, slot, sp.ref); ok {
				aud, err := p.Audience(v)
				if err != nil {
					out.lines = append(out.lines, LogLine{Level: "warn", Msg: "a key its provider's rules refuse was not delivered",
						Fields: map[string]any{"tool": m.Name, "slot": slot}})
					v = ""
				} else {
					out.keyed = append(out.keyed, aud...)
				}
			}
		}
		if v == "" {
			if sp.req.Required || (sp.ref != nil && sp.ref.Required) {
				return nil, tool.AsError(tool.Invalid("%s: credential %q has no value for this task", secretref.RefusalSecretMissing, slot))
			}
			continue
		}
		provenance[slot] = from
		out.creds = append(out.creds, toolwire.Credential{Name: slot, Value: v})
		out.values = append(out.values, v)
	}
	if len(provenance) > 0 {
		out.lines = append(out.lines, LogLine{Level: "info", Msg: "credentials delivered (source by slot)",
			Fields: map[string]any{"tool": m.Name, "slots": provenance}})
	}
	slices.Sort(out.keyed)
	out.keyed = slices.Compact(out.keyed)
	return out, nil
}
