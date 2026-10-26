package main

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// This local storage fence records the selected authority generation without
// changing a native identity, scope hash, Node pin or Hub credential.
type codexDomainBinding struct {
	LocalDomainVersion int                       `json:"local_domain_version,omitempty"`
	LocalDomain        wire.LocalDomainSelection `json:"local_domain,omitzero"`
	codexEndpointGroupsBinding
}

// The private cache uses distinct names for the registration binding fence so
// embedding it in a session or outbox cannot shadow their binding_id fields.
// These coordinates are only copied from an authenticated consumed context.
type codexEndpointGroupsBinding struct {
	EndpointGroupsVersion    int    `json:"endpoint_groups_version,omitempty"`
	RegistrationDigest       string `json:"registration_digest,omitempty"`
	RegistrationRevision     uint64 `json:"registration_revision,omitempty"`
	RegistrationBindingID    string `json:"registration_binding_id,omitempty"`
	RegistrationBindingEpoch uint64 `json:"registration_binding_epoch,omitempty"`
	RegistrationNodeKeyEpoch uint64 `json:"registration_node_key_epoch,omitempty"`
}

func (b codexEndpointGroupsBinding) validate() error {
	if b.EndpointGroupsVersion != 1 || !localContextHex(b.RegistrationDigest, 64) || b.RegistrationRevision == 0 || b.RegistrationRevision >= 1<<63 ||
		!localContextText(b.RegistrationBindingID, 128) || strings.ContainsAny(b.RegistrationBindingID, "/\\") || strings.IndexFunc(b.RegistrationBindingID, unicode.IsSpace) >= 0 ||
		b.RegistrationBindingEpoch == 0 || b.RegistrationBindingEpoch >= 1<<63 || b.RegistrationNodeKeyEpoch == 0 || b.RegistrationNodeKeyEpoch >= 1<<63 {
		return errCodexMCPContext
	}
	return nil
}

func (binding codexDomainBinding) validate() error {
	if binding.codexEndpointGroupsBinding != (codexEndpointGroupsBinding{}) {
		if binding.LocalDomainVersion != 0 || binding.LocalDomain != (wire.LocalDomainSelection{}) {
			return errCodexMCPContext
		}
		return binding.codexEndpointGroupsBinding.validate()
	}
	if binding.LocalDomainVersion == 0 && binding.LocalDomain == (wire.LocalDomainSelection{}) {
		return nil
	}
	if binding.LocalDomainVersion != 1 || wire.ValidateLocalDomainSelection(binding.LocalDomain) != nil {
		return errCodexMCPContext
	}
	return nil
}

func (binding codexDomainBinding) stored() string {
	if binding == (codexDomainBinding{}) {
		return ""
	}
	raw, _ := json.Marshal(binding)
	return string(raw)
}

func decodeCodexDomainBinding(raw string) (codexDomainBinding, error) {
	var binding codexDomainBinding
	if raw == "" {
		return binding, nil
	}
	if len(raw) > 1024 || decodeLocalBridgeRequest([]byte(raw), &binding) != nil || binding.validate() != nil || binding.stored() != raw {
		return codexDomainBinding{}, errCodexMCPContext
	}
	return binding, nil
}

// A queued domain operation also keeps the exact native admission binding.
// A later Join under the same policy cannot lend it a replacement session.
type codexOutboxBinding struct {
	codexDomainBinding
	NativeBindingID        string                            `json:"native_binding_id"`
	NativeBindingEpoch     uint64                            `json:"native_binding_epoch"`
	EndpointGroupAuthority wire.EndpointGroupCurrentEndpoint `json:"endpoint_group_authority,omitzero"`
}

func (binding codexOutboxBinding) validate() error {
	if binding == (codexOutboxBinding{}) {
		return nil
	}
	if binding.codexDomainBinding.validate() != nil || !localContextText(binding.NativeBindingID, 256) || binding.NativeBindingEpoch == 0 || binding.NativeBindingEpoch >= 1<<63 {
		return errCodexMCPContext
	}
	if binding.EndpointGroupsVersion != 0 {
		if binding.NativeBindingID != binding.RegistrationBindingID || binding.NativeBindingEpoch != binding.RegistrationBindingEpoch || binding.codexDomainBinding.validateEndpointGroupAuthority(binding.EndpointGroupAuthority) != nil {
			return errCodexMCPContext
		}
	} else if binding.LocalDomainVersion != 1 || binding.EndpointGroupAuthority != (wire.EndpointGroupCurrentEndpoint{}) {
		return errCodexMCPContext
	}
	return nil
}

func (binding codexOutboxBinding) stored() string {
	if binding == (codexOutboxBinding{}) {
		return ""
	}
	raw, _ := json.Marshal(binding)
	return string(raw)
}

func decodeCodexOutboxBinding(raw string) (codexOutboxBinding, error) {
	var binding codexOutboxBinding
	if raw == "" {
		return binding, nil
	}
	if len(raw) > 16<<10 || decodeLocalBridgeRequest([]byte(raw), &binding) != nil || binding.EndpointGroupsVersion == 0 && len(raw) > 2048 || binding.validate() != nil || binding.stored() != raw {
		return codexOutboxBinding{}, errCodexMCPContext
	}
	return binding, nil
}

func (b codexDomainBinding) validateEndpointGroupAuthority(a wire.EndpointGroupCurrentEndpoint) error {
	r, h := a.Relation, a.OwnerControl
	if b.EndpointGroupsVersion != 1 || b.validate() != nil || e2ee.ValidateEndpointGroupOwnerControl(h) != nil || r.State != "ACTIVE" || r.RegistrationDigest != b.RegistrationDigest || r.RegistrationRevision != b.RegistrationRevision ||
		r.BindingID != b.RegistrationBindingID || r.BindingEpoch != b.RegistrationBindingEpoch || r.GroupID == "" || r.EndpointID == "" || r.PrincipalID == "" ||
		r.ContributionRevision == 0 || r.ContributionRevision >= 1<<63 || r.AuthorityID == "" || r.AuthorityEpoch == 0 || r.AuthorityEpoch >= 1<<63 ||
		!localContextHex(r.OwnerControlDigest, 64) || r.DecisionRevision != h.Revision || h.DenyReason != "NONE" {
		return errCodexMCPContext
	}
	switch h.Mode {
	case "DEFAULT":
		if h.Revision != 0 || h.PolicyID != "" || h.PolicyEpoch != 0 || r.Source != "DEFAULT_POLICY" {
			return errCodexMCPContext
		}
	case "OWNER":
		if r.Source != "OWNER_EXPLICIT" || r.PolicyID != h.PolicyID || r.PolicyEpoch != h.PolicyEpoch || r.AuthorityID != h.PolicyID || r.AuthorityEpoch != h.PolicyEpoch {
			return errCodexMCPContext
		}
	default:
		return errCodexMCPContext
	}
	return nil
}

func (m *mcpServer) currentCodexDomainBinding() (codexDomainBinding, error) {
	if m.codexContext == nil {
		return codexDomainBinding{}, nil
	}
	m.codexContext.mu.RLock()
	defer m.codexContext.mu.RUnlock()
	if m.codexContext.activeVerification == nil {
		return codexDomainBinding{}, errCodexMCPContext
	}
	return codexContextBinding(*m.codexContext.activeVerification)
}

func codexContextBinding(value localCodexContext) (codexDomainBinding, error) {
	b := codexDomainBinding{LocalDomainVersion: value.LocalDomainVersion, LocalDomain: value.LocalDomain, codexEndpointGroupsBinding: codexEndpointGroupsBinding{EndpointGroupsVersion: value.EndpointGroupsVersion, RegistrationDigest: value.RegistrationDigest, RegistrationRevision: value.RegistrationRevision, RegistrationBindingID: value.BindingID, RegistrationBindingEpoch: value.BindingEpoch, RegistrationNodeKeyEpoch: value.NodeKeyEpoch}}
	switch value.VerificationProfile {
	case "", LocalCodexContextProfileLegacy:
		if b != (codexDomainBinding{}) {
			return codexDomainBinding{}, errCodexMCPContext
		}
	case LocalCodexContextProfileDomain:
		if b.LocalDomainVersion != 1 || b.codexEndpointGroupsBinding != (codexEndpointGroupsBinding{}) || b.validate() != nil {
			return codexDomainBinding{}, errCodexMCPContext
		}
	case LocalCodexContextProfileEndpointGroups:
		if b.EndpointGroupsVersion != 1 || b.validate() != nil {
			return codexDomainBinding{}, errCodexMCPContext
		}
	default:
		return codexDomainBinding{}, errCodexMCPContext
	}
	return b, nil
}

// Only the private Node's consumed one-use context selects a verification
// profile. Empty is the original strict wire shape; partial/unknown profiles
// cannot fall back to it. A policy selector is never a caller-issued grant.
func codexContextDomain(value localCodexContext) (wire.LocalDomainSelection, bool, error) {
	zero := wire.LocalDomainSelection{}
	// Old LocalDomain-only consumers must explicitly opt in to the independent
	// registration profile. A recognized new profile cannot become legacy strict.
	if _, err := codexContextBinding(value); err != nil {
		return zero, false, err
	}
	switch value.VerificationProfile {
	case "", LocalCodexContextProfileLegacy:
		if value.LocalDomainVersion != 0 || value.LocalDomain != zero {
			return zero, false, errCodexMCPContext
		}
		return zero, false, nil
	case LocalCodexContextProfileDomain:
		if value.LocalDomainVersion != 1 || wire.ValidateLocalDomainSelection(value.LocalDomain) != nil {
			return zero, false, errCodexMCPContext
		}
		return value.LocalDomain, true, nil
	default:
		return zero, false, errCodexMCPContext
	}
}

func (m *mcpServer) requireStrictCodexContext() error {
	if m.codexContext == nil {
		return nil // The established explicit legacy entry remains separate.
	}
	m.codexContext.mu.RLock()
	defer m.codexContext.mu.RUnlock()
	if m.codexContext.activeVerification == nil {
		return errCodexMCPContext
	}
	binding, err := codexContextBinding(*m.codexContext.activeVerification)
	if err != nil || binding != (codexDomainBinding{}) {
		return errCodexMCPContext
	}
	return nil
}
