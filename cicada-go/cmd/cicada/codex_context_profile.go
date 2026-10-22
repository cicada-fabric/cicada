package main

import (
	"encoding/json"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

// This local storage fence records the selected authority generation without
// changing a native identity, scope hash, Node pin or Hub credential.
type codexDomainBinding struct {
	LocalDomainVersion int                       `json:"local_domain_version,omitempty"`
	LocalDomain        wire.LocalDomainSelection `json:"local_domain,omitzero"`
}

func (binding codexDomainBinding) validate() error {
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
	NativeBindingID    string `json:"native_binding_id"`
	NativeBindingEpoch uint64 `json:"native_binding_epoch"`
}

func (binding codexOutboxBinding) validate() error {
	if binding == (codexOutboxBinding{}) {
		return nil
	}
	if binding.codexDomainBinding.validate() != nil || binding.LocalDomainVersion != 1 || !localContextText(binding.NativeBindingID, 256) || binding.NativeBindingEpoch == 0 || binding.NativeBindingEpoch >= 1<<63 {
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
	if len(raw) > 2048 || decodeLocalBridgeRequest([]byte(raw), &binding) != nil || binding.validate() != nil || binding.stored() != raw {
		return codexOutboxBinding{}, errCodexMCPContext
	}
	return binding, nil
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
	selection, domain, err := codexContextDomain(*m.codexContext.activeVerification)
	if err != nil {
		return codexDomainBinding{}, err
	}
	if !domain {
		return codexDomainBinding{}, nil
	}
	return codexDomainBinding{LocalDomainVersion: 1, LocalDomain: selection}, nil
}

// Only the private Node's consumed one-use context selects a verification
// profile. Empty is the original strict wire shape; partial/unknown profiles
// cannot fall back to it. A policy selector is never a caller-issued grant.
func codexContextDomain(value localCodexContext) (wire.LocalDomainSelection, bool, error) {
	zero := wire.LocalDomainSelection{}
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
	_, domain, err := codexContextDomain(*m.codexContext.activeVerification)
	if err != nil || domain {
		return errCodexMCPContext
	}
	return nil
}
