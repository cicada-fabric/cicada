package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/harness"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/store"
)

type mcpEndpointKeyCandidateResult struct {
	EndpointID       string `json:"endpoint_id"`
	KeyID            string `json:"key_id"`
	Fingerprint      string `json:"fingerprint"`
	CandidateStatus  string `json:"candidate_status"`
	CandidateVersion int64  `json:"candidate_version"`
}

func (m *mcpServer) publishEndpointKeyCandidate(arguments map[string]any) (any, error) {
	if len(arguments) != 0 {
		return nil, errors.New("cicada_publish_endpoint_key_candidate accepts no arguments; identity comes from the current session")
	}
	m.joinMu.Lock()
	defer m.joinMu.Unlock()

	current, err := harness.DetectCurrentSession()
	if err != nil {
		return nil, err
	}
	trusted, err := normalizeMCPTrustedContext(current)
	if err != nil {
		return nil, err
	}

	m.sessionMu.RLock()
	token := strings.TrimSpace(m.sessionToken)
	endpointID := strings.TrimSpace(m.endpointID)
	groupID := strings.TrimSpace(m.sessionGroupID)
	boundContext := m.sessionContext
	boundContextSet := m.sessionContextSet
	sessionScope := strings.TrimSpace(m.sessionScope)
	cached := m.sessionPublic
	m.sessionMu.RUnlock()
	if token == "" {
		return nil, errors.New("cicada_publish_endpoint_key_candidate requires an active Cicada session; call cicada_join first")
	}
	if !boundContextSet || boundContext != trusted {
		return nil, errors.New("Cicada session is bound to a different native session context")
	}
	currentScope, _, err := mcpSessionScope(m.baseURL, current)
	if err != nil {
		return nil, err
	}
	if sessionScope == "" || sessionScope != currentScope {
		return nil, errors.New("Cicada session is not cached for the current native session context")
	}
	if endpointID == "" || groupID == "" || cached.Endpoint.ID != endpointID || cached.Endpoint.GroupID != groupID {
		return nil, errors.New("cached Cicada session endpoint or Group context is incomplete")
	}
	if strings.TrimSpace(cached.BindingID) == "" || cached.BindingEpoch == 0 {
		return nil, errors.New("cached Cicada session binding context is incomplete")
	}
	expectedOwner := strings.TrimSpace(cached.Endpoint.Owner)

	whoami, err := m.api(http.MethodGet, "/v2/fabric/whoami", nil)
	if err != nil {
		return nil, err
	}
	card, err := networkCardFromResult(whoami)
	if err != nil {
		return nil, errors.New("current Cicada session returned an invalid whoami response")
	}
	if card.EndpointID != endpointID || card.GroupID != groupID || card.NodeID != trusted.NodeID ||
		card.BindingID != cached.BindingID || card.BindingEpoch != cached.BindingEpoch ||
		strings.TrimSpace(card.PrincipalID) == "" {
		return nil, errors.New("current Cicada session does not match its cached Endpoint, Group, Node, or binding")
	}
	if card.Harness != "" && harness.Canonical(card.Harness) != trusted.Harness {
		return nil, errors.New("current Cicada session harness does not match its cached native context")
	}
	if cached.NetworkCard.PrincipalID != "" && cached.NetworkCard.PrincipalID != card.PrincipalID {
		return nil, errors.New("current Cicada session Principal does not match its cached server context")
	}

	stateDir := endpointKeyNodeStateBase()
	if stateDir == "" {
		return nil, errors.New("endpoint key publication requires CICADA_NODE_STATE_DIR or CICADA_STATE_DIR")
	}
	identity, err := nodekeys.LoadOrCreate(machineNodeStateDir(stateDir, card.NodeID), card.EndpointID)
	if err != nil {
		return nil, fmt.Errorf("load Node-local Endpoint identity: %w", err)
	}
	public := identity.Public()
	fingerprint, err := nodekeys.PeerKeyFingerprint(public)
	if err != nil {
		return nil, err
	}

	path := "/v2/fabric/endpoint-keys/" + url.PathEscape(card.EndpointID)
	existingResult, err := m.api(http.MethodGet, path, nil)
	if err != nil {
		var responseErr *mcpHTTPError
		if !errors.As(err, &responseErr) || responseErr.statusCode != http.StatusNotFound {
			return nil, err
		}
	} else {
		existing, decodeErr := endpointKeyCandidateFromResult(existingResult)
		if decodeErr != nil {
			return nil, fmt.Errorf("decode existing Endpoint key candidate: %w", decodeErr)
		}
		if err := validateMCPCurrentCandidate(existing, card, expectedOwner); err != nil {
			return nil, err
		}
		if existing.KeyID != public.ID || !sameMCPKeyPublic(existing.Public, public) {
			return nil, errors.New("Hub already has a different public key candidate for this Endpoint")
		}
	}

	attestation, err := identity.SignEndpointKeyAttestation(card.EndpointID, card.PrincipalID,
		card.NodeID, card.BindingID, card.BindingEpoch)
	if err != nil {
		return nil, fmt.Errorf("sign Endpoint key candidate: %w", err)
	}
	registeredResult, err := m.api(http.MethodPost, "/v2/fabric/endpoint-keys", struct {
		Attestation json.RawMessage `json:"attestation"`
	}{Attestation: json.RawMessage(attestation)})
	if err != nil {
		return nil, err
	}
	registered, err := endpointKeyCandidateFromResult(registeredResult)
	if err != nil {
		return nil, fmt.Errorf("decode registered Endpoint key candidate: %w", err)
	}
	if err := validateMCPCurrentCandidate(registered, card, expectedOwner); err != nil {
		return nil, err
	}
	if registered.KeyID != public.ID || !sameMCPKeyPublic(registered.Public, public) {
		return nil, errors.New("Hub returned a different public key candidate than the one signed locally")
	}
	return mcpEndpointKeyCandidateResult{
		EndpointID: card.EndpointID, KeyID: public.ID, Fingerprint: fingerprint,
		CandidateStatus: registered.State, CandidateVersion: registered.Version,
	}, nil
}

func endpointKeyNodeStateBase() string {
	if value := strings.TrimSpace(os.Getenv("CICADA_NODE_STATE_DIR")); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv("CICADA_STATE_DIR"))
}

func endpointKeyCandidateFromResult(result any) (store.EndpointKeyCandidate, error) {
	encoded, err := json.Marshal(result)
	if err != nil {
		return store.EndpointKeyCandidate{}, err
	}
	var candidate store.EndpointKeyCandidate
	if err := json.Unmarshal(encoded, &candidate); err != nil {
		return store.EndpointKeyCandidate{}, err
	}
	if candidate.EndpointID == "" || candidate.KeyID == "" || candidate.Public.ID == "" {
		return store.EndpointKeyCandidate{}, errors.New("candidate response omitted public identity fields")
	}
	return candidate, nil
}

func validateMCPCurrentCandidate(candidate store.EndpointKeyCandidate, card fabric.NetworkCard, expectedOwner string) error {
	if candidate.EndpointID != card.EndpointID || candidate.PrincipalID != card.PrincipalID ||
		candidate.NodeID != card.NodeID || candidate.BindingID != card.BindingID ||
		candidate.BindingEpoch != card.BindingEpoch || candidate.KeyID != candidate.Public.ID ||
		candidate.OwnerID == "" || (expectedOwner != "" && candidate.OwnerID != expectedOwner) ||
		candidate.State != store.EndpointKeyCandidateStateCandidate || candidate.Version <= 0 {
		return errors.New("Hub returned an Endpoint key candidate for a different or invalid session binding")
	}
	verified, err := e2ee.VerifyEndpointKeyAttestation(candidate.Proof, card.EndpointID, card.PrincipalID,
		card.NodeID, card.BindingID, card.BindingEpoch)
	if err != nil || !sameMCPKeyPublic(verified, candidate.Public) {
		return errors.New("Hub returned an Endpoint key candidate with an invalid attestation")
	}
	return nil
}

func sameMCPKeyPublic(left, right e2ee.PublicIdentity) bool {
	return left.ID == right.ID && bytes.Equal(left.KEMPublic, right.KEMPublic) &&
		bytes.Equal(left.SigningPublic, right.SigningPublic)
}
