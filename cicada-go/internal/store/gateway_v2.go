package store

// This file contains the additive v2-C GroupGateway state layer.  It is
// deliberately independent from the legacy Fabric envelope and Relay
// delivery tables: a FederationRequest records the authorization and result
// relationship between two Groups, while Relay remains responsible for
// transporting an opaque message.  In particular, this package does not
// expose a Worker-to-Worker cross-Group send path.  The service layer must
// route such traffic through the two representative assignments represented
// here.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	GroupCardPublished = "PUBLISHED"
	GroupCardRevoked   = "REVOKED"

	FederationContractDraft   = "DRAFT"
	FederationContractActive  = "ACTIVE"
	FederationContractPaused  = "PAUSED"
	FederationContractExpired = "EXPIRED"
	FederationContractRevoked = "REVOKED"

	RepresentativeAssignmentPending = "PENDING"
	RepresentativeAssignmentActive  = "ACTIVE"
	RepresentativeAssignmentPaused  = "PAUSED"
	RepresentativeAssignmentRevoked = "REVOKED"
	RepresentativeAssignmentExpired = "EXPIRED"

	FederationRequestCreated            = "CREATED"
	FederationRequestSourceAuthorized   = "SOURCE_AUTHORIZED"
	FederationRequestSent               = "SENT"
	FederationRequestPending            = "PENDING_ACCEPTANCE"
	FederationRequestAccepted           = "ACCEPTED"
	FederationRequestInProgress         = "IN_PROGRESS"
	FederationRequestResultSubmitted    = "RESULT_SUBMITTED"
	FederationRequestResultAccepted     = "RESULT_ACCEPTED"
	FederationRequestClosed             = "CLOSED"
	FederationRequestNeedsClarification = "NEEDS_CLARIFICATION"
	FederationRequestRejected           = "REJECTED"
	FederationRequestExpired            = "EXPIRED"
	FederationRequestCancelRequested    = "CANCEL_REQUESTED"
	FederationRequestCancelled          = "CANCELLED"
	FederationRequestFailed             = "FAILED"
	FederationRequestLateResult         = "LATE_RESULT"

	RepresentativeMailboxReady     = "READY"
	RepresentativeMailboxClaimed   = "CLAIMED"
	RepresentativeMailboxDelivered = "DELIVERED"
	RepresentativeMailboxExpired   = "EXPIRED"
	RepresentativeMailboxCancelled = "CANCELLED"

	FederationResultSubmitted = "RESULT_SUBMITTED"
	FederationResultAccepted  = "RESULT_ACCEPTED"
	FederationResultRejected  = "REJECTED"
	FederationResultLate      = "LATE_RESULT"
)

// Compatibility spellings are useful to callers which use the wording from
// the architecture document instead of the shorter store constants.
const (
	GroupCardStatePublished     = GroupCardPublished
	GroupCardStateRevoked       = GroupCardRevoked
	ContractStateDraft          = FederationContractDraft
	ContractStateActive         = FederationContractActive
	ContractStatePaused         = FederationContractPaused
	ContractStateExpired        = FederationContractExpired
	ContractStateRevoked        = FederationContractRevoked
	RepresentativeStatusPending = RepresentativeAssignmentPending
	RepresentativeStatusActive  = RepresentativeAssignmentActive
	RepresentativeStatusPaused  = RepresentativeAssignmentPaused
	RepresentativeStatusRevoked = RepresentativeAssignmentRevoked
	RepresentativeStatusExpired = RepresentativeAssignmentExpired
	FederationRequestPENDING    = FederationRequestPending
	FederationRequestACCEPTED   = FederationRequestAccepted
	FederationRequestCOMPLETED  = FederationRequestClosed
	FederationRequestRESULT     = FederationRequestResultSubmitted
)

var (
	ErrGroupCardNotFound                = errors.New("group card not found")
	ErrFederationContractNotFound       = errors.New("federation contract not found")
	ErrRepresentativeAssignmentNotFound = errors.New("representative assignment not found")
	ErrFederationRequestNotFound        = errors.New("federation request not found")
	ErrFederationResultNotFound         = errors.New("federation result not found")
	ErrRepresentativeMailboxNotFound    = errors.New("representative mailbox item not found")
	ErrGatewayDigestConflict            = errors.New("gateway digest conflicts with existing record")
	ErrGatewayIdempotencyConflict       = ErrGatewayDigestConflict
	ErrFederationDigestConflict         = ErrGatewayDigestConflict
	ErrGatewayInvalidState              = errors.New("gateway object has invalid state transition")
	ErrGatewayContractExpired           = errors.New("federation contract is expired or inactive")
	ErrGatewayScopeDenied               = errors.New("federation scope is outside the contract")
	ErrGatewayGroupMismatch             = errors.New("federation group does not match the contract or representative")
	ErrGatewayDeadline                  = errors.New("federation deadline is invalid or expired")
	ErrGatewayAuthorization             = errors.New("federation authorization is not active")
	ErrGatewayLeaseHeld                 = errors.New("representative lease is held by another owner")
	ErrGatewayStaleEpoch                = errors.New("representative epoch is stale")
	ErrGatewayLeaseOwner                = errors.New("representative lease owner mismatch")
	ErrGatewayLeaseExpired              = errors.New("representative lease has expired")
	ErrGatewayNoMailbox                 = errors.New("representative mailbox has no claimable item")
)

// Aliases let callers use the same vocabulary as the v2-B session store.
var (
	ErrRepresentativeStaleEpoch = ErrGatewayStaleEpoch
	ErrRepresentativeLeaseHeld  = ErrGatewayLeaseHeld
	ErrGatewayRequestNotFound   = ErrFederationRequestNotFound
	ErrGatewayContractNotFound  = ErrFederationContractNotFound
)

// GroupCard is the public, versioned description of a Group.  Public
// capabilities and representative endpoints are declarations; they are not
// authorization by themselves.  The GroupGateway verifies a contract and
// representative assignment before using a card.
type GroupCard struct {
	ID                        string         `json:"group_card_id"`
	CardID                    string         `json:"card_id,omitempty"`
	GroupID                   string         `json:"group_id"`
	Version                   int64          `json:"version"`
	TrustDomainID             string         `json:"trust_domain_id,omitempty"`
	OwnerTrustDomainID        string         `json:"owner_trust_domain_id,omitempty"`
	PublicCapabilities        []string       `json:"public_capabilities,omitempty"`
	Capabilities              []string       `json:"capabilities,omitempty"`
	InputContracts            map[string]any `json:"input_contracts,omitempty"`
	OutputContracts           map[string]any `json:"output_contracts,omitempty"`
	RepresentativeEndpointID  string         `json:"representative_endpoint_id,omitempty"`
	RepresentativeEndpointIDs []string       `json:"representative_endpoint_ids,omitempty"`
	RepresentativeEndpoints   []string       `json:"representative_endpoints,omitempty"`
	SecuritySummary           map[string]any `json:"security_summary,omitempty"`
	SecuritySummaryRef        string         `json:"security_summary_ref,omitempty"`
	AvailabilityAt            string         `json:"availability_at,omitempty"`
	AvailableAt               string         `json:"available_at,omitempty"`
	ExpiresAt                 string         `json:"expires_at,omitempty"`
	State                     string         `json:"state"`
	Digest                    string         `json:"digest"`
	CreatedAt                 string         `json:"created_at"`
	UpdatedAt                 string         `json:"updated_at"`
}

// FederationContract is a bilateral capability grant.  Scope values are
// exact strings unless the contract explicitly contains "*".  A contract
// digest is immutable for a given contract ID/version.
type FederationContract struct {
	ID                     string         `json:"contract_id"`
	ContractID             string         `json:"contract_ref,omitempty"`
	SourceGroupID          string         `json:"source_group_id"`
	TargetGroupID          string         `json:"target_group_id"`
	Capability             string         `json:"capability"`
	Scopes                 []string       `json:"scopes,omitempty"`
	Scope                  []string       `json:"scope,omitempty"`
	State                  string         `json:"state"`
	ExpiresAt              string         `json:"expires_at,omitempty"`
	Expiry                 string         `json:"expiry,omitempty"`
	NotBefore              string         `json:"not_before,omitempty"`
	Version                int64          `json:"version"`
	Digest                 string         `json:"digest"`
	AuthorizationRef       string         `json:"authorization_ref,omitempty"`
	SourceAuthorizationRef string         `json:"source_authorization_ref,omitempty"`
	TargetAuthorizationRef string         `json:"target_authorization_ref,omitempty"`
	InputContract          map[string]any `json:"input_contract,omitempty"`
	OutputContract         map[string]any `json:"output_contract,omitempty"`
	CreatedAt              string         `json:"created_at"`
	UpdatedAt              string         `json:"updated_at"`
}

// RepresentativeAssignment binds one authenticated principal/endpoint to a
// Group and a bounded scope.  OwnerID and Epoch are the fencing coordinates
// for accepting requests and settling results.
type RepresentativeAssignment struct {
	ID                  string   `json:"representative_assignment_id"`
	AssignmentID        string   `json:"assignment_id,omitempty"`
	GroupID             string   `json:"group_id"`
	PrincipalID         string   `json:"principal_id"`
	EndpointID          string   `json:"endpoint_id"`
	Scope               []string `json:"scope,omitempty"`
	Scopes              []string `json:"scopes,omitempty"`
	ContractID          string   `json:"contract_id,omitempty"`
	ContractRef         string   `json:"contract_ref,omitempty"`
	ContractIDs         []string `json:"contract_ids,omitempty"`
	ContractRefs        []string `json:"contract_refs,omitempty"`
	OwnerID             string   `json:"owner_id,omitempty"`
	OwnerPrincipalID    string   `json:"owner_principal_id,omitempty"`
	LeaseOwner          string   `json:"lease_owner,omitempty"`
	LeaseExpiresAt      string   `json:"lease_expires_at,omitempty"`
	OwnerLeaseExpiresAt string   `json:"owner_lease_expires_at,omitempty"`
	Epoch               uint64   `json:"epoch"`
	Status              string   `json:"status"`
	Version             int64    `json:"version"`
	CreatedAt           string   `json:"created_at"`
	UpdatedAt           string   `json:"updated_at"`
}

type RepresentativeAssignmentFilter struct {
	GroupID     string
	PrincipalID string
	EndpointID  string
	Status      string
	Limit       int
}

// FederationRequest retains both sides of a cross-Group request and the
// source/provenance links used when a result is returned.  Result acceptance
// and request closure are separate transitions: ACCEPTED is never completion.
type FederationRequest struct {
	ID                               string   `json:"federation_request_id"`
	FederationRequestID              string   `json:"request_id,omitempty"`
	OriginRequestID                  string   `json:"origin_request_id"`
	SourceGroupID                    string   `json:"source_group_id"`
	TargetGroupID                    string   `json:"target_group_id"`
	SourceRepresentativeEndpointID   string   `json:"source_representative_endpoint_id"`
	TargetRepresentativeEndpointID   string   `json:"target_representative_endpoint_id"`
	SourceRepresentativeID           string   `json:"source_representative_id,omitempty"`
	TargetRepresentativeID           string   `json:"target_representative_id,omitempty"`
	SourceRepresentativeAssignmentID string   `json:"source_representative_assignment_id,omitempty"`
	TargetRepresentativeAssignmentID string   `json:"target_representative_assignment_id,omitempty"`
	OriginPrincipalID                string   `json:"origin_principal_id"`
	Capability                       string   `json:"capability"`
	ContractID                       string   `json:"contract_id,omitempty"`
	ContractRef                      string   `json:"contract_ref,omitempty"`
	RequestDigest                    string   `json:"request_digest"`
	Digest                           string   `json:"digest,omitempty"`
	Scopes                           []string `json:"scopes,omitempty"`
	Scope                            []string `json:"scope,omitempty"`
	ArtifactRefs                     []string `json:"artifact_refs,omitempty"`
	Deadline                         string   `json:"deadline"`
	MaxHops                          int      `json:"max_hops"`
	State                            string   `json:"state"`
	SourceState                      string   `json:"source_state,omitempty"`
	TargetState                      string   `json:"target_state,omitempty"`
	ProducerPrincipalID              string   `json:"producer_principal_id,omitempty"`
	ProducerEndpointID               string   `json:"producer_endpoint_id,omitempty"`
	ProducerGroupID                  string   `json:"producer_group_id,omitempty"`
	EvidenceRefs                     []string `json:"evidence_refs,omitempty"`
	ProvenanceRefs                   []string `json:"provenance_refs,omitempty"`
	ResultID                         string   `json:"result_id,omitempty"`
	ResultAssociationID              string   `json:"result_association_id,omitempty"`
	ResultDigest                     string   `json:"result_digest,omitempty"`
	SourceOwnerID                    string   `json:"source_owner_id,omitempty"`
	SourceOwnerEpoch                 uint64   `json:"source_owner_epoch,omitempty"`
	TargetOwnerID                    string   `json:"target_owner_id,omitempty"`
	TargetOwnerEpoch                 uint64   `json:"target_owner_epoch,omitempty"`
	AcceptedAt                       string   `json:"accepted_at,omitempty"`
	StartedAt                        string   `json:"started_at,omitempty"`
	ResultSubmittedAt                string   `json:"result_submitted_at,omitempty"`
	ResultAcceptedAt                 string   `json:"result_accepted_at,omitempty"`
	ClosedAt                         string   `json:"closed_at,omitempty"`
	CancelRequestedAt                string   `json:"cancel_requested_at,omitempty"`
	CancelledAt                      string   `json:"cancelled_at,omitempty"`
	ExpiredAt                        string   `json:"expired_at,omitempty"`
	LateResultAt                     string   `json:"late_result_at,omitempty"`
	CreatedAt                        string   `json:"created_at"`
	UpdatedAt                        string   `json:"updated_at"`
}

type FederationRequestFilter struct {
	SourceGroupID   string
	TargetGroupID   string
	State           string
	OriginRequestID string
	Limit           int
}

// FederationResult is intentionally separate from a representative.  The
// producer fields are supplied by the authenticated worker/result path and
// are preserved verbatim; a representative is only the transport boundary.
type FederationResult struct {
	ID                    string   `json:"result_id"`
	ResultID              string   `json:"id,omitempty"`
	RequestID             string   `json:"federation_request_id"`
	FederationRequestID   string   `json:"request_id,omitempty"`
	Digest                string   `json:"digest"`
	ResultDigest          string   `json:"result_digest,omitempty"`
	State                 string   `json:"state"`
	ProducerPrincipalID   string   `json:"producer_principal_id"`
	ProducerEndpointID    string   `json:"producer_endpoint_id,omitempty"`
	ProducerGroupID       string   `json:"producer_group_id"`
	ArtifactRefs          []string `json:"artifact_refs,omitempty"`
	EvidenceRefs          []string `json:"evidence_refs,omitempty"`
	ProvenanceRefs        []string `json:"provenance_refs,omitempty"`
	VerificationLevel     string   `json:"verification_level,omitempty"`
	PayloadRef            string   `json:"payload_ref,omitempty"`
	SubmittedByEndpointID string   `json:"submitted_by_endpoint_id,omitempty"`
	SubmittedByOwnerID    string   `json:"submitted_by_owner_id,omitempty"`
	SubmittedByEpoch      uint64   `json:"submitted_by_epoch,omitempty"`
	LateForState          string   `json:"late_for_state,omitempty"`
	CreatedAt             string   `json:"created_at"`
	UpdatedAt             string   `json:"updated_at"`
}

// RepresentativeMailboxItem is a durable notification/reference.  It does
// not copy a request body; the request row is the authority.
type RepresentativeMailboxItem struct {
	ID                         string `json:"mailbox_id"`
	MailboxID                  string `json:"id,omitempty"`
	RequestID                  string `json:"federation_request_id"`
	FederationRequestID        string `json:"request_id,omitempty"`
	GroupID                    string `json:"group_id"`
	RepresentativeEndpointID   string `json:"representative_endpoint_id"`
	RepresentativeAssignmentID string `json:"representative_assignment_id"`
	OwnerID                    string `json:"owner_id,omitempty"`
	OwnerEpoch                 uint64 `json:"owner_epoch,omitempty"`
	State                      string `json:"state"`
	AvailableAt                string `json:"available_at"`
	Deadline                   string `json:"deadline"`
	Attempts                   int    `json:"attempts"`
	LastError                  string `json:"last_error,omitempty"`
	ClaimedAt                  string `json:"claimed_at,omitempty"`
	DeliveredAt                string `json:"delivered_at,omitempty"`
	CreatedAt                  string `json:"created_at"`
	UpdatedAt                  string `json:"updated_at"`
}

type RepresentativeMailboxClaimInput struct {
	GroupID                    string
	RepresentativeEndpointID   string
	RepresentativeAssignmentID string
	OwnerID                    string
	Owner                      string
	Epoch                      uint64
	Limit                      int
}

type RepresentativeClaimInput struct {
	AssignmentID   string
	OwnerID        string
	LeaseExpiresAt string
	ExpectedEpoch  uint64
	Force          bool
}

const gatewayV2Schema = `
CREATE TABLE IF NOT EXISTS gateway_v2_group_cards (
  id TEXT PRIMARY KEY,
  group_id TEXT NOT NULL,
  version INTEGER NOT NULL CHECK(version > 0),
  trust_domain_id TEXT NOT NULL DEFAULT '',
  public_capabilities_json TEXT NOT NULL DEFAULT '[]',
  input_contracts_json TEXT NOT NULL DEFAULT '{}',
  output_contracts_json TEXT NOT NULL DEFAULT '{}',
  representative_endpoint_ids_json TEXT NOT NULL DEFAULT '[]',
  security_summary_json TEXT NOT NULL DEFAULT '{}',
  security_summary_ref TEXT NOT NULL DEFAULT '',
  availability_at TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'PUBLISHED',
  digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(group_id, version)
);
CREATE INDEX IF NOT EXISTS gateway_v2_group_cards_group_idx
  ON gateway_v2_group_cards(group_id, version DESC);

CREATE TABLE IF NOT EXISTS gateway_v2_contracts (
  id TEXT PRIMARY KEY,
  source_group_id TEXT NOT NULL,
  target_group_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  scopes_json TEXT NOT NULL DEFAULT '[]',
  state TEXT NOT NULL DEFAULT 'ACTIVE',
  not_before TEXT NOT NULL DEFAULT '',
  expires_at TEXT NOT NULL,
  version INTEGER NOT NULL CHECK(version > 0),
  digest TEXT NOT NULL,
  authorization_ref TEXT NOT NULL DEFAULT '',
  source_authorization_ref TEXT NOT NULL DEFAULT '',
  target_authorization_ref TEXT NOT NULL DEFAULT '',
  input_contract_json TEXT NOT NULL DEFAULT '{}',
  output_contract_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(source_group_id, target_group_id, capability, version)
);
CREATE INDEX IF NOT EXISTS gateway_v2_contracts_pair_idx
  ON gateway_v2_contracts(source_group_id, target_group_id, state, expires_at);

CREATE TABLE IF NOT EXISTS gateway_v2_representatives (
  id TEXT PRIMARY KEY,
  group_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  endpoint_id TEXT NOT NULL,
  scopes_json TEXT NOT NULL DEFAULT '[]',
  contract_ids_json TEXT NOT NULL DEFAULT '[]',
  owner_id TEXT NOT NULL DEFAULT '',
  lease_expires_at TEXT NOT NULL DEFAULT '',
  epoch INTEGER NOT NULL DEFAULT 1 CHECK(epoch > 0),
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  version INTEGER NOT NULL DEFAULT 1 CHECK(version > 0),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS gateway_v2_representatives_group_idx
  ON gateway_v2_representatives(group_id, status, endpoint_id);
CREATE UNIQUE INDEX IF NOT EXISTS gateway_v2_representatives_active_endpoint_idx
  ON gateway_v2_representatives(group_id, endpoint_id)
  WHERE status IN ('PENDING','ACTIVE','PAUSED');

CREATE TABLE IF NOT EXISTS gateway_v2_requests (
  id TEXT PRIMARY KEY,
  origin_request_id TEXT NOT NULL DEFAULT '',
  source_group_id TEXT NOT NULL,
  target_group_id TEXT NOT NULL,
  source_representative_endpoint_id TEXT NOT NULL,
  target_representative_endpoint_id TEXT NOT NULL,
  source_representative_assignment_id TEXT NOT NULL,
  target_representative_assignment_id TEXT NOT NULL,
  origin_principal_id TEXT NOT NULL,
  capability TEXT NOT NULL,
  contract_id TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  scopes_json TEXT NOT NULL DEFAULT '[]',
  artifact_refs_json TEXT NOT NULL DEFAULT '[]',
  deadline TEXT NOT NULL,
  max_hops INTEGER NOT NULL CHECK(max_hops > 0),
  state TEXT NOT NULL,
  source_state TEXT NOT NULL DEFAULT '',
  target_state TEXT NOT NULL DEFAULT '',
  producer_principal_id TEXT NOT NULL DEFAULT '',
  producer_endpoint_id TEXT NOT NULL DEFAULT '',
  producer_group_id TEXT NOT NULL DEFAULT '',
  evidence_refs_json TEXT NOT NULL DEFAULT '[]',
  provenance_refs_json TEXT NOT NULL DEFAULT '[]',
  result_id TEXT NOT NULL DEFAULT '',
  result_digest TEXT NOT NULL DEFAULT '',
  source_owner_id TEXT NOT NULL DEFAULT '',
  source_owner_epoch INTEGER NOT NULL DEFAULT 0,
  target_owner_id TEXT NOT NULL DEFAULT '',
  target_owner_epoch INTEGER NOT NULL DEFAULT 0,
  accepted_at TEXT NOT NULL DEFAULT '',
  started_at TEXT NOT NULL DEFAULT '',
  result_submitted_at TEXT NOT NULL DEFAULT '',
  result_accepted_at TEXT NOT NULL DEFAULT '',
  closed_at TEXT NOT NULL DEFAULT '',
  cancel_requested_at TEXT NOT NULL DEFAULT '',
  cancelled_at TEXT NOT NULL DEFAULT '',
  expired_at TEXT NOT NULL DEFAULT '',
  late_result_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS gateway_v2_requests_origin_idx
  ON gateway_v2_requests(source_group_id, origin_request_id)
  WHERE origin_request_id <> '';
CREATE INDEX IF NOT EXISTS gateway_v2_requests_state_idx
  ON gateway_v2_requests(state, deadline, created_at);
CREATE INDEX IF NOT EXISTS gateway_v2_requests_pair_idx
  ON gateway_v2_requests(source_group_id, target_group_id, updated_at);

CREATE TABLE IF NOT EXISTS gateway_v2_request_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  from_state TEXT NOT NULL DEFAULT '',
  to_state TEXT NOT NULL DEFAULT '',
  actor_id TEXT NOT NULL DEFAULT '',
  owner_epoch INTEGER NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  FOREIGN KEY(request_id) REFERENCES gateway_v2_requests(id)
);
CREATE INDEX IF NOT EXISTS gateway_v2_request_events_idx
  ON gateway_v2_request_events(request_id, id);

CREATE TABLE IF NOT EXISTS gateway_v2_mailbox (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  group_id TEXT NOT NULL,
  representative_endpoint_id TEXT NOT NULL,
  representative_assignment_id TEXT NOT NULL,
  owner_id TEXT NOT NULL DEFAULT '',
  owner_epoch INTEGER NOT NULL DEFAULT 0,
  state TEXT NOT NULL DEFAULT 'READY',
  available_at TEXT NOT NULL,
  deadline TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  claimed_at TEXT NOT NULL DEFAULT '',
  delivered_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(request_id, representative_assignment_id),
  FOREIGN KEY(request_id) REFERENCES gateway_v2_requests(id)
);
CREATE INDEX IF NOT EXISTS gateway_v2_mailbox_pending_idx
  ON gateway_v2_mailbox(group_id, representative_endpoint_id, state, available_at);

CREATE TABLE IF NOT EXISTS gateway_v2_results (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  digest TEXT NOT NULL,
  state TEXT NOT NULL,
  producer_principal_id TEXT NOT NULL,
  producer_endpoint_id TEXT NOT NULL DEFAULT '',
  producer_group_id TEXT NOT NULL,
  artifact_refs_json TEXT NOT NULL DEFAULT '[]',
  evidence_refs_json TEXT NOT NULL DEFAULT '[]',
  provenance_refs_json TEXT NOT NULL DEFAULT '[]',
  verification_level TEXT NOT NULL DEFAULT '',
  payload_ref TEXT NOT NULL DEFAULT '',
  submitted_by_endpoint_id TEXT NOT NULL DEFAULT '',
  submitted_by_owner_id TEXT NOT NULL DEFAULT '',
  submitted_by_epoch INTEGER NOT NULL DEFAULT 0,
  late_for_state TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(request_id)
);
CREATE INDEX IF NOT EXISTS gateway_v2_results_producer_idx
  ON gateway_v2_results(producer_group_id, producer_principal_id, created_at);
`

// initializeGatewayV2Schema is intentionally a separate hook.  The main
// Store initializer is wired by the owning service so opening an old database
// can be rolled out independently from the GroupGateway code.
func (s *Store) initializeGatewayV2Schema() error {
	if _, err := s.db.Exec(gatewayV2Schema); err != nil {
		return fmt.Errorf("initialize gateway v2 schema: %w", err)
	}
	return nil
}

// InitializeGatewayV2Schema is the explicit migration hook used by tests and
// by applications during staged rollout.
func (s *Store) InitializeGatewayV2Schema() error { return s.initializeGatewayV2Schema() }

func gatewayTrim(value string) string { return strings.TrimSpace(value) }

func gatewayLimit(limit int) int {
	if limit <= 0 || limit > 1000 {
		return 100
	}
	return limit
}

func gatewayJSON(value any, empty string) (string, error) {
	if value == nil {
		return empty, nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func gatewayStringSlice(value []string) []string {
	seen := make(map[string]struct{}, len(value))
	out := make([]string, 0, len(value))
	for _, item := range value {
		item = gatewayTrim(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func gatewayDecodeStrings(raw string) ([]string, error) {
	var values []string
	if raw == "" {
		return []string{}, nil
	}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	if values == nil {
		values = []string{}
	}
	return values, nil
}

func gatewayDecodeMap(raw string) (map[string]any, error) {
	values := map[string]any{}
	if raw == "" {
		return values, nil
	}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return nil, err
	}
	if values == nil {
		values = map[string]any{}
	}
	return values, nil
}

func gatewayDigest(value any) string {
	b, _ := json.Marshal(value)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func gatewayParseTime(value string) (time.Time, error) {
	value = gatewayTrim(value)
	if value == "" {
		return time.Time{}, errors.New("timestamp is required")
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("timestamp must be RFC3339: %w", err)
	}
	return parsed.UTC(), nil
}

func gatewayExpiryValid(value string, nowTime time.Time) error {
	parsed, err := gatewayParseTime(value)
	if err != nil {
		return ErrGatewayContractExpired
	}
	if !parsed.After(nowTime) {
		return ErrGatewayContractExpired
	}
	return nil
}

func gatewayDeadlineValid(value string, nowTime time.Time) error {
	parsed, err := gatewayParseTime(value)
	if err != nil || !parsed.After(nowTime) {
		return ErrGatewayDeadline
	}
	return nil
}

func gatewayScopeAllowed(allowed, requested []string) bool {
	allowed = gatewayStringSlice(allowed)
	requested = gatewayStringSlice(requested)
	if len(requested) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		set[scope] = struct{}{}
	}
	for _, scope := range requested {
		if _, ok := set[scope]; !ok {
			if _, wildcard := set["*"]; !wildcard {
				return false
			}
		}
	}
	return true
}

func gatewayScopeSubset(requested, allowed []string) bool {
	return gatewayScopeAllowed(allowed, requested)
}

func normalizeGroupCard(card GroupCard) (GroupCard, string, string, string, error) {
	card.ID = gatewayTrim(card.ID)
	if card.ID == "" {
		card.ID = gatewayTrim(card.CardID)
	}
	if card.ID == "" {
		card.ID = NewID("gcard")
	}
	card.CardID = card.ID
	card.GroupID = gatewayTrim(card.GroupID)
	card.TrustDomainID = gatewayTrim(card.TrustDomainID)
	if card.TrustDomainID == "" {
		card.TrustDomainID = gatewayTrim(card.OwnerTrustDomainID)
	}
	if card.Version <= 0 {
		card.Version = 1
	}
	if len(card.PublicCapabilities) == 0 {
		card.PublicCapabilities = card.Capabilities
	}
	card.PublicCapabilities = gatewayStringSlice(card.PublicCapabilities)
	card.Capabilities = append([]string(nil), card.PublicCapabilities...)
	endpoints := make([]string, 0, len(card.RepresentativeEndpointIDs)+len(card.RepresentativeEndpoints)+1)
	if card.RepresentativeEndpointID != "" {
		endpoints = append(endpoints, card.RepresentativeEndpointID)
	}
	endpoints = append(endpoints, card.RepresentativeEndpointIDs...)
	endpoints = append(endpoints, card.RepresentativeEndpoints...)
	card.RepresentativeEndpointIDs = gatewayStringSlice(endpoints)
	card.RepresentativeEndpoints = append([]string(nil), card.RepresentativeEndpointIDs...)
	if len(card.RepresentativeEndpointIDs) > 0 {
		card.RepresentativeEndpointID = card.RepresentativeEndpointIDs[0]
	}
	if card.InputContracts == nil {
		card.InputContracts = map[string]any{}
	}
	if card.OutputContracts == nil {
		card.OutputContracts = map[string]any{}
	}
	if card.SecuritySummary == nil {
		card.SecuritySummary = map[string]any{}
	}
	card.SecuritySummaryRef = gatewayTrim(card.SecuritySummaryRef)
	card.AvailabilityAt = gatewayTrim(card.AvailabilityAt)
	if card.AvailabilityAt == "" {
		card.AvailabilityAt = gatewayTrim(card.AvailableAt)
	}
	card.AvailableAt = card.AvailabilityAt
	card.ExpiresAt = gatewayTrim(card.ExpiresAt)
	if card.State == "" {
		card.State = GroupCardPublished
	}
	if card.GroupID == "" {
		return card, "", "", "", errors.New("group card group is required")
	}
	publicJSON, err := gatewayJSON(card.PublicCapabilities, "[]")
	if err != nil {
		return card, "", "", "", fmt.Errorf("encode group card capabilities: %w", err)
	}
	endpointJSON, err := gatewayJSON(card.RepresentativeEndpointIDs, "[]")
	if err != nil {
		return card, "", "", "", fmt.Errorf("encode group card representatives: %w", err)
	}
	inputJSON, err := gatewayJSON(card.InputContracts, "{}")
	if err != nil {
		return card, "", "", "", fmt.Errorf("encode group card input contract: %w", err)
	}
	outputJSON, err := gatewayJSON(card.OutputContracts, "{}")
	if err != nil {
		return card, "", "", "", fmt.Errorf("encode group card output contract: %w", err)
	}
	securityJSON, err := gatewayJSON(card.SecuritySummary, "{}")
	if err != nil {
		return card, "", "", "", fmt.Errorf("encode group card security summary: %w", err)
	}
	if card.Digest == "" {
		card.Digest = gatewayDigest(struct {
			GroupID      string         `json:"group_id"`
			Version      int64          `json:"version"`
			Capabilities []string       `json:"capabilities"`
			Endpoints    []string       `json:"endpoints"`
			Security     map[string]any `json:"security"`
		}{card.GroupID, card.Version, card.PublicCapabilities, card.RepresentativeEndpointIDs, card.SecuritySummary})
	}
	return card, publicJSON, endpointJSON, inputJSON + "\x00" + outputJSON + "\x00" + securityJSON, nil
}

type gatewayCardDecoded struct {
	Card GroupCard
}

func scanGroupCard(row interface{ Scan(...any) error }) (*GroupCard, error) {
	var card GroupCard
	var publicJSON, inputJSON, outputJSON, endpointsJSON, securityJSON string
	if err := row.Scan(&card.ID, &card.GroupID, &card.Version, &card.TrustDomainID,
		&publicJSON, &inputJSON, &outputJSON, &endpointsJSON, &securityJSON,
		&card.SecuritySummaryRef, &card.AvailabilityAt, &card.ExpiresAt,
		&card.State, &card.Digest, &card.CreatedAt, &card.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	var err error
	if card.PublicCapabilities, err = gatewayDecodeStrings(publicJSON); err != nil {
		return nil, err
	}
	if card.RepresentativeEndpointIDs, err = gatewayDecodeStrings(endpointsJSON); err != nil {
		return nil, err
	}
	if card.InputContracts, err = gatewayDecodeMap(inputJSON); err != nil {
		return nil, err
	}
	if card.OutputContracts, err = gatewayDecodeMap(outputJSON); err != nil {
		return nil, err
	}
	if card.SecuritySummary, err = gatewayDecodeMap(securityJSON); err != nil {
		return nil, err
	}
	card.CardID = card.ID
	card.Capabilities = append([]string(nil), card.PublicCapabilities...)
	card.RepresentativeEndpoints = append([]string(nil), card.RepresentativeEndpointIDs...)
	card.AvailableAt = card.AvailabilityAt
	if len(card.RepresentativeEndpointIDs) > 0 {
		card.RepresentativeEndpointID = card.RepresentativeEndpointIDs[0]
	}
	card.OwnerTrustDomainID = card.TrustDomainID
	return &card, nil
}

const gatewayCardColumns = `id, group_id, version, trust_domain_id,
public_capabilities_json, input_contracts_json, output_contracts_json,
representative_endpoint_ids_json, security_summary_json, security_summary_ref,
availability_at, expires_at, state, digest, created_at, updated_at`

func (s *Store) UpsertGroupCard(card GroupCard) (*GroupCard, error) {
	card, publicJSON, endpointJSON, combinedJSON, err := normalizeGroupCard(card)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(combinedJSON, "\x00")
	if len(parts) != 3 {
		return nil, errors.New("invalid normalized group card")
	}
	inputJSON, outputJSON, securityJSON := parts[0], parts[1], parts[2]
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var existingID, existingDigest string
	err = s.db.QueryRow(`SELECT id, digest FROM gateway_v2_group_cards WHERE group_id = ? AND version = ?`, card.GroupID, card.Version).Scan(&existingID, &existingDigest)
	if err == nil {
		if existingDigest != card.Digest {
			return nil, ErrGatewayDigestConflict
		}
		return scanGroupCard(s.db.QueryRow(`SELECT `+gatewayCardColumns+` FROM gateway_v2_group_cards WHERE id = ?`, existingID))
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	_, err = s.db.Exec(`INSERT INTO gateway_v2_group_cards
(id, group_id, version, trust_domain_id, public_capabilities_json,
 input_contracts_json, output_contracts_json, representative_endpoint_ids_json,
 security_summary_json, security_summary_ref, availability_at, expires_at,
 state, digest, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, card.ID, card.GroupID,
		card.Version, card.TrustDomainID, publicJSON, inputJSON, outputJSON,
		endpointJSON, securityJSON, card.SecuritySummaryRef, card.AvailabilityAt,
		card.ExpiresAt, card.State, card.Digest, timestamp, timestamp)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			var digest string
			if readErr := s.db.QueryRow(`SELECT digest FROM gateway_v2_group_cards WHERE group_id = ? AND version = ?`, card.GroupID, card.Version).Scan(&digest); readErr == nil && digest == card.Digest {
				return scanGroupCard(s.db.QueryRow(`SELECT `+gatewayCardColumns+` FROM gateway_v2_group_cards WHERE group_id = ? AND version = ?`, card.GroupID, card.Version))
			}
		}
		return nil, fmt.Errorf("insert group card: %w", err)
	}
	return scanGroupCard(s.db.QueryRow(`SELECT `+gatewayCardColumns+` FROM gateway_v2_group_cards WHERE id = ?`, card.ID))
}

func (s *Store) CreateGroupCard(card GroupCard) (*GroupCard, error)  { return s.UpsertGroupCard(card) }
func (s *Store) PutGroupCard(card GroupCard) (*GroupCard, error)     { return s.UpsertGroupCard(card) }
func (s *Store) PublishGroupCard(card GroupCard) (*GroupCard, error) { return s.UpsertGroupCard(card) }

func (s *Store) GetGroupCard(id string) (*GroupCard, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	card, err := scanGroupCard(s.db.QueryRow(`SELECT `+gatewayCardColumns+` FROM gateway_v2_group_cards WHERE id = ?`, gatewayTrim(id)))
	if err != nil {
		return nil, err
	}
	if card == nil {
		return nil, ErrGroupCardNotFound
	}
	return card, nil
}

func (s *Store) GetLatestGroupCard(groupID string) (*GroupCard, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	card, err := scanGroupCard(s.db.QueryRow(`SELECT `+gatewayCardColumns+` FROM gateway_v2_group_cards WHERE group_id = ? ORDER BY version DESC LIMIT 1`, gatewayTrim(groupID)))
	if err != nil {
		return nil, err
	}
	if card == nil {
		return nil, ErrGroupCardNotFound
	}
	return card, nil
}

func (s *Store) ListGroupCards(groupID string, limit int) ([]GroupCard, error) {
	limit = gatewayLimit(limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	query := `SELECT ` + gatewayCardColumns + ` FROM gateway_v2_group_cards WHERE 1=1`
	args := []any{}
	if groupID = gatewayTrim(groupID); groupID != "" {
		query += ` AND group_id = ?`
		args = append(args, groupID)
	}
	query += ` ORDER BY group_id, version DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]GroupCard, 0)
	for rows.Next() {
		card, err := scanGroupCard(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *card)
	}
	return result, rows.Err()
}

func normalizeFederationContract(contract FederationContract) (FederationContract, string, string, string, string, error) {
	contract.ID = gatewayTrim(contract.ID)
	if contract.ID == "" {
		contract.ID = gatewayTrim(contract.ContractID)
	}
	if contract.ID == "" {
		contract.ID = NewID("contract")
	}
	contract.ContractID = contract.ID
	contract.SourceGroupID = gatewayTrim(contract.SourceGroupID)
	contract.TargetGroupID = gatewayTrim(contract.TargetGroupID)
	contract.Capability = gatewayTrim(contract.Capability)
	if len(contract.Scopes) == 0 {
		contract.Scopes = contract.Scope
	}
	contract.Scopes = gatewayStringSlice(contract.Scopes)
	contract.Scope = append([]string(nil), contract.Scopes...)
	contract.State = gatewayTrim(contract.State)
	if contract.State == "" {
		contract.State = FederationContractActive
	}
	contract.ExpiresAt = gatewayTrim(contract.ExpiresAt)
	if contract.ExpiresAt == "" {
		contract.ExpiresAt = gatewayTrim(contract.Expiry)
	}
	contract.Expiry = contract.ExpiresAt
	if contract.Version <= 0 {
		contract.Version = 1
	}
	contract.AuthorizationRef = gatewayTrim(contract.AuthorizationRef)
	contract.SourceAuthorizationRef = gatewayTrim(contract.SourceAuthorizationRef)
	contract.TargetAuthorizationRef = gatewayTrim(contract.TargetAuthorizationRef)
	if contract.InputContract == nil {
		contract.InputContract = map[string]any{}
	}
	if contract.OutputContract == nil {
		contract.OutputContract = map[string]any{}
	}
	if contract.SourceGroupID == "" || contract.TargetGroupID == "" || contract.Capability == "" {
		return contract, "", "", "", "", errors.New("contract source group, target group, and capability are required")
	}
	if contract.SourceGroupID == contract.TargetGroupID {
		return contract, "", "", "", "", ErrGatewayGroupMismatch
	}
	if contract.ExpiresAt == "" {
		return contract, "", "", "", "", ErrGatewayDeadline
	}
	scopeJSON, err := gatewayJSON(contract.Scopes, "[]")
	if err != nil {
		return contract, "", "", "", "", err
	}
	inputJSON, err := gatewayJSON(contract.InputContract, "{}")
	if err != nil {
		return contract, "", "", "", "", err
	}
	outputJSON, err := gatewayJSON(contract.OutputContract, "{}")
	if err != nil {
		return contract, "", "", "", "", err
	}
	if contract.Digest == "" {
		contract.Digest = gatewayDigest(struct {
			Source, Target, Capability string
			Scopes                     []string
			State, ExpiresAt           string
			Version                    int64
		}{contract.SourceGroupID, contract.TargetGroupID, contract.Capability, contract.Scopes, contract.State, contract.ExpiresAt, contract.Version})
	}
	return contract, scopeJSON, inputJSON, outputJSON, contract.Digest, nil
}

func scanFederationContract(row interface{ Scan(...any) error }) (*FederationContract, error) {
	var contract FederationContract
	var scopeJSON, inputJSON, outputJSON string
	err := row.Scan(&contract.ID, &contract.SourceGroupID, &contract.TargetGroupID,
		&contract.Capability, &scopeJSON, &contract.State, &contract.NotBefore,
		&contract.ExpiresAt, &contract.Version, &contract.Digest,
		&contract.AuthorizationRef, &contract.SourceAuthorizationRef,
		&contract.TargetAuthorizationRef, &inputJSON, &outputJSON,
		&contract.CreatedAt, &contract.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	contract.ContractID = contract.ID
	contract.Expiry = contract.ExpiresAt
	contract.Scope, err = gatewayDecodeStrings(scopeJSON)
	if err != nil {
		return nil, err
	}
	contract.Scopes = append([]string(nil), contract.Scope...)
	contract.InputContract, err = gatewayDecodeMap(inputJSON)
	if err != nil {
		return nil, err
	}
	contract.OutputContract, err = gatewayDecodeMap(outputJSON)
	if err != nil {
		return nil, err
	}
	return &contract, nil
}

const gatewayContractColumns = `id, source_group_id, target_group_id, capability,
scopes_json, state, not_before, expires_at, version, digest, authorization_ref,
source_authorization_ref, target_authorization_ref, input_contract_json,
output_contract_json, created_at, updated_at`

func (s *Store) UpsertFederationContract(contract FederationContract) (*FederationContract, error) {
	contract, scopeJSON, inputJSON, outputJSON, digest, err := normalizeFederationContract(contract)
	if err != nil {
		return nil, err
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var existingID, existingDigest string
	err = s.db.QueryRow(`SELECT id, digest FROM gateway_v2_contracts WHERE source_group_id = ? AND target_group_id = ? AND capability = ? AND version = ?`, contract.SourceGroupID, contract.TargetGroupID, contract.Capability, contract.Version).Scan(&existingID, &existingDigest)
	if err == nil {
		if existingDigest != digest {
			return nil, ErrGatewayDigestConflict
		}
		return scanFederationContract(s.db.QueryRow(`SELECT `+gatewayContractColumns+` FROM gateway_v2_contracts WHERE id = ?`, existingID))
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	_, err = s.db.Exec(`INSERT INTO gateway_v2_contracts
(id, source_group_id, target_group_id, capability, scopes_json, state,
 not_before, expires_at, version, digest, authorization_ref,
 source_authorization_ref, target_authorization_ref, input_contract_json,
 output_contract_json, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, contract.ID,
		contract.SourceGroupID, contract.TargetGroupID, contract.Capability, scopeJSON,
		contract.State, contract.NotBefore, contract.ExpiresAt, contract.Version,
		digest, contract.AuthorizationRef, contract.SourceAuthorizationRef,
		contract.TargetAuthorizationRef, inputJSON, outputJSON, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("insert federation contract: %w", err)
	}
	return scanFederationContract(s.db.QueryRow(`SELECT `+gatewayContractColumns+` FROM gateway_v2_contracts WHERE id = ?`, contract.ID))
}
func (s *Store) CreateFederationContract(contract FederationContract) (*FederationContract, error) {
	return s.UpsertFederationContract(contract)
}
func (s *Store) PutFederationContract(contract FederationContract) (*FederationContract, error) {
	return s.UpsertFederationContract(contract)
}

func (s *Store) GetFederationContract(id string) (*FederationContract, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	contract, err := scanFederationContract(s.db.QueryRow(`SELECT `+gatewayContractColumns+` FROM gateway_v2_contracts WHERE id = ?`, gatewayTrim(id)))
	if err != nil {
		return nil, err
	}
	if contract == nil {
		return nil, ErrFederationContractNotFound
	}
	return contract, nil
}

func scanRepresentativeAssignment(row interface{ Scan(...any) error }) (*RepresentativeAssignment, error) {
	var assignment RepresentativeAssignment
	var scopesJSON, contractsJSON string
	err := row.Scan(&assignment.ID, &assignment.GroupID, &assignment.PrincipalID,
		&assignment.EndpointID, &scopesJSON, &contractsJSON, &assignment.OwnerID,
		&assignment.LeaseExpiresAt, &assignment.Epoch, &assignment.Status,
		&assignment.Version, &assignment.CreatedAt, &assignment.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	assignment.AssignmentID = assignment.ID
	assignment.OwnerPrincipalID = assignment.OwnerID
	assignment.LeaseOwner = assignment.OwnerID
	assignment.OwnerLeaseExpiresAt = assignment.LeaseExpiresAt
	assignment.Scope, err = gatewayDecodeStrings(scopesJSON)
	if err != nil {
		return nil, err
	}
	assignment.Scopes = append([]string(nil), assignment.Scope...)
	assignment.ContractIDs, err = gatewayDecodeStrings(contractsJSON)
	if err != nil {
		return nil, err
	}
	assignment.ContractRefs = append([]string(nil), assignment.ContractIDs...)
	if len(assignment.ContractIDs) > 0 {
		assignment.ContractID = assignment.ContractIDs[0]
		assignment.ContractRef = assignment.ContractIDs[0]
	}
	return &assignment, nil
}

const gatewayAssignmentColumns = `id, group_id, principal_id, endpoint_id,
scopes_json, contract_ids_json, owner_id, lease_expires_at, epoch, status,
version, created_at, updated_at`

func normalizeRepresentativeAssignment(assignment RepresentativeAssignment) (RepresentativeAssignment, string, string, error) {
	assignment.ID = gatewayTrim(assignment.ID)
	if assignment.ID == "" {
		assignment.ID = gatewayTrim(assignment.AssignmentID)
	}
	if assignment.ID == "" {
		assignment.ID = NewID("rep")
	}
	assignment.AssignmentID = assignment.ID
	assignment.GroupID = gatewayTrim(assignment.GroupID)
	assignment.PrincipalID = gatewayTrim(assignment.PrincipalID)
	assignment.EndpointID = gatewayTrim(assignment.EndpointID)
	if len(assignment.Scope) == 0 {
		assignment.Scope = assignment.Scopes
	}
	assignment.Scope = gatewayStringSlice(assignment.Scope)
	assignment.Scopes = append([]string(nil), assignment.Scope...)
	contracts := make([]string, 0, len(assignment.ContractIDs)+len(assignment.ContractRefs)+2)
	if assignment.ContractID != "" {
		contracts = append(contracts, assignment.ContractID)
	}
	if assignment.ContractRef != "" {
		contracts = append(contracts, assignment.ContractRef)
	}
	contracts = append(contracts, assignment.ContractIDs...)
	contracts = append(contracts, assignment.ContractRefs...)
	assignment.ContractIDs = gatewayStringSlice(contracts)
	assignment.ContractRefs = append([]string(nil), assignment.ContractIDs...)
	if len(assignment.ContractIDs) > 0 {
		assignment.ContractID = assignment.ContractIDs[0]
		assignment.ContractRef = assignment.ContractIDs[0]
	}
	assignment.OwnerID = gatewayTrim(assignment.OwnerID)
	if assignment.OwnerID == "" {
		assignment.OwnerID = gatewayTrim(assignment.OwnerPrincipalID)
	}
	if assignment.OwnerID == "" {
		assignment.OwnerID = gatewayTrim(assignment.LeaseOwner)
	}
	assignment.OwnerPrincipalID = assignment.OwnerID
	assignment.LeaseOwner = assignment.OwnerID
	assignment.LeaseExpiresAt = gatewayTrim(assignment.LeaseExpiresAt)
	if assignment.LeaseExpiresAt == "" {
		assignment.LeaseExpiresAt = gatewayTrim(assignment.OwnerLeaseExpiresAt)
	}
	assignment.OwnerLeaseExpiresAt = assignment.LeaseExpiresAt
	assignment.Status = gatewayTrim(assignment.Status)
	if assignment.Status == "" {
		assignment.Status = RepresentativeAssignmentActive
	}
	if assignment.Epoch == 0 {
		assignment.Epoch = 1
	}
	if assignment.Version <= 0 {
		assignment.Version = 1
	}
	if assignment.GroupID == "" || assignment.PrincipalID == "" || assignment.EndpointID == "" {
		return assignment, "", "", errors.New("representative group, principal, and endpoint are required")
	}
	scopeJSON, err := gatewayJSON(assignment.Scope, "[]")
	if err != nil {
		return assignment, "", "", err
	}
	contractJSON, err := gatewayJSON(assignment.ContractIDs, "[]")
	if err != nil {
		return assignment, "", "", err
	}
	return assignment, scopeJSON, contractJSON, nil
}

func (s *Store) CreateRepresentativeAssignment(assignment RepresentativeAssignment) (*RepresentativeAssignment, error) {
	assignment, scopeJSON, contractJSON, err := normalizeRepresentativeAssignment(assignment)
	if err != nil {
		return nil, err
	}
	for _, contractID := range assignment.ContractIDs {
		contract, getErr := s.GetFederationContract(contractID)
		if getErr != nil {
			return nil, getErr
		}
		if contract.SourceGroupID != assignment.GroupID && contract.TargetGroupID != assignment.GroupID {
			return nil, ErrGatewayGroupMismatch
		}
		if !gatewayScopeSubset(assignment.Scope, contract.Scopes) {
			return nil, ErrGatewayScopeDenied
		}
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO gateway_v2_representatives
(id, group_id, principal_id, endpoint_id, scopes_json, contract_ids_json,
 owner_id, lease_expires_at, epoch, status, version, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, assignment.ID, assignment.GroupID,
		assignment.PrincipalID, assignment.EndpointID, scopeJSON, contractJSON,
		assignment.OwnerID, assignment.LeaseExpiresAt, assignment.Epoch,
		assignment.Status, assignment.Version, timestamp, timestamp)
	if err != nil {
		return nil, fmt.Errorf("insert representative assignment: %w", err)
	}
	return scanRepresentativeAssignment(s.db.QueryRow(`SELECT `+gatewayAssignmentColumns+` FROM gateway_v2_representatives WHERE id = ?`, assignment.ID))
}
func (s *Store) CreateRepresentative(assignment RepresentativeAssignment) (*RepresentativeAssignment, error) {
	return s.CreateRepresentativeAssignment(assignment)
}
func (s *Store) PutRepresentativeAssignment(assignment RepresentativeAssignment) (*RepresentativeAssignment, error) {
	return s.CreateRepresentativeAssignment(assignment)
}

func (s *Store) GetRepresentativeAssignment(id string) (*RepresentativeAssignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	assignment, err := scanRepresentativeAssignment(s.db.QueryRow(`SELECT `+gatewayAssignmentColumns+` FROM gateway_v2_representatives WHERE id = ?`, gatewayTrim(id)))
	if err != nil {
		return nil, err
	}
	if assignment == nil {
		return nil, ErrRepresentativeAssignmentNotFound
	}
	return assignment, nil
}

func (s *Store) ListRepresentativeAssignments(filter RepresentativeAssignmentFilter) ([]RepresentativeAssignment, error) {
	limit := gatewayLimit(filter.Limit)
	query := `SELECT ` + gatewayAssignmentColumns + ` FROM gateway_v2_representatives WHERE 1=1`
	args := []any{}
	for _, item := range []struct{ value, column string }{{filter.GroupID, "group_id"}, {filter.PrincipalID, "principal_id"}, {filter.EndpointID, "endpoint_id"}, {filter.Status, "status"}} {
		if value := gatewayTrim(item.value); value != "" {
			query += ` AND ` + item.column + ` = ?`
			args = append(args, value)
		}
	}
	query += ` ORDER BY updated_at DESC, id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []RepresentativeAssignment{}
	for rows.Next() {
		row, err := scanRepresentativeAssignment(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *row)
	}
	return result, rows.Err()
}

func parseRepresentativeClaim(input any, args []any) (RepresentativeClaimInput, error) {
	var claim RepresentativeClaimInput
	switch value := input.(type) {
	case RepresentativeClaimInput:
		claim = value
	case string:
		claim.AssignmentID = gatewayTrim(value)
		if len(args) > 0 {
			claim.OwnerID, _ = args[0].(string)
		}
		if len(args) > 1 {
			claim.LeaseExpiresAt, _ = args[1].(string)
		}
		if len(args) > 2 {
			switch epoch := args[2].(type) {
			case uint64:
				claim.ExpectedEpoch = epoch
			case int:
				if epoch >= 0 {
					claim.ExpectedEpoch = uint64(epoch)
				}
			case int64:
				if epoch >= 0 {
					claim.ExpectedEpoch = uint64(epoch)
				}
			}
		}
	default:
		return claim, errors.New("representative claim input is invalid")
	}
	claim.AssignmentID = gatewayTrim(claim.AssignmentID)
	claim.OwnerID = gatewayTrim(claim.OwnerID)
	claim.LeaseExpiresAt = gatewayTrim(claim.LeaseExpiresAt)
	if claim.AssignmentID == "" || claim.OwnerID == "" {
		return claim, errors.New("representative assignment and owner are required")
	}
	if claim.LeaseExpiresAt == "" {
		claim.LeaseExpiresAt = time.Now().UTC().Add(5 * time.Minute).Format(time.RFC3339)
	}
	if _, err := gatewayParseTime(claim.LeaseExpiresAt); err != nil {
		return claim, ErrGatewayDeadline
	}
	return claim, nil
}

func (s *Store) claimRepresentative(input any, args []any, force bool) (*RepresentativeAssignment, error) {
	claim, err := parseRepresentativeClaim(input, args)
	if err != nil {
		return nil, err
	}
	claim.Force = claim.Force || force
	timestamp := now()
	nowTime, _ := gatewayParseTime(timestamp)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(e error) (*RepresentativeAssignment, error) { _ = tx.Rollback(); return nil, e }
	assignment, err := scanRepresentativeAssignment(tx.QueryRow(`SELECT `+gatewayAssignmentColumns+` FROM gateway_v2_representatives WHERE id = ?`, claim.AssignmentID))
	if err != nil {
		return rollback(err)
	}
	if assignment == nil {
		return rollback(ErrRepresentativeAssignmentNotFound)
	}
	if assignment.Status != RepresentativeAssignmentActive && assignment.Status != RepresentativeAssignmentPending {
		return rollback(ErrGatewayInvalidState)
	}
	if claim.ExpectedEpoch != 0 && claim.ExpectedEpoch != assignment.Epoch {
		return rollback(ErrGatewayStaleEpoch)
	}
	leaseActive := assignment.OwnerID != "" && assignment.LeaseExpiresAt != ""
	if leaseActive {
		expiry, parseErr := gatewayParseTime(assignment.LeaseExpiresAt)
		if parseErr == nil && expiry.After(nowTime) {
			if assignment.OwnerID != claim.OwnerID {
				return rollback(ErrGatewayLeaseHeld)
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return assignment, nil
		}
	}
	if assignment.OwnerID != "" && leaseActive && !claim.Force { /* expired leases may be taken over */
	}
	if _, err := tx.Exec(`UPDATE gateway_v2_representatives SET owner_id = ?, lease_expires_at = ?, epoch = epoch + 1, status = ?, version = version + 1, updated_at = ? WHERE id = ? AND epoch = ?`, claim.OwnerID, claim.LeaseExpiresAt, RepresentativeAssignmentActive, timestamp, claim.AssignmentID, assignment.Epoch); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getRepresentativeAssignmentLocked(claim.AssignmentID)
}

func (s *Store) getRepresentativeAssignmentLocked(id string) (*RepresentativeAssignment, error) {
	row, err := scanRepresentativeAssignment(s.db.QueryRow(`SELECT `+gatewayAssignmentColumns+` FROM gateway_v2_representatives WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrRepresentativeAssignmentNotFound
	}
	return row, nil
}

// ClaimRepresentative accepts either RepresentativeClaimInput or the compact
// (assignmentID, ownerID, leaseExpiry, expectedEpoch) argument form.
func (s *Store) ClaimRepresentative(input any, args ...any) (*RepresentativeAssignment, error) {
	return s.claimRepresentative(input, args, false)
}
func (s *Store) TakeoverRepresentative(input any, args ...any) (*RepresentativeAssignment, error) {
	return s.claimRepresentative(input, args, true)
}

func (s *Store) ValidateRepresentativeOwner(assignmentID, ownerID string, epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	assignment, err := scanRepresentativeAssignment(s.db.QueryRow(`SELECT `+gatewayAssignmentColumns+` FROM gateway_v2_representatives WHERE id = ?`, gatewayTrim(assignmentID)))
	if err != nil {
		return err
	}
	if assignment == nil {
		return ErrRepresentativeAssignmentNotFound
	}
	if assignment.OwnerID != gatewayTrim(ownerID) {
		return ErrGatewayLeaseOwner
	}
	if assignment.Epoch != epoch {
		return ErrGatewayStaleEpoch
	}
	if assignment.LeaseExpiresAt == "" {
		return ErrGatewayLeaseExpired
	}
	expiry, parseErr := gatewayParseTime(assignment.LeaseExpiresAt)
	if parseErr != nil || !expiry.After(time.Now().UTC()) {
		return ErrGatewayLeaseExpired
	}
	if assignment.Status != RepresentativeAssignmentActive {
		return ErrGatewayInvalidState
	}
	return nil
}

func (s *Store) RenewRepresentativeLease(assignmentID, ownerID string, epoch uint64, leaseExpiresAt string) (*RepresentativeAssignment, error) {
	if err := gatewayDeadlineValid(leaseExpiresAt, time.Now().UTC()); err != nil {
		return nil, err
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE gateway_v2_representatives SET lease_expires_at = ?, version = version + 1, updated_at = ? WHERE id = ? AND owner_id = ? AND epoch = ? AND status = ?`, leaseExpiresAt, timestamp, assignmentID, ownerID, epoch, RepresentativeAssignmentActive)
	if err != nil {
		return nil, err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return nil, ErrGatewayStaleEpoch
	}
	return s.getRepresentativeAssignmentLocked(assignmentID)
}

func (s *Store) ReleaseRepresentative(assignmentID, ownerID string, epoch uint64) (*RepresentativeAssignment, error) {
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE gateway_v2_representatives SET owner_id = '', lease_expires_at = '', epoch = epoch + 1, version = version + 1, updated_at = ? WHERE id = ? AND owner_id = ? AND epoch = ?`, timestamp, assignmentID, ownerID, epoch)
	if err != nil {
		return nil, err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return nil, ErrGatewayStaleEpoch
	}
	return s.getRepresentativeAssignmentLocked(assignmentID)
}

func (s *Store) validateContractTx(tx *sql.Tx, contractID, sourceGroupID, targetGroupID, capability string, scopes []string, deadline string) (*FederationContract, error) {
	contract, err := scanFederationContract(tx.QueryRow(`SELECT `+gatewayContractColumns+` FROM gateway_v2_contracts WHERE id = ?`, gatewayTrim(contractID)))
	if err != nil {
		return nil, err
	}
	if contract == nil {
		return nil, ErrFederationContractNotFound
	}
	if contract.SourceGroupID != gatewayTrim(sourceGroupID) || contract.TargetGroupID != gatewayTrim(targetGroupID) || contract.Capability != gatewayTrim(capability) {
		return nil, ErrGatewayGroupMismatch
	}
	if contract.State != FederationContractActive {
		return nil, ErrGatewayContractExpired
	}
	nowTime := time.Now().UTC()
	if err := gatewayExpiryValid(contract.ExpiresAt, nowTime); err != nil {
		return nil, err
	}
	if deadline != "" {
		deadlineTime, parseErr := gatewayParseTime(deadline)
		if parseErr != nil || !deadlineTime.After(nowTime) {
			return nil, ErrGatewayDeadline
		}
		expiry, _ := gatewayParseTime(contract.ExpiresAt)
		if deadlineTime.After(expiry) {
			return nil, ErrGatewayDeadline
		}
	}
	if !gatewayScopeAllowed(contract.Scopes, scopes) {
		return nil, ErrGatewayScopeDenied
	}
	return contract, nil
}

func (s *Store) validateAssignmentTx(tx *sql.Tx, assignmentID, groupID, endpointID, contractID string, scopes []string) (*RepresentativeAssignment, error) {
	assignment, err := scanRepresentativeAssignment(tx.QueryRow(`SELECT `+gatewayAssignmentColumns+` FROM gateway_v2_representatives WHERE id = ?`, assignmentID))
	if err != nil {
		return nil, err
	}
	if assignment == nil {
		return nil, ErrRepresentativeAssignmentNotFound
	}
	if assignment.GroupID != groupID || assignment.EndpointID != endpointID {
		return nil, ErrGatewayGroupMismatch
	}
	if assignment.Status != RepresentativeAssignmentActive {
		return nil, ErrGatewayAuthorization
	}
	if len(assignment.ContractIDs) > 0 {
		found := false
		for _, id := range assignment.ContractIDs {
			if id == contractID {
				found = true
				break
			}
		}
		if !found {
			return nil, ErrGatewayAuthorization
		}
	}
	if !gatewayScopeAllowed(assignment.Scope, scopes) {
		return nil, ErrGatewayScopeDenied
	}
	return assignment, nil
}

func gatewayCheckAssignmentLeaseTx(tx *sql.Tx, assignmentID, ownerID string, epoch uint64) error {
	var currentOwner, leaseExpiresAt, status string
	var currentEpoch uint64
	err := tx.QueryRow(`SELECT owner_id, lease_expires_at, epoch, status FROM gateway_v2_representatives WHERE id = ?`, assignmentID).Scan(&currentOwner, &leaseExpiresAt, &currentEpoch, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRepresentativeAssignmentNotFound
	}
	if err != nil {
		return err
	}
	if currentOwner != ownerID {
		return ErrGatewayLeaseOwner
	}
	if currentEpoch != epoch {
		return ErrGatewayStaleEpoch
	}
	if status != RepresentativeAssignmentActive {
		return ErrGatewayInvalidState
	}
	expiresAt, parseErr := gatewayParseTime(leaseExpiresAt)
	if parseErr != nil || !expiresAt.After(time.Now().UTC()) {
		return ErrGatewayLeaseExpired
	}
	return nil
}

func (s *Store) validatePrincipalMembershipTx(tx *sql.Tx, principalID, groupID string) error {
	principalID, groupID = gatewayTrim(principalID), gatewayTrim(groupID)
	if principalID == "" || groupID == "" {
		return ErrGatewayAuthorization
	}
	var status, expiresAt, principalStatus, groupState string
	err := tx.QueryRow(`SELECT m.status, m.expires_at, p.status, g.state FROM memberships m JOIN principals p ON p.id = m.principal_id JOIN groups g ON g.id = m.group_id WHERE m.principal_id = ? AND m.group_id = ?`, principalID, groupID).Scan(&status, &expiresAt, &principalStatus, &groupState)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrGatewayAuthorization
	}
	if err != nil {
		return err
	}
	if status != MembershipStatusActive || principalStatus != PrincipalStatusActive || groupState != GroupStateActive {
		return ErrGatewayAuthorization
	}
	if expiresAt != "" {
		expiry, parseErr := gatewayParseTime(expiresAt)
		if parseErr == nil && !expiry.After(time.Now().UTC()) {
			return ErrGatewayAuthorization
		}
	}
	return nil
}

func normalizeFederationRequest(request FederationRequest) (FederationRequest, string, string, string, error) {
	request.ID = gatewayTrim(request.ID)
	if request.ID == "" {
		request.ID = gatewayTrim(request.FederationRequestID)
	}
	if request.ID == "" {
		request.ID = NewID("frequest")
	}
	request.FederationRequestID = request.ID
	request.OriginRequestID = gatewayTrim(request.OriginRequestID)
	request.SourceGroupID = gatewayTrim(request.SourceGroupID)
	request.TargetGroupID = gatewayTrim(request.TargetGroupID)
	if request.SourceRepresentativeEndpointID == "" {
		request.SourceRepresentativeEndpointID = gatewayTrim(request.SourceRepresentativeID)
	}
	if request.TargetRepresentativeEndpointID == "" {
		request.TargetRepresentativeEndpointID = gatewayTrim(request.TargetRepresentativeID)
	}
	request.SourceRepresentativeEndpointID = gatewayTrim(request.SourceRepresentativeEndpointID)
	request.TargetRepresentativeEndpointID = gatewayTrim(request.TargetRepresentativeEndpointID)
	request.SourceRepresentativeAssignmentID = gatewayTrim(request.SourceRepresentativeAssignmentID)
	request.TargetRepresentativeAssignmentID = gatewayTrim(request.TargetRepresentativeAssignmentID)
	request.OriginPrincipalID = gatewayTrim(request.OriginPrincipalID)
	request.Capability = gatewayTrim(request.Capability)
	if request.ContractID == "" {
		request.ContractID = gatewayTrim(request.ContractRef)
	}
	request.ContractID = gatewayTrim(request.ContractID)
	request.ContractRef = request.ContractID
	if request.RequestDigest == "" {
		request.RequestDigest = gatewayTrim(request.Digest)
	}
	request.RequestDigest = gatewayTrim(request.RequestDigest)
	request.Digest = request.RequestDigest
	if len(request.Scopes) == 0 {
		request.Scopes = request.Scope
	}
	request.Scopes = gatewayStringSlice(request.Scopes)
	request.Scope = append([]string(nil), request.Scopes...)
	request.ArtifactRefs = gatewayStringSlice(request.ArtifactRefs)
	request.EvidenceRefs = gatewayStringSlice(request.EvidenceRefs)
	request.ProvenanceRefs = gatewayStringSlice(request.ProvenanceRefs)
	request.Deadline = gatewayTrim(request.Deadline)
	if request.MaxHops <= 0 {
		request.MaxHops = 1
	}
	request.State = gatewayTrim(request.State)
	if request.State == "" {
		request.State = FederationRequestPending
	}
	if request.SourceGroupID == "" || request.TargetGroupID == "" || request.SourceGroupID == request.TargetGroupID {
		return request, "", "", "", ErrGatewayGroupMismatch
	}
	if request.SourceRepresentativeEndpointID == "" || request.TargetRepresentativeEndpointID == "" || request.SourceRepresentativeAssignmentID == "" || request.TargetRepresentativeAssignmentID == "" {
		return request, "", "", "", errors.New("both representative endpoints and assignments are required")
	}
	if request.OriginPrincipalID == "" || request.Capability == "" || request.ContractID == "" || request.Deadline == "" {
		return request, "", "", "", errors.New("origin principal, capability, contract, and deadline are required")
	}
	artifactJSON, err := gatewayJSON(request.ArtifactRefs, "[]")
	if err != nil {
		return request, "", "", "", err
	}
	scopeJSON, err := gatewayJSON(request.Scopes, "[]")
	if err != nil {
		return request, "", "", "", err
	}
	evidenceJSON, err := gatewayJSON(request.EvidenceRefs, "[]")
	if err != nil {
		return request, "", "", "", err
	}
	provenanceJSON, err := gatewayJSON(request.ProvenanceRefs, "[]")
	if err != nil {
		return request, "", "", "", err
	}
	if request.RequestDigest == "" {
		request.RequestDigest = gatewayDigest(struct {
			Origin, Source, Target, Capability, Contract, Deadline string
			Scopes, Artifacts                                      []string
			MaxHops                                                int
		}{request.OriginRequestID, request.SourceGroupID, request.TargetGroupID, request.Capability, request.ContractID, request.Deadline, request.Scopes, request.ArtifactRefs, request.MaxHops})
		request.Digest = request.RequestDigest
	}
	return request, scopeJSON, artifactJSON, evidenceJSON + "\x00" + provenanceJSON, nil
}

func scanFederationRequest(row interface{ Scan(...any) error }) (*FederationRequest, error) {
	var request FederationRequest
	var scopesJSON, artifactsJSON, evidenceJSON, provenanceJSON string
	err := row.Scan(&request.ID, &request.OriginRequestID, &request.SourceGroupID, &request.TargetGroupID, &request.SourceRepresentativeEndpointID, &request.TargetRepresentativeEndpointID, &request.SourceRepresentativeAssignmentID, &request.TargetRepresentativeAssignmentID, &request.OriginPrincipalID, &request.Capability, &request.ContractID, &request.RequestDigest, &scopesJSON, &artifactsJSON, &request.Deadline, &request.MaxHops, &request.State, &request.SourceState, &request.TargetState, &request.ProducerPrincipalID, &request.ProducerEndpointID, &request.ProducerGroupID, &evidenceJSON, &provenanceJSON, &request.ResultID, &request.ResultDigest, &request.SourceOwnerID, &request.SourceOwnerEpoch, &request.TargetOwnerID, &request.TargetOwnerEpoch, &request.AcceptedAt, &request.StartedAt, &request.ResultSubmittedAt, &request.ResultAcceptedAt, &request.ClosedAt, &request.CancelRequestedAt, &request.CancelledAt, &request.ExpiredAt, &request.LateResultAt, &request.CreatedAt, &request.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	request.FederationRequestID = request.ID
	request.SourceRepresentativeID = request.SourceRepresentativeEndpointID
	request.TargetRepresentativeID = request.TargetRepresentativeEndpointID
	request.ContractRef = request.ContractID
	request.Digest = request.RequestDigest
	request.Scopes, err = gatewayDecodeStrings(scopesJSON)
	if err != nil {
		return nil, err
	}
	request.Scope = append([]string(nil), request.Scopes...)
	request.ArtifactRefs, err = gatewayDecodeStrings(artifactsJSON)
	if err != nil {
		return nil, err
	}
	request.EvidenceRefs, err = gatewayDecodeStrings(evidenceJSON)
	if err != nil {
		return nil, err
	}
	request.ProvenanceRefs, err = gatewayDecodeStrings(provenanceJSON)
	if err != nil {
		return nil, err
	}
	request.ResultAssociationID = request.ResultID
	return &request, nil
}

const gatewayRequestColumns = `id, origin_request_id, source_group_id, target_group_id,
source_representative_endpoint_id, target_representative_endpoint_id,
source_representative_assignment_id, target_representative_assignment_id,
origin_principal_id, capability, contract_id, request_digest, scopes_json,
artifact_refs_json, deadline, max_hops, state, source_state, target_state,
producer_principal_id, producer_endpoint_id, producer_group_id,
evidence_refs_json, provenance_refs_json, result_id, result_digest,
source_owner_id, source_owner_epoch, target_owner_id, target_owner_epoch,
accepted_at, started_at, result_submitted_at, result_accepted_at, closed_at,
cancel_requested_at, cancelled_at, expired_at, late_result_at, created_at, updated_at`

func gatewayInsertEventTx(tx *sql.Tx, requestID, eventType, fromState, toState, actor string, epoch uint64, reason, timestamp string) error {
	_, err := tx.Exec(`INSERT INTO gateway_v2_request_events (request_id, event_type, from_state, to_state, actor_id, owner_epoch, reason, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, requestID, eventType, fromState, toState, actor, epoch, reason, timestamp)
	return err
}

func gatewayInsertMailboxTx(tx *sql.Tx, request *FederationRequest, timestamp string) error {
	_, err := tx.Exec(`INSERT OR IGNORE INTO gateway_v2_mailbox
(id, request_id, group_id, representative_endpoint_id,
 representative_assignment_id, owner_id, owner_epoch, state, available_at,
 deadline, attempts, last_error, claimed_at, delivered_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '', '', '', ?, ?)`, NewID("mbox"), request.ID,
		request.TargetGroupID, request.TargetRepresentativeEndpointID,
		request.TargetRepresentativeAssignmentID, "", 0, RepresentativeMailboxReady,
		timestamp, request.Deadline, timestamp, timestamp)
	return err
}

func (s *Store) CreateFederationRequest(request FederationRequest) (*FederationRequest, error) {
	request, scopeJSON, artifactJSON, combinedJSON, err := normalizeFederationRequest(request)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(combinedJSON, "\x00")
	if len(parts) != 2 {
		return nil, errors.New("invalid normalized federation request")
	}
	evidenceJSON, provenanceJSON := parts[0], parts[1]
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(e error) (*FederationRequest, error) { _ = tx.Rollback(); return nil, e }
	contract, err := s.validateContractTx(tx, request.ContractID, request.SourceGroupID, request.TargetGroupID, request.Capability, request.Scopes, request.Deadline)
	if err != nil {
		return rollback(err)
	}
	if err := s.validatePrincipalMembershipTx(tx, request.OriginPrincipalID, request.SourceGroupID); err != nil {
		return rollback(err)
	}
	if _, err := s.validateAssignmentTx(tx, request.SourceRepresentativeAssignmentID, request.SourceGroupID, request.SourceRepresentativeEndpointID, contract.ID, request.Scopes); err != nil {
		return rollback(err)
	}
	if _, err := s.validateAssignmentTx(tx, request.TargetRepresentativeAssignmentID, request.TargetGroupID, request.TargetRepresentativeEndpointID, contract.ID, request.Scopes); err != nil {
		return rollback(err)
	}
	// A request with the same source scoped origin ID is an immutable retry.
	var existingID, existingDigest string
	if request.OriginRequestID != "" {
		queryErr := tx.QueryRow(`SELECT id, request_digest FROM gateway_v2_requests WHERE source_group_id = ? AND origin_request_id = ?`, request.SourceGroupID, request.OriginRequestID).Scan(&existingID, &existingDigest)
		if queryErr == nil {
			if existingDigest != request.RequestDigest {
				return rollback(ErrGatewayDigestConflict)
			}
			existing, readErr := scanFederationRequest(tx.QueryRow(`SELECT `+gatewayRequestColumns+` FROM gateway_v2_requests WHERE id = ?`, existingID))
			if readErr != nil {
				return rollback(readErr)
			}
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return existing, nil
		}
		if !errors.Is(queryErr, sql.ErrNoRows) {
			return rollback(queryErr)
		}
	}
	if request.State == FederationRequestPending {
		request.SourceState = FederationRequestSent
		request.TargetState = FederationRequestPending
	} else if request.SourceState == "" {
		request.SourceState = request.State
	}
	if request.TargetState == "" {
		request.TargetState = request.State
	}
	_, err = tx.Exec(`INSERT INTO gateway_v2_requests
(id, origin_request_id, source_group_id, target_group_id,
 source_representative_endpoint_id, target_representative_endpoint_id,
 source_representative_assignment_id, target_representative_assignment_id,
 origin_principal_id, capability, contract_id, request_digest, scopes_json,
 artifact_refs_json, deadline, max_hops, state, source_state, target_state,
 producer_principal_id, producer_endpoint_id, producer_group_id,
 evidence_refs_json, provenance_refs_json, result_id, result_digest,
 source_owner_id, source_owner_epoch, target_owner_id, target_owner_epoch,
 accepted_at, started_at, result_submitted_at, result_accepted_at, closed_at,
 cancel_requested_at, cancelled_at, expired_at, late_result_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', '', ?, ?, '', '', '', 0, '', 0, '', '', '', '', '', '', '', '', '', ?, ?)`,
		request.ID, request.OriginRequestID, request.SourceGroupID, request.TargetGroupID,
		request.SourceRepresentativeEndpointID, request.TargetRepresentativeEndpointID,
		request.SourceRepresentativeAssignmentID, request.TargetRepresentativeAssignmentID,
		request.OriginPrincipalID, request.Capability, contract.ID, request.RequestDigest,
		scopeJSON, artifactJSON, request.Deadline, request.MaxHops, request.State,
		request.SourceState, request.TargetState, evidenceJSON, provenanceJSON, timestamp, timestamp)
	if err != nil {
		return rollback(fmt.Errorf("insert federation request: %w", err))
	}
	if err := gatewayInsertEventTx(tx, request.ID, request.State, "", request.State, request.OriginPrincipalID, 0, "created", timestamp); err != nil {
		return rollback(err)
	}
	if request.State == FederationRequestPending {
		if err := gatewayInsertMailboxTx(tx, &request, timestamp); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getFederationRequestLocked(request.ID)
}

func (s *Store) CreateFederationRequestV2(request FederationRequest) (*FederationRequest, error) {
	return s.CreateFederationRequest(request)
}
func (s *Store) PutFederationRequest(request FederationRequest) (*FederationRequest, error) {
	return s.CreateFederationRequest(request)
}

func (s *Store) getFederationRequestLocked(id string) (*FederationRequest, error) {
	request, err := scanFederationRequest(s.db.QueryRow(`SELECT `+gatewayRequestColumns+` FROM gateway_v2_requests WHERE id = ?`, id))
	if err != nil {
		return nil, err
	}
	if request == nil {
		return nil, ErrFederationRequestNotFound
	}
	return request, nil
}
func (s *Store) GetFederationRequest(id string) (*FederationRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getFederationRequestLocked(gatewayTrim(id))
}
func (s *Store) GetFederationRequestV2(id string) (*FederationRequest, error) {
	return s.GetFederationRequest(id)
}

func (s *Store) ListFederationRequests(filter FederationRequestFilter) ([]FederationRequest, error) {
	limit := gatewayLimit(filter.Limit)
	query := `SELECT ` + gatewayRequestColumns + ` FROM gateway_v2_requests WHERE 1=1`
	args := []any{}
	for _, item := range []struct{ value, column string }{{filter.SourceGroupID, "source_group_id"}, {filter.TargetGroupID, "target_group_id"}, {filter.State, "state"}, {filter.OriginRequestID, "origin_request_id"}} {
		if value := gatewayTrim(item.value); value != "" {
			query += ` AND ` + item.column + ` = ?`
			args = append(args, value)
		}
	}
	query += ` ORDER BY created_at DESC, id LIMIT ?`
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []FederationRequest{}
	for rows.Next() {
		row, err := scanFederationRequest(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *row)
	}
	return result, rows.Err()
}

func (s *Store) ValidateFederationRequest(request FederationRequest) error {
	normalized, _, _, _, err := normalizeFederationRequest(request)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	contract, err := s.validateContractTx(tx, normalized.ContractID, normalized.SourceGroupID, normalized.TargetGroupID, normalized.Capability, normalized.Scopes, normalized.Deadline)
	if err != nil {
		return err
	}
	if err := s.validatePrincipalMembershipTx(tx, normalized.OriginPrincipalID, normalized.SourceGroupID); err != nil {
		return err
	}
	if _, err := s.validateAssignmentTx(tx, normalized.SourceRepresentativeAssignmentID, normalized.SourceGroupID, normalized.SourceRepresentativeEndpointID, contract.ID, normalized.Scopes); err != nil {
		return err
	}
	if _, err := s.validateAssignmentTx(tx, normalized.TargetRepresentativeAssignmentID, normalized.TargetGroupID, normalized.TargetRepresentativeEndpointID, contract.ID, normalized.Scopes); err != nil {
		return err
	}
	return nil
}

func parseOwnerEpoch(args []any) (string, uint64) {
	var owner string
	var epoch uint64
	if len(args) > 0 {
		owner, _ = args[0].(string)
	}
	if len(args) > 1 {
		switch value := args[1].(type) {
		case uint64:
			epoch = value
		case int:
			if value >= 0 {
				epoch = uint64(value)
			}
		case int64:
			if value >= 0 {
				epoch = uint64(value)
			}
		}
	}
	return gatewayTrim(owner), epoch
}

func (s *Store) transitionFederationRequest(requestID, eventType, actor string, epoch uint64, expected []string, next, reason string, ownerSide string) (*FederationRequest, error) {
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(e error) (*FederationRequest, error) { _ = tx.Rollback(); return nil, e }
	request, err := scanFederationRequest(tx.QueryRow(`SELECT `+gatewayRequestColumns+` FROM gateway_v2_requests WHERE id = ?`, requestID))
	if err != nil {
		return rollback(err)
	}
	if request == nil {
		return rollback(ErrFederationRequestNotFound)
	}
	valid := false
	for _, state := range expected {
		if request.State == state {
			valid = true
			break
		}
	}
	if !valid {
		if request.State == next {
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return request, nil
		}
		return rollback(ErrGatewayInvalidState)
	}
	if err := gatewayDeadlineValid(request.Deadline, time.Now().UTC()); err != nil {
		return rollback(err)
	}
	if ownerSide == "target" {
		var currentOwner string
		var currentEpoch uint64
		if err := tx.QueryRow(`SELECT owner_id, epoch FROM gateway_v2_representatives WHERE id = ?`, request.TargetRepresentativeAssignmentID).Scan(&currentOwner, &currentEpoch); err != nil {
			return rollback(ErrRepresentativeAssignmentNotFound)
		}
		if currentOwner != actor {
			return rollback(ErrGatewayLeaseOwner)
		}
		if currentEpoch != epoch {
			return rollback(ErrGatewayStaleEpoch)
		}
		if err := gatewayCheckAssignmentLeaseTx(tx, request.TargetRepresentativeAssignmentID, actor, epoch); err != nil {
			return rollback(err)
		}
		request.TargetOwnerID, request.TargetOwnerEpoch = actor, epoch
	} else if ownerSide == "source" {
		var currentOwner string
		var currentEpoch uint64
		if err := tx.QueryRow(`SELECT owner_id, epoch FROM gateway_v2_representatives WHERE id = ?`, request.SourceRepresentativeAssignmentID).Scan(&currentOwner, &currentEpoch); err != nil {
			return rollback(ErrRepresentativeAssignmentNotFound)
		}
		if currentOwner != actor {
			return rollback(ErrGatewayLeaseOwner)
		}
		if currentEpoch != epoch {
			return rollback(ErrGatewayStaleEpoch)
		}
		if err := gatewayCheckAssignmentLeaseTx(tx, request.SourceRepresentativeAssignmentID, actor, epoch); err != nil {
			return rollback(err)
		}
		request.SourceOwnerID, request.SourceOwnerEpoch = actor, epoch
	}
	updates := `UPDATE gateway_v2_requests SET state = ?, updated_at = ?`
	args := []any{next, timestamp}
	switch next {
	case FederationRequestAccepted:
		updates += `, accepted_at = ?, target_owner_id = ?, target_owner_epoch = ?, target_state = ?`
		args = append(args, timestamp, actor, epoch, next)
	case FederationRequestInProgress:
		updates += `, started_at = ?, target_state = ?`
		args = append(args, timestamp, next)
	case FederationRequestResultAccepted:
		updates += `, result_accepted_at = ?, source_state = ?`
		args = append(args, timestamp, next)
	case FederationRequestClosed:
		updates += `, closed_at = ?, source_state = ?`
		args = append(args, timestamp, next)
	}
	updates += ` WHERE id = ?`
	args = append(args, requestID)
	if _, err := tx.Exec(updates, args...); err != nil {
		return rollback(err)
	}
	if err := gatewayInsertEventTx(tx, requestID, eventType, request.State, next, actor, epoch, reason, timestamp); err != nil {
		return rollback(err)
	}
	if next == FederationRequestAccepted {
		_, _ = tx.Exec(`UPDATE gateway_v2_mailbox SET state = ?, owner_id = ?, owner_epoch = ?, claimed_at = ?, updated_at = ? WHERE request_id = ? AND state IN (?, ?)`, RepresentativeMailboxClaimed, actor, epoch, timestamp, timestamp, requestID, RepresentativeMailboxReady, RepresentativeMailboxClaimed)
	}
	if next == FederationRequestPending {
		if err := gatewayInsertMailboxTx(tx, request, timestamp); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getFederationRequestLocked(requestID)
}

// AuthorizeFederationRequest and SendFederationRequest are explicit state
// transitions for callers that create a request in CREATED.  The normal
// CreateFederationRequest path validates both ends and queues PENDING requests
// immediately.
func (s *Store) AuthorizeFederationRequest(requestID string, args ...any) (*FederationRequest, error) {
	owner, epoch := parseOwnerEpoch(args)
	return s.transitionFederationRequest(gatewayTrim(requestID), "SOURCE_AUTHORIZED", owner, epoch, []string{FederationRequestCreated}, FederationRequestSourceAuthorized, "source representative authorized", "source")
}
func (s *Store) SendFederationRequest(requestID string, args ...any) (*FederationRequest, error) {
	owner, epoch := parseOwnerEpoch(args)
	return s.transitionFederationRequest(gatewayTrim(requestID), "SENT", owner, epoch, []string{FederationRequestSourceAuthorized, FederationRequestSent}, FederationRequestPending, "sent to target representative", "source")
}
func (s *Store) DispatchFederationRequest(requestID string, args ...any) (*FederationRequest, error) {
	return s.SendFederationRequest(requestID, args...)
}

func (s *Store) AcceptFederationRequest(requestID string, args ...any) (*FederationRequest, error) {
	owner, epoch := parseOwnerEpoch(args)
	return s.transitionFederationRequest(gatewayTrim(requestID), "ACCEPTED", owner, epoch, []string{FederationRequestPending, FederationRequestSent}, FederationRequestAccepted, "target representative accepted", "target")
}
func (s *Store) BeginFederationRequest(requestID string, args ...any) (*FederationRequest, error) {
	owner, epoch := parseOwnerEpoch(args)
	return s.transitionFederationRequest(gatewayTrim(requestID), "IN_PROGRESS", owner, epoch, []string{FederationRequestAccepted, FederationRequestInProgress}, FederationRequestInProgress, "target representative started work", "target")
}

func (s *Store) scanMailbox(row interface{ Scan(...any) error }) (*RepresentativeMailboxItem, error) {
	var item RepresentativeMailboxItem
	err := row.Scan(&item.ID, &item.RequestID, &item.GroupID, &item.RepresentativeEndpointID, &item.RepresentativeAssignmentID, &item.OwnerID, &item.OwnerEpoch, &item.State, &item.AvailableAt, &item.Deadline, &item.Attempts, &item.LastError, &item.ClaimedAt, &item.DeliveredAt, &item.CreatedAt, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	item.MailboxID = item.ID
	item.FederationRequestID = item.RequestID
	return &item, nil
}

const gatewayMailboxColumns = `id, request_id, group_id, representative_endpoint_id,
representative_assignment_id, owner_id, owner_epoch, state, available_at,
deadline, attempts, last_error, claimed_at, delivered_at, created_at, updated_at`

func parseMailboxClaim(input any, args []any) (RepresentativeMailboxClaimInput, error) {
	var claim RepresentativeMailboxClaimInput
	switch value := input.(type) {
	case RepresentativeMailboxClaimInput:
		claim = value
	case string:
		claim.RepresentativeAssignmentID = value
		if len(args) > 0 {
			claim.OwnerID, _ = args[0].(string)
		}
		if len(args) > 1 {
			switch epoch := args[1].(type) {
			case uint64:
				claim.Epoch = epoch
			case int:
				if epoch >= 0 {
					claim.Epoch = uint64(epoch)
				}
			}
		}
	default:
		return claim, errors.New("mailbox claim input is invalid")
	}
	if claim.OwnerID == "" {
		claim.OwnerID = claim.Owner
	}
	claim.OwnerID = gatewayTrim(claim.OwnerID)
	if claim.OwnerID == "" || claim.RepresentativeAssignmentID == "" || claim.Epoch == 0 {
		return claim, errors.New("mailbox assignment, owner, and epoch are required")
	}
	claim.Limit = gatewayLimit(claim.Limit)
	return claim, nil
}

// ClaimRepresentativeMailbox claims durable requests for the currently leased
// representative.  It can be called after an offline period; no presence bit
// is used to discard queued work.
func (s *Store) ClaimRepresentativeMailbox(input any, args ...any) ([]RepresentativeMailboxItem, error) {
	claim, err := parseMailboxClaim(input, args)
	if err != nil {
		return nil, err
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(e error) ([]RepresentativeMailboxItem, error) { _ = tx.Rollback(); return nil, e }
	var assignmentGroup, assignmentEndpoint, assignmentOwner string
	var assignmentEpoch uint64
	var assignmentStatus string
	if err := tx.QueryRow(`SELECT group_id, endpoint_id, owner_id, epoch, status FROM gateway_v2_representatives WHERE id = ?`, claim.RepresentativeAssignmentID).Scan(&assignmentGroup, &assignmentEndpoint, &assignmentOwner, &assignmentEpoch, &assignmentStatus); errors.Is(err, sql.ErrNoRows) {
		return rollback(ErrRepresentativeAssignmentNotFound)
	} else if err != nil {
		return rollback(err)
	}
	if assignmentOwner != claim.OwnerID {
		return rollback(ErrGatewayLeaseOwner)
	}
	if assignmentEpoch != claim.Epoch {
		return rollback(ErrGatewayStaleEpoch)
	}
	if assignmentStatus != RepresentativeAssignmentActive {
		return rollback(ErrGatewayInvalidState)
	}
	if claim.GroupID != "" && claim.GroupID != assignmentGroup {
		return rollback(ErrGatewayGroupMismatch)
	}
	if claim.RepresentativeEndpointID != "" && claim.RepresentativeEndpointID != assignmentEndpoint {
		return rollback(ErrGatewayGroupMismatch)
	}
	if err := gatewayDeadlineValid((func() string {
		var deadline string
		_ = tx.QueryRow(`SELECT lease_expires_at FROM gateway_v2_representatives WHERE id = ?`, claim.RepresentativeAssignmentID).Scan(&deadline)
		return deadline
	})(), time.Now().UTC()); err != nil {
		return rollback(ErrGatewayLeaseExpired)
	}
	rows, err := tx.Query(`SELECT `+gatewayMailboxColumns+` FROM gateway_v2_mailbox WHERE group_id = ? AND representative_endpoint_id = ? AND representative_assignment_id = ? AND state = ? AND available_at <= ? AND deadline > ? ORDER BY available_at, id LIMIT ?`, assignmentGroup, assignmentEndpoint, claim.RepresentativeAssignmentID, RepresentativeMailboxReady, timestamp, timestamp, claim.Limit)
	if err != nil {
		return rollback(err)
	}
	items := []RepresentativeMailboxItem{}
	ids := []string{}
	for rows.Next() {
		item, scanErr := s.scanMailbox(rows)
		if scanErr != nil {
			rows.Close()
			return rollback(scanErr)
		}
		items = append(items, *item)
		ids = append(ids, item.ID)
	}
	if err := rows.Close(); err != nil {
		return rollback(err)
	}
	for _, id := range ids {
		if _, err := tx.Exec(`UPDATE gateway_v2_mailbox SET state = ?, owner_id = ?, owner_epoch = ?, attempts = attempts + 1, claimed_at = ?, updated_at = ? WHERE id = ? AND state = ?`, RepresentativeMailboxClaimed, claim.OwnerID, claim.Epoch, timestamp, timestamp, id, RepresentativeMailboxReady); err != nil {
			return rollback(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	for index := range items {
		items[index].State = RepresentativeMailboxClaimed
		items[index].OwnerID = claim.OwnerID
		items[index].OwnerEpoch = claim.Epoch
		items[index].Attempts++
		items[index].ClaimedAt = timestamp
		items[index].UpdatedAt = timestamp
	}
	return items, nil
}

func (s *Store) ListRepresentativeMailbox(groupID, endpointID string, limit int) ([]RepresentativeMailboxItem, error) {
	limit = gatewayLimit(limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT `+gatewayMailboxColumns+` FROM gateway_v2_mailbox WHERE (? = '' OR group_id = ?) AND (? = '' OR representative_endpoint_id = ?) ORDER BY available_at, id LIMIT ?`, gatewayTrim(groupID), gatewayTrim(groupID), gatewayTrim(endpointID), gatewayTrim(endpointID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []RepresentativeMailboxItem{}
	for rows.Next() {
		item, err := s.scanMailbox(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *item)
	}
	return result, rows.Err()
}
func (s *Store) GetRepresentativeMailbox(id string) (*RepresentativeMailboxItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, err := s.scanMailbox(s.db.QueryRow(`SELECT `+gatewayMailboxColumns+` FROM gateway_v2_mailbox WHERE id = ?`, gatewayTrim(id)))
	if err != nil {
		return nil, err
	}
	if item == nil {
		return nil, ErrRepresentativeMailboxNotFound
	}
	return item, nil
}

func (s *Store) AcknowledgeRepresentativeMailbox(id, ownerID string, epoch uint64) (*RepresentativeMailboxItem, error) {
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`UPDATE gateway_v2_mailbox SET state = ?, delivered_at = ?, updated_at = ? WHERE id = ? AND state = ? AND owner_id = ? AND owner_epoch = ?`, RepresentativeMailboxDelivered, timestamp, timestamp, id, RepresentativeMailboxClaimed, ownerID, epoch)
	if err != nil {
		return nil, err
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		return nil, ErrGatewayStaleEpoch
	}
	return s.scanMailbox(s.db.QueryRow(`SELECT `+gatewayMailboxColumns+` FROM gateway_v2_mailbox WHERE id = ?`, id))
}

func (s *Store) SubmitFederationResult(result FederationResult, args ...any) (*FederationRequest, error) {
	result.ID = gatewayTrim(result.ID)
	if result.ID == "" {
		result.ID = gatewayTrim(result.ResultID)
	}
	if result.ID == "" {
		result.ID = NewID("fresult")
	}
	result.ResultID = result.ID
	if result.RequestID == "" {
		result.RequestID = gatewayTrim(result.FederationRequestID)
	}
	result.RequestID = gatewayTrim(result.RequestID)
	result.FederationRequestID = result.RequestID
	if result.Digest == "" {
		result.Digest = gatewayTrim(result.ResultDigest)
	}
	result.Digest = gatewayTrim(result.Digest)
	result.ArtifactRefs = gatewayStringSlice(result.ArtifactRefs)
	result.EvidenceRefs = gatewayStringSlice(result.EvidenceRefs)
	result.ProvenanceRefs = gatewayStringSlice(result.ProvenanceRefs)
	result.ProducerPrincipalID = gatewayTrim(result.ProducerPrincipalID)
	result.ProducerEndpointID = gatewayTrim(result.ProducerEndpointID)
	result.ProducerGroupID = gatewayTrim(result.ProducerGroupID)
	owner, epoch := parseOwnerEpoch(args)
	if owner == "" {
		owner = gatewayTrim(result.SubmittedByOwnerID)
	}
	if epoch == 0 {
		epoch = result.SubmittedByEpoch
	}
	if result.RequestID == "" || result.Digest == "" || result.ProducerPrincipalID == "" || result.ProducerGroupID == "" {
		return nil, errors.New("result request, digest, producer principal, and producer group are required")
	}
	artifactJSON, err := gatewayJSON(result.ArtifactRefs, "[]")
	if err != nil {
		return nil, err
	}
	evidenceJSON, err := gatewayJSON(result.EvidenceRefs, "[]")
	if err != nil {
		return nil, err
	}
	provenanceJSON, err := gatewayJSON(result.ProvenanceRefs, "[]")
	if err != nil {
		return nil, err
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(e error) (*FederationRequest, error) { _ = tx.Rollback(); return nil, e }
	request, err := scanFederationRequest(tx.QueryRow(`SELECT `+gatewayRequestColumns+` FROM gateway_v2_requests WHERE id = ?`, result.RequestID))
	if err != nil {
		return rollback(err)
	}
	if request == nil {
		return rollback(ErrFederationRequestNotFound)
	}
	var currentOwner string
	var currentEpoch uint64
	if err := tx.QueryRow(`SELECT owner_id, epoch FROM gateway_v2_representatives WHERE id = ?`, request.TargetRepresentativeAssignmentID).Scan(&currentOwner, &currentEpoch); err != nil {
		return rollback(ErrRepresentativeAssignmentNotFound)
	}
	if owner == "" {
		return rollback(ErrGatewayLeaseOwner)
	}
	if currentOwner != owner {
		return rollback(ErrGatewayLeaseOwner)
	}
	if currentEpoch != epoch {
		return rollback(ErrGatewayStaleEpoch)
	}
	if err := gatewayCheckAssignmentLeaseTx(tx, request.TargetRepresentativeAssignmentID, owner, epoch); err != nil {
		return rollback(err)
	}
	var existingDigest, existingState string
	lookupErr := tx.QueryRow(`SELECT digest, state FROM gateway_v2_results WHERE request_id = ?`, request.ID).Scan(&existingDigest, &existingState)
	if lookupErr == nil {
		if existingDigest != result.Digest {
			return rollback(ErrGatewayDigestConflict)
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return request, nil
	}
	if !errors.Is(lookupErr, sql.ErrNoRows) {
		return rollback(lookupErr)
	}
	late := request.State == FederationRequestExpired || request.State == FederationRequestCancelled || request.State == FederationRequestClosed || request.State == FederationRequestRejected || request.State == FederationRequestFailed || request.State == FederationRequestLateResult
	resultState := FederationResultSubmitted
	nextRequestState := FederationRequestResultSubmitted
	if late {
		resultState = FederationResultLate
		nextRequestState = FederationRequestLateResult
	}
	_, err = tx.Exec(`INSERT INTO gateway_v2_results (id, request_id, digest, state, producer_principal_id, producer_endpoint_id, producer_group_id, artifact_refs_json, evidence_refs_json, provenance_refs_json, verification_level, payload_ref, submitted_by_endpoint_id, submitted_by_owner_id, submitted_by_epoch, late_for_state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, result.ID, request.ID, result.Digest, resultState, result.ProducerPrincipalID, result.ProducerEndpointID, result.ProducerGroupID, artifactJSON, evidenceJSON, provenanceJSON, result.VerificationLevel, result.PayloadRef, result.SubmittedByEndpointID, owner, epoch, request.State, timestamp, timestamp)
	if err != nil {
		return rollback(fmt.Errorf("insert federation result: %w", err))
	}
	if _, err := tx.Exec(`UPDATE gateway_v2_requests SET state = ?, target_state = ?, producer_principal_id = ?, producer_endpoint_id = ?, producer_group_id = ?, evidence_refs_json = ?, provenance_refs_json = ?, result_id = ?, result_digest = ?, result_submitted_at = ?, late_result_at = CASE WHEN ? = 1 THEN ? ELSE late_result_at END, updated_at = ? WHERE id = ?`, nextRequestState, nextRequestState, result.ProducerPrincipalID, result.ProducerEndpointID, result.ProducerGroupID, evidenceJSON, provenanceJSON, result.ID, result.Digest, timestamp, boolInt(late), timestamp, timestamp, request.ID); err != nil {
		return rollback(err)
	}
	if err := gatewayInsertEventTx(tx, request.ID, resultState, request.State, nextRequestState, owner, epoch, func() string {
		if late {
			return "result arrived after terminal request"
		}
		return "producer result submitted"
	}(), timestamp); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getFederationRequestLocked(request.ID)
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func scanFederationResult(row interface{ Scan(...any) error }) (*FederationResult, error) {
	var result FederationResult
	var artifactJSON, evidenceJSON, provenanceJSON string
	err := row.Scan(&result.ID, &result.RequestID, &result.Digest, &result.State, &result.ProducerPrincipalID, &result.ProducerEndpointID, &result.ProducerGroupID, &artifactJSON, &evidenceJSON, &provenanceJSON, &result.VerificationLevel, &result.PayloadRef, &result.SubmittedByEndpointID, &result.SubmittedByOwnerID, &result.SubmittedByEpoch, &result.LateForState, &result.CreatedAt, &result.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result.ResultID = result.ID
	result.FederationRequestID = result.RequestID
	result.ResultDigest = result.Digest
	result.ArtifactRefs, err = gatewayDecodeStrings(artifactJSON)
	if err != nil {
		return nil, err
	}
	result.EvidenceRefs, err = gatewayDecodeStrings(evidenceJSON)
	if err != nil {
		return nil, err
	}
	result.ProvenanceRefs, err = gatewayDecodeStrings(provenanceJSON)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

const gatewayResultColumns = `id, request_id, digest, state, producer_principal_id,
producer_endpoint_id, producer_group_id, artifact_refs_json, evidence_refs_json,
provenance_refs_json, verification_level, payload_ref, submitted_by_endpoint_id,
submitted_by_owner_id, submitted_by_epoch, late_for_state, created_at, updated_at`

func (s *Store) GetFederationResult(id string) (*FederationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := scanFederationResult(s.db.QueryRow(`SELECT `+gatewayResultColumns+` FROM gateway_v2_results WHERE id = ?`, gatewayTrim(id)))
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrFederationResultNotFound
	}
	return result, nil
}
func (s *Store) GetFederationResultForRequest(requestID string) (*FederationResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := scanFederationResult(s.db.QueryRow(`SELECT `+gatewayResultColumns+` FROM gateway_v2_results WHERE request_id = ?`, gatewayTrim(requestID)))
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrFederationResultNotFound
	}
	return result, nil
}

func (s *Store) AcceptFederationResult(requestID string, args ...any) (*FederationRequest, error) {
	var resultID string
	var rest []any
	if len(args) > 0 {
		resultID, _ = args[0].(string)
		rest = args[1:]
	}
	owner, epoch := parseOwnerEpoch(rest)
	if owner == "" && len(args) > 0 {
		owner, epoch = parseOwnerEpoch(args)
	}
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(e error) (*FederationRequest, error) { _ = tx.Rollback(); return nil, e }
	request, err := scanFederationRequest(tx.QueryRow(`SELECT `+gatewayRequestColumns+` FROM gateway_v2_requests WHERE id = ?`, requestID))
	if err != nil {
		return rollback(err)
	}
	if request == nil {
		return rollback(ErrFederationRequestNotFound)
	}
	if resultID == "" {
		resultID = request.ResultID
	}
	var resultState, resultDigest string
	if err := tx.QueryRow(`SELECT state, digest FROM gateway_v2_results WHERE id = ? AND request_id = ?`, resultID, requestID).Scan(&resultState, &resultDigest); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return rollback(ErrFederationResultNotFound)
		}
		return rollback(err)
	}
	if resultState == FederationResultAccepted && request.State == FederationRequestResultAccepted {
		if err := tx.Commit(); err != nil {
			return nil, err
		}
		return request, nil
	}
	if resultState != FederationResultSubmitted {
		return rollback(ErrGatewayInvalidState)
	}
	var sourceOwner string
	var sourceEpoch uint64
	if err := tx.QueryRow(`SELECT owner_id, epoch FROM gateway_v2_representatives WHERE id = ?`, request.SourceRepresentativeAssignmentID).Scan(&sourceOwner, &sourceEpoch); err != nil {
		return rollback(ErrRepresentativeAssignmentNotFound)
	}
	if sourceOwner != owner {
		return rollback(ErrGatewayLeaseOwner)
	}
	if sourceEpoch != epoch {
		return rollback(ErrGatewayStaleEpoch)
	}
	if err := gatewayCheckAssignmentLeaseTx(tx, request.SourceRepresentativeAssignmentID, owner, epoch); err != nil {
		return rollback(err)
	}
	if request.State != FederationRequestResultSubmitted {
		return rollback(ErrGatewayInvalidState)
	}
	if _, err := tx.Exec(`UPDATE gateway_v2_results SET state = ?, updated_at = ? WHERE id = ? AND state = ?`, FederationResultAccepted, timestamp, resultID, FederationResultSubmitted); err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec(`UPDATE gateway_v2_requests SET state = ?, source_state = ?, result_accepted_at = ?, updated_at = ? WHERE id = ? AND state = ?`, FederationRequestResultAccepted, FederationRequestResultAccepted, timestamp, timestamp, requestID, FederationRequestResultSubmitted); err != nil {
		return rollback(err)
	}
	if err := gatewayInsertEventTx(tx, requestID, FederationRequestResultAccepted, request.State, FederationRequestResultAccepted, owner, epoch, "source representative accepted result", timestamp); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getFederationRequestLocked(requestID)
}

func (s *Store) SettleFederationRequest(requestID string, args ...any) (*FederationRequest, error) {
	owner, epoch := parseOwnerEpoch(args)
	return s.transitionFederationRequest(gatewayTrim(requestID), "CLOSED", owner, epoch, []string{FederationRequestResultAccepted}, FederationRequestClosed, "federation request settled", "source")
}
func (s *Store) CloseFederationRequest(requestID string, args ...any) (*FederationRequest, error) {
	return s.SettleFederationRequest(requestID, args...)
}
func (s *Store) SettleFederationResult(requestID string, args ...any) (*FederationRequest, error) {
	return s.SettleFederationRequest(requestID, args...)
}

func (s *Store) finishFederationRequest(requestID, state, event, reason string) (*FederationRequest, error) {
	timestamp := now()
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	rollback := func(e error) (*FederationRequest, error) { _ = tx.Rollback(); return nil, e }
	request, err := scanFederationRequest(tx.QueryRow(`SELECT `+gatewayRequestColumns+` FROM gateway_v2_requests WHERE id = ?`, requestID))
	if err != nil {
		return rollback(err)
	}
	if request == nil {
		return rollback(ErrFederationRequestNotFound)
	}
	if request.State == FederationRequestClosed || request.State == FederationRequestCancelled || request.State == FederationRequestExpired {
		if request.State == state {
			if err := tx.Commit(); err != nil {
				return nil, err
			}
			return request, nil
		}
		return rollback(ErrGatewayInvalidState)
	}
	if state == FederationRequestExpired {
		if _, err := gatewayParseTime(request.Deadline); err != nil {
			return rollback(ErrGatewayDeadline)
		}
	}
	if _, err := tx.Exec(`UPDATE gateway_v2_requests SET state = ?, source_state = ?, target_state = ?, expired_at = CASE WHEN ? = ? THEN ? ELSE expired_at END, cancelled_at = CASE WHEN ? = ? THEN ? ELSE cancelled_at END, cancel_requested_at = CASE WHEN ? = ? THEN ? ELSE cancel_requested_at END, updated_at = ? WHERE id = ?`, state, state, state, state, FederationRequestExpired, timestamp, state, FederationRequestCancelled, timestamp, state, FederationRequestCancelRequested, timestamp, timestamp, requestID); err != nil {
		return rollback(err)
	}
	if _, err := tx.Exec(`UPDATE gateway_v2_mailbox SET state = CASE WHEN ? = ? THEN ? ELSE ? END, updated_at = ? WHERE request_id = ? AND state IN (?, ?)`, state, FederationRequestExpired, RepresentativeMailboxExpired, RepresentativeMailboxCancelled, timestamp, requestID, RepresentativeMailboxReady, RepresentativeMailboxClaimed); err != nil {
		return rollback(err)
	}
	if err := gatewayInsertEventTx(tx, requestID, event, request.State, state, "", 0, reason, timestamp); err != nil {
		return rollback(err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.getFederationRequestLocked(requestID)
}

func (s *Store) CancelFederationRequest(requestID, reason string) (*FederationRequest, error) {
	return s.finishFederationRequest(gatewayTrim(requestID), FederationRequestCancelled, "CANCELLED", reason)
}
func (s *Store) RequestFederationCancellation(requestID, reason string) (*FederationRequest, error) {
	return s.finishFederationRequest(gatewayTrim(requestID), FederationRequestCancelRequested, "CANCEL_REQUESTED", reason)
}
func (s *Store) ExpireFederationRequest(requestID, reason string) (*FederationRequest, error) {
	return s.finishFederationRequest(gatewayTrim(requestID), FederationRequestExpired, "EXPIRED", reason)
}

func (s *Store) SweepExpiredFederationRequests(limit int) ([]FederationRequest, error) {
	limit = gatewayLimit(limit)
	s.mu.Lock()
	var ids []string
	rows, err := s.db.Query(`SELECT id FROM gateway_v2_requests WHERE state IN (?, ?, ?, ?) AND deadline <= ? ORDER BY deadline, id LIMIT ?`, FederationRequestCreated, FederationRequestSourceAuthorized, FederationRequestSent, FederationRequestPending, now(), limit)
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			s.mu.Unlock()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	s.mu.Unlock()
	result := make([]FederationRequest, 0, len(ids))
	for _, id := range ids {
		request, err := s.ExpireFederationRequest(id, "deadline reached")
		if err != nil {
			return nil, err
		}
		result = append(result, *request)
	}
	return result, nil
}
