package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodeinbox"
	"github.com/cicada-ai/cicada/internal/store"
)

// machineRelayJournalEntry contains remote delivery coordinates and signed
// clear route metadata. The message body remains in nodeinbox's SQLite payload
// column, and sealed ciphertext remains in nodekeys' durable crypto inbox;
// neither payload is copied into this recovery journal or an error message.
type machineRelayJournalEntry struct {
	MessageID         string                      `json:"message_id"`
	RequestID         string                      `json:"request_id,omitempty"`
	Kind              string                      `json:"kind,omitempty"`
	GroupID           string                      `json:"group_id,omitempty"`
	NetworkID         string                      `json:"network_id,omitempty"`
	SenderEndpointID  string                      `json:"sender_endpoint_id,omitempty"`
	ReplyTo           string                      `json:"reply_to,omitempty"`
	Digest            string                      `json:"digest"`
	EndpointID        string                      `json:"endpoint_id"`
	BindingID         string                      `json:"binding_id"`
	BindingEpoch      uint64                      `json:"binding_epoch"`
	AttemptID         string                      `json:"attempt_id"`
	SessionID         string                      `json:"session_id"`
	Harness           string                      `json:"harness"`
	NodeReceived      bool                        `json:"node_received,omitempty"`
	QueueAccepted     bool                        `json:"codex_queue_accepted,omitempty"`
	QueueAcceptedSent bool                        `json:"codex_queue_accepted_sent,omitempty"`
	RuntimeInjected   bool                        `json:"runtime_injected,omitempty"`
	ConsumptionSent   bool                        `json:"consumption_unconfirmed,omitempty"`
	UncertainSent     bool                        `json:"injection_uncertain,omitempty"`
	FailedSent        bool                        `json:"failed,omitempty"`
	PayloadMode       string                      `json:"payload_mode,omitempty"`
	DataScope         string                      `json:"data_scope,omitempty"`
	AuthorizationKind string                      `json:"authorization_kind,omitempty"`
	SealedRoute       *store.RelaySealedV1Route   `json:"sealed_route,omitempty"`
	SealedSecurity    *store.RelayMessageSecurity `json:"sealed_security,omitempty"`
}

type machineRelayJournalDisk struct {
	Deliveries []machineRelayJournalEntry `json:"deliveries"`
}

type machineRelayJournal struct {
	path       string
	deliveries []machineRelayJournalEntry
}

func machineNodeStateDir(stateDir, machineID string) string {
	// Prefixing the escaped ID means values such as ".." can never become a
	// path component that escapes the configured state directory.
	return filepath.Join(stateDir, "nodes", "node-"+urlPath(machineID))
}

func machineNodeInboxPath(stateDir, machineID string) string {
	return filepath.Join(machineNodeStateDir(stateDir, machineID), "inbox.sqlite")
}

func openMachineRelayJournal(stateDir, machineID string) (*machineRelayJournal, error) {
	path := filepath.Join(machineNodeStateDir(stateDir, machineID), "relay-journal.json")
	journal := &machineRelayJournal{path: path, deliveries: make([]machineRelayJournalEntry, 0)}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return journal, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read machine relay journal: %w", err)
	}
	var disk machineRelayJournalDisk
	if err := json.Unmarshal(data, &disk); err != nil {
		return nil, fmt.Errorf("decode machine relay journal: %w", err)
	}
	journal.deliveries = disk.Deliveries
	return journal, nil
}

func (j *machineRelayJournal) persist() error {
	if j == nil || strings.TrimSpace(j.path) == "" {
		return errors.New("machine relay journal is not initialized")
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return fmt.Errorf("create machine relay journal directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(j.path), ".relay-journal-*")
	if err != nil {
		return fmt.Errorf("create machine relay journal temporary file: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect machine relay journal: %w", err)
	}
	encoderErr := json.NewEncoder(temporary).Encode(machineRelayJournalDisk{Deliveries: j.deliveries})
	if encoderErr == nil {
		encoderErr = temporary.Sync()
	}
	closeErr := temporary.Close()
	if encoderErr != nil {
		return fmt.Errorf("write machine relay journal: %w", encoderErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close machine relay journal: %w", closeErr)
	}
	if err := os.Rename(temporaryName, j.path); err != nil {
		return fmt.Errorf("commit machine relay journal: %w", err)
	}
	return nil
}

func (j *machineRelayJournal) index(messageID string) int {
	for index := range j.deliveries {
		if j.deliveries[index].MessageID == messageID {
			return index
		}
	}
	return -1
}

func (j *machineRelayJournal) entry(messageID string) *machineRelayJournalEntry {
	index := j.index(messageID)
	if index < 0 {
		return nil
	}
	entry := j.deliveries[index]
	return &entry
}

func (j *machineRelayJournal) put(delivery fabric.Delivery) error {
	index := j.index(delivery.MessageID)
	entry := machineRelayJournalEntry{
		MessageID: delivery.MessageID, Digest: delivery.Digest,
		EndpointID: delivery.EndpointID, BindingID: delivery.BindingID,
		BindingEpoch: delivery.BindingEpoch, AttemptID: delivery.AttemptID,
		SessionID: delivery.NativeSessionID, Harness: delivery.Harness,
		RequestID: delivery.RequestID, Kind: delivery.Kind, GroupID: delivery.GroupID,
		SenderEndpointID: delivery.SenderEndpointID, ReplyTo: delivery.ReplyTo,
	}
	if index >= 0 {
		previous := j.deliveries[index]
		if previous.PayloadMode == "SEALED_V1" {
			return errors.New("machine relay message ID is already bound to a sealed payload")
		}
		if previous.Digest == entry.Digest && previous.AttemptID == entry.AttemptID {
			entry.NodeReceived = previous.NodeReceived
			entry.QueueAccepted = previous.QueueAccepted
			entry.QueueAcceptedSent = previous.QueueAcceptedSent
			entry.RuntimeInjected = previous.RuntimeInjected
			entry.ConsumptionSent = previous.ConsumptionSent
			entry.UncertainSent = previous.UncertainSent
			entry.FailedSent = previous.FailedSent
		}
		j.deliveries[index] = entry
	} else {
		j.deliveries = append(j.deliveries, entry)
	}
	return j.persist()
}

func (j *machineRelayJournal) update(messageID string, update func(*machineRelayJournalEntry)) error {
	index := j.index(messageID)
	if index < 0 {
		return fmt.Errorf("machine relay journal entry %s not found", messageID)
	}
	update(&j.deliveries[index])
	return j.persist()
}

func (j *machineRelayJournal) remove(messageID string) error {
	index := j.index(messageID)
	if index < 0 {
		return nil
	}
	j.deliveries = append(j.deliveries[:index], j.deliveries[index+1:]...)
	return j.persist()
}

func machineRelayConsumerID(machineID string) string {
	consumer := "machine-agent:" + strings.TrimSpace(machineID)
	if len(consumer) > 256 {
		consumer = consumer[:256]
	}
	return consumer
}

func processMachineFabricDeliveriesV2(ctx context.Context, base, machineID string, inbox *nodeinbox.Inbox, stateDirs ...string) error {
	if inbox == nil {
		return errors.New("machine node inbox is required for v2 relay delivery")
	}
	stateDir := ""
	if len(stateDirs) > 0 {
		stateDir = stateDirs[0]
	}
	if err := inbox.Recover(ctx); err != nil {
		return fmt.Errorf("recover machine node inbox: %w", err)
	}
	journal, err := openMachineRelayJournal(stateDir, machineID)
	if err != nil {
		return err
	}
	var sealedPayload struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	sealedEndpoint := base + "/v2/relay/nodes/" + urlPath(machineID) + "/sealed/claim"
	if err := machineAPIJSON(ctx, sealedEndpoint, http.MethodPost, map[string]any{
		"consumer_id": machineRelayConsumerID(machineID), "limit": 50,
	}, &sealedPayload); err != nil {
		return fmt.Errorf("claim v2 sealed relay deliveries: %w", err)
	}
	for _, delivery := range sealedPayload.Deliveries {
		if err := acceptMachineSealedRelayDelivery(ctx, base, machineID, stateDir, inbox, journal, delivery); err != nil {
			return err
		}
	}
	var groupSealedPayload struct {
		Deliveries []fabric.NodeSealedDelivery `json:"deliveries"`
	}
	groupSealedEndpoint := base + "/v2/relay/nodes/" + urlPath(machineID) + "/group/sealed/claim"
	if err := machineAPIJSON(ctx, groupSealedEndpoint, http.MethodPost, map[string]any{
		"consumer_id": machineRelayConsumerID(machineID), "limit": 50,
	}, &groupSealedPayload); err != nil {
		return fmt.Errorf("claim same-Group sealed relay deliveries: %w", err)
	}
	for _, delivery := range groupSealedPayload.Deliveries {
		if err := acceptMachineCrossNodeGroupDelivery(ctx, base, machineID, stateDir, inbox, journal, delivery); err != nil {
			return err
		}
	}
	var networkDirectPayload struct {
		Deliveries []fabric.NetworkDirectDelivery `json:"deliveries"`
	}
	if err := machineAPIJSON(ctx, base+"/v2/fabric/node/networks/direct/claim", http.MethodPost,
		map[string]any{"node_id": machineID, "consumer_id": machineRelayConsumerID(machineID), "limit": 50},
		&networkDirectPayload); err != nil {
		return fmt.Errorf("claim Network direct sealed deliveries: %w", err)
	}
	for _, delivery := range networkDirectPayload.Deliveries {
		if err := acceptMachineNetworkDirectDelivery(ctx, base, machineID, stateDir, inbox, journal, delivery); err != nil {
			return err
		}
	}
	var payload struct {
		Deliveries []fabric.Delivery `json:"deliveries"`
	}
	endpoint := base + "/v2/relay/nodes/" + urlPath(machineID) + "/claim"
	if err := machineAPIJSON(ctx, endpoint, http.MethodPost, map[string]any{
		"consumer_id": machineRelayConsumerID(machineID), "limit": 50,
	}, &payload); err != nil {
		return fmt.Errorf("claim v2 relay deliveries: %w", err)
	}
	if err := reconcileMachineRelayJournal(ctx, base, machineID, stateDir, inbox, journal); err != nil {
		return err
	}
	for _, delivery := range payload.Deliveries {
		if err := acceptMachineRelayDelivery(ctx, base, machineID, inbox, journal, delivery); err != nil {
			return err
		}
	}
	if err := reconcileMachineRelayJournal(ctx, base, machineID, stateDir, inbox, journal); err != nil {
		return err
	}
	return drainMachineRelayInbox(ctx, base, machineID, stateDir, inbox, journal)
}

func acceptMachineRelayDelivery(ctx context.Context, base, machineID string, inbox *nodeinbox.Inbox, journal *machineRelayJournal, delivery fabric.Delivery) error {
	if delivery.PayloadMode != "" && delivery.PayloadMode != "PLAINTEXT" {
		return fmt.Errorf("v2 relay delivery %s uses unsupported payload mode", delivery.MessageID)
	}
	if existing := journal.entry(delivery.MessageID); existing != nil && existing.PayloadMode == "SEALED_V1" {
		return errors.New("machine relay message ID is already bound to a sealed payload")
	}
	stored, _, err := inbox.Save(ctx, nodeinbox.Message{
		MessageID: delivery.MessageID, Digest: delivery.Digest,
		EndpointID: delivery.EndpointID, SessionID: delivery.NativeSessionID,
		BindingEpoch: delivery.BindingEpoch, Payload: []byte(delivery.Body),
	})
	if err != nil {
		return fmt.Errorf("save v2 relay delivery %s: %w", delivery.MessageID, err)
	}
	if stored == nil {
		return fmt.Errorf("save v2 relay delivery %s returned no record", delivery.MessageID)
	}
	if err := journal.put(delivery); err != nil {
		return fmt.Errorf("journal v2 relay delivery %s: %w", delivery.MessageID, err)
	}
	entry := journal.entry(delivery.MessageID)
	if entry == nil {
		return fmt.Errorf("journal v2 relay delivery %s is missing", delivery.MessageID)
	}
	if entry.NodeReceived {
		return nil
	}
	if err := reportMachineRelayReceiptReliably(ctx, base, machineID, *entry, fabric.ReceiptNodeReceived, ""); err != nil {
		return fmt.Errorf("report v2 NODE_RECEIVED for %s: %w", delivery.MessageID, err)
	}
	return journal.update(delivery.MessageID, func(entry *machineRelayJournalEntry) {
		entry.NodeReceived = true
	})
}

func reconcileMachineRelayJournal(ctx context.Context, base, machineID, stateDir string, inbox *nodeinbox.Inbox, journal *machineRelayJournal) error {
	for index := 0; index < len(journal.deliveries); index++ {
		entry := journal.deliveries[index]
		delivery, err := inbox.Get(ctx, entry.MessageID)
		if errors.Is(err, nodeinbox.ErrNotFound) {
			if entry.PayloadMode == "SEALED_V1" {
				recoveryErr := recoverMachineSealedInboxSave(ctx, base, stateDir, machineID, inbox, entry)
				if recoveryErr != nil {
					if entry.AuthorizationKind == "network-direct" && machineAPIHasStatus(recoveryErr,
						http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusGone) {
						if err := journal.remove(entry.MessageID); err != nil {
							return err
						}
						index--
						continue
					}
					// The remote claim can expire and be reissued under a new attempt.
					// Keep the journal until that happens; it is the only recovery
					// pointer to the ciphertext already committed in nodekeys.
					if machineAPIHasStatus(recoveryErr, http.StatusNotFound) {
						continue
					}
					return fmt.Errorf("recover sealed local relay delivery %s: %w", entry.MessageID, recoveryErr)
				}
				delivery, err = inbox.Get(ctx, entry.MessageID)
				if err != nil {
					return fmt.Errorf("read recovered sealed relay delivery %s: %w", entry.MessageID, err)
				}
			} else {
				if err := journal.remove(entry.MessageID); err != nil {
					return err
				}
				index--
				continue
			}
		}
		if err != nil {
			return fmt.Errorf("read local relay delivery %s: %w", entry.MessageID, err)
		}
		if entry.AuthorizationKind == "network-direct" {
			if delivery.State == nodeinbox.FAILED {
				if err := journal.remove(entry.MessageID); err != nil {
					return err
				}
				index--
				continue
			}
			if _, authErr := fetchMachineNetworkDirectAuthorization(ctx, base, entry.MessageID, entry.AttemptID); authErr != nil {
				if machineAPIHasStatus(authErr, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusGone) {
					if delivery.State == nodeinbox.NODE_RECEIVED {
						if err := retireMachineNetworkDirectDenied(ctx, inbox, journal, nodeinbox.Claim{Delivery: *delivery}, entry); err != nil {
							return err
						}
					} else if err := journal.remove(entry.MessageID); err != nil {
						return err
					}
					index--
					continue
				}
				return authErr
			}
		}
		if !entry.NodeReceived {
			if err := reportMachineRelayReceiptReliably(ctx, base, machineID, entry, fabric.ReceiptNodeReceived, ""); err != nil {
				return fmt.Errorf("report v2 NODE_RECEIVED for %s: %w", entry.MessageID, err)
			}
			if err := journal.update(entry.MessageID, func(entry *machineRelayJournalEntry) {
				entry.NodeReceived = true
			}); err != nil {
				return err
			}
			entry.NodeReceived = true
		}
		switch delivery.State {
		case nodeinbox.INJECTION_UNCERTAIN:
			if entry.QueueAccepted {
				if err := completeMachineRelayCodexQueue(ctx, base, machineID, inbox, journal,
					nodeinbox.Claim{Delivery: *delivery}, entry); err != nil {
					return err
				}
				index--
				continue
			}
			if entry.UncertainSent {
				continue
			}
			if err := reportMachineRelayReceiptReliably(ctx, base, machineID, entry, fabric.ReceiptInjectionUncertain, delivery.Failure); err != nil {
				return fmt.Errorf("report v2 INJECTION_UNCERTAIN for %s: %w", entry.MessageID, err)
			}
			if err := journal.update(entry.MessageID, func(entry *machineRelayJournalEntry) {
				entry.UncertainSent = true
			}); err != nil {
				return err
			}
		case nodeinbox.RUNTIME_INJECTED:
			if err := finishMachineRelayRuntime(ctx, base, machineID, inbox, journal, entry, false); err != nil {
				return err
			}
			if journal.index(entry.MessageID) < 0 {
				index--
			}
		case nodeinbox.CONSUMPTION_UNCONFIRMED:
			if entry.QueueAccepted {
				if err := completeMachineRelayCodexQueue(ctx, base, machineID, inbox, journal,
					nodeinbox.Claim{Delivery: *delivery}, entry); err != nil {
					return err
				}
				index--
				continue
			}
			if !entry.RuntimeInjected {
				if err := reportMachineRelayReceiptReliably(ctx, base, machineID, entry, fabric.ReceiptRuntimeInjected, ""); err != nil {
					return fmt.Errorf("report v2 RUNTIME_INJECTED for %s: %w", entry.MessageID, err)
				}
				if err := journal.update(entry.MessageID, func(entry *machineRelayJournalEntry) {
					entry.RuntimeInjected = true
				}); err != nil {
					return err
				}
				entry.RuntimeInjected = true
			}
			if err := reportMachineRelayConsumption(ctx, base, machineID, journal, entry); err != nil {
				return err
			}
			if journal.index(entry.MessageID) < 0 {
				index--
			}
		case nodeinbox.FAILED:
			if entry.FailedSent {
				continue
			}
			if err := reportMachineRelayReceiptReliably(ctx, base, machineID, entry, "FAILED", delivery.Failure); err != nil {
				return fmt.Errorf("report v2 FAILED for %s: %w", entry.MessageID, err)
			}
			if err := journal.remove(entry.MessageID); err != nil {
				return err
			}
			index--
		}
	}
	return nil
}

func drainMachineRelayInbox(ctx context.Context, base, machineID, stateDir string, inbox *nodeinbox.Inbox, journal *machineRelayJournal) error {
	consumerID := machineRelayConsumerID(machineID)
	for {
		claim, err := inbox.Claim(ctx, consumerID)
		if errors.Is(err, nodeinbox.ErrNoDelivery) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("claim local relay delivery: %w", err)
		}
		entry := journal.entry(claim.MessageID)
		if entry == nil {
			return fmt.Errorf("local relay delivery %s has no remote coordinates", claim.MessageID)
		}
		if !entry.NodeReceived {
			if err := reportMachineRelayReceiptReliably(ctx, base, machineID, *entry, fabric.ReceiptNodeReceived, ""); err != nil {
				return fmt.Errorf("report v2 NODE_RECEIVED for %s: %w", claim.MessageID, err)
			}
			if err := journal.update(claim.MessageID, func(entry *machineRelayJournalEntry) {
				entry.NodeReceived = true
			}); err != nil {
				return err
			}
			entry.NodeReceived = true
		}
		if entry.PayloadMode == "SEALED_V1" {
			var drainErr error
			if entry.AuthorizationKind == "network-direct" {
				drainErr = drainMachineNetworkDirectClaim(ctx, base, machineID, stateDir, inbox, journal, *claim, *entry)
			} else if entry.AuthorizationKind == "same-group" {
				drainErr = drainMachineCrossNodeGroupRelayClaim(ctx, base, machineID, stateDir, inbox, journal, *claim, *entry)
			} else {
				drainErr = drainMachineSealedRelayClaim(ctx, base, machineID, stateDir, inbox, journal, *claim, *entry)
			}
			if drainErr != nil {
				return drainErr
			}
			continue
		}
		if _, err := inbox.BeginInjection(ctx, claim.AttemptID); err != nil {
			if errors.Is(err, nodeinbox.ErrInjectionUncertain) {
				if !entry.UncertainSent {
					if receiptErr := reportMachineRelayReceiptReliably(ctx, base, machineID, *entry, fabric.ReceiptInjectionUncertain, ""); receiptErr != nil {
						return fmt.Errorf("report v2 INJECTION_UNCERTAIN for %s: %w", claim.MessageID, receiptErr)
					}
					if journalErr := journal.update(claim.MessageID, func(entry *machineRelayJournalEntry) {
						entry.UncertainSent = true
					}); journalErr != nil {
						return journalErr
					}
				}
				continue
			}
			return fmt.Errorf("begin injection for %s: %w", claim.MessageID, err)
		}
		if entry.Harness != "codex" {
			if err := failMachineRelayDelivery(ctx, base, machineID, inbox, journal, *claim, *entry,
				"exact native-session wake is not available for harness "+entry.Harness); err != nil {
				return err
			}
			continue
		}
		if err := executeMachineNativeCodex(ctx, claim.SessionID, machineRelayPrompt(*entry, claim.Payload)); err != nil {
			var uncertain *nativeInjectionUncertainError
			if errors.As(err, &uncertain) {
				receipt := machineRelayReceipt(*claim, nodeinbox.INJECTION_UNCERTAIN)
				receipt.Error = "native queue process started but injection could not be confirmed"
				if _, recordErr := inbox.Acknowledge(ctx, receipt); recordErr != nil {
					return recordErr
				}
				if reconcileErr := reconcileMachineRelayJournal(ctx, base, machineID, stateDir, inbox, journal); reconcileErr != nil {
					return reconcileErr
				}
				continue
			}
			if failErr := failMachineRelayDelivery(ctx, base, machineID, inbox, journal, *claim, *entry, err.Error()); failErr != nil {
				return failErr
			}
			continue
		}
		if err := completeMachineRelayCodexQueue(ctx, base, machineID, inbox, journal, *claim, *entry); err != nil {
			return err
		}
	}
}

func machineRelayReceipt(claim nodeinbox.Claim, state nodeinbox.State) nodeinbox.Receipt {
	return nodeinbox.Receipt{
		MessageID: claim.MessageID, Digest: claim.Digest, EndpointID: claim.EndpointID,
		SessionID: claim.SessionID, BindingEpoch: claim.BindingEpoch,
		AttemptID: claim.AttemptID, State: state,
	}
}

// completeMachineRelayCodexQueue persists the confirmed CLI queue result and
// reports that the queued message has not yet been confirmed as woken or
// consumed. It never infers RUNTIME_INJECTED from a zero queue exit.
func completeMachineRelayCodexQueue(ctx context.Context, base, machineID string, inbox *nodeinbox.Inbox,
	journal *machineRelayJournal, claim nodeinbox.Claim, entry machineRelayJournalEntry) error {
	if !entry.QueueAccepted {
		if err := journal.update(entry.MessageID, func(entry *machineRelayJournalEntry) {
			entry.QueueAccepted = true
		}); err != nil {
			return err
		}
		entry.QueueAccepted = true
	}
	if _, err := inbox.RecordCodexQueueAccepted(ctx, machineRelayReceipt(claim, nodeinbox.CONSUMPTION_UNCONFIRMED)); err != nil {
		return fmt.Errorf("record local CODEX_QUEUE_ACCEPTED for %s: %w", entry.MessageID, err)
	}
	if !entry.QueueAcceptedSent {
		if err := reportMachineRelayReceiptReliably(ctx, base, machineID, entry, fabric.ReceiptCodexQueueAccepted, ""); err != nil {
			return fmt.Errorf("report CODEX_QUEUE_ACCEPTED for %s: %w", entry.MessageID, err)
		}
		if err := journal.update(entry.MessageID, func(entry *machineRelayJournalEntry) {
			entry.QueueAcceptedSent = true
		}); err != nil {
			return err
		}
		entry.QueueAcceptedSent = true
	}
	if err := reportMachineRelayReceiptReliably(ctx, base, machineID, entry, fabric.ReceiptConsumptionUncertain, ""); err != nil {
		return fmt.Errorf("report queued but not consumed for %s: %w", entry.MessageID, err)
	}
	return journal.remove(entry.MessageID)
}

func finishMachineRelayRuntime(ctx context.Context, base, machineID string, inbox *nodeinbox.Inbox, journal *machineRelayJournal, entry machineRelayJournalEntry, localRuntimeAlreadyRecorded bool) error {
	if !entry.RuntimeInjected {
		if err := reportMachineRelayReceiptReliably(ctx, base, machineID, entry, fabric.ReceiptRuntimeInjected, ""); err != nil {
			return fmt.Errorf("report v2 RUNTIME_INJECTED for %s: %w", entry.MessageID, err)
		}
		if err := journal.update(entry.MessageID, func(entry *machineRelayJournalEntry) {
			entry.RuntimeInjected = true
		}); err != nil {
			return err
		}
		entry.RuntimeInjected = true
	}
	if !localRuntimeAlreadyRecorded {
		delivery, err := inbox.Get(ctx, entry.MessageID)
		if err != nil {
			return fmt.Errorf("read runtime delivery %s: %w", entry.MessageID, err)
		}
		if delivery.State == nodeinbox.RUNTIME_INJECTED {
			claim := nodeinbox.Claim{Delivery: *delivery}
			if _, err := inbox.RecordConsumptionUnconfirmed(ctx, machineRelayReceipt(claim, nodeinbox.CONSUMPTION_UNCONFIRMED)); err != nil {
				return fmt.Errorf("record local consumption uncertainty for %s: %w", entry.MessageID, err)
			}
		}
	}
	return reportMachineRelayConsumption(ctx, base, machineID, journal, entry)
}

func reportMachineRelayConsumption(ctx context.Context, base, machineID string, journal *machineRelayJournal, entry machineRelayJournalEntry) error {
	if entry.ConsumptionSent {
		return nil
	}
	if err := reportMachineRelayReceiptReliably(ctx, base, machineID, entry, fabric.ReceiptConsumptionUncertain, ""); err != nil {
		return fmt.Errorf("report v2 CONSUMPTION_UNCONFIRMED for %s: %w", entry.MessageID, err)
	}
	return journal.remove(entry.MessageID)
}

func failMachineRelayDelivery(ctx context.Context, base, machineID string, inbox *nodeinbox.Inbox, journal *machineRelayJournal, claim nodeinbox.Claim, entry machineRelayJournalEntry, reason string) error {
	if _, err := inbox.RecordFailed(ctx, machineRelayReceipt(claim, nodeinbox.FAILED), reason); err != nil {
		return fmt.Errorf("record local relay failure for %s: %w", claim.MessageID, err)
	}
	if entry.FailedSent {
		return journal.remove(entry.MessageID)
	}
	if err := reportMachineRelayReceiptReliably(ctx, base, machineID, entry, "FAILED", reason); err != nil {
		return fmt.Errorf("report v2 FAILED for %s: %w", claim.MessageID, err)
	}
	return journal.remove(entry.MessageID)
}

func reportMachineRelayReceiptReliably(ctx context.Context, base, machineID string, entry machineRelayJournalEntry, layer, reason string) error {
	endpoint := base + "/v2/relay/nodes/" + urlPath(machineID) + "/receipts"
	if entry.AuthorizationKind == "network-direct" {
		endpoint = base + "/v2/fabric/node/networks/direct/receipt"
	}
	payload := fabric.NodeReceiptInput{
		AttemptID: entry.AttemptID, MessageID: entry.MessageID, Digest: entry.Digest,
		EndpointID: entry.EndpointID, BindingID: entry.BindingID,
		BindingEpoch: entry.BindingEpoch, Layer: layer, Error: limitText(reason, 1024),
	}
	for {
		err := machineAPIJSON(ctx, endpoint, http.MethodPost, payload, nil)
		if err == nil {
			return nil
		}
		var apiErr *machineAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode >= 400 && apiErr.StatusCode < 500 {
			return err
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

// executeMachineNativeCodex uses the official queue subcommand and the exact
// native session ID from the v2 binding. It never sends keyboard input to a
// terminal and discards command output so a prompt cannot enter logs.
type nativeInjectionUncertainError struct{ cause error }

func (e *nativeInjectionUncertainError) Error() string {
	return "codex queue injection is uncertain: " + e.cause.Error()
}
func (e *nativeInjectionUncertainError) Unwrap() error { return e.cause }

func executeMachineNativeCodex(parent context.Context, nativeSessionID, prompt string) error {
	if strings.TrimSpace(nativeSessionID) == "" || prompt == "" {
		return errors.New("v2 relay delivery is missing its native session or body")
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	binary := strings.TrimSpace(os.Getenv("CICADA_CODEX_BIN"))
	if binary == "" {
		binary = "codex"
	}
	command := exec.CommandContext(ctx, binary, "queue", "--thread", nativeSessionID, "--message", prompt)
	command.Env = machineWorkerEnvironment(os.Environ(), true)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return fmt.Errorf("codex queue could not start: %w", err)
	}
	if err := command.Wait(); err != nil {
		if ctx.Err() != nil {
			return &nativeInjectionUncertainError{cause: ctx.Err()}
		}
		// A nonzero exit is not proof that the runtime made no durable write.
		// Without a native idempotency receipt, do not turn this into a retry.
		return &nativeInjectionUncertainError{cause: err}
	}
	return nil
}
