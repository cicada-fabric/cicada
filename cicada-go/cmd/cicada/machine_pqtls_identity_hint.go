package main

import (
	"encoding/hex"
	"errors"
	"sync/atomic"
)

// An existing Owner-approved application identity supplies only the missing
// startup coordinate. OpenRuntime still checks the independent floor, Owner
// trust, original Prepare, staged material and a new remote current query under
// its locks. Neither a TLS config nor a bundle can supply this identity hint.
func recoverMachinePQHubIdentityHint(hub *machineHubContext, pqConfigPath string) error {
	if pqConfigPath == "" || hub == nil || hub.HubID != "" {
		return nil
	}
	client, _, err := loadMachineRecoveryClient(hub.StateDir, hub.NodeID)
	if err != nil {
		return errors.New("existing approved NodeControl identity required before PQ TLS startup")
	}
	s := client.state
	digest, err := hex.DecodeString(s.ApprovedCandidateDigest)
	if !client.bindingReady() || s.HubOrigin != hub.Origin || s.NodeID != hub.NodeID || s.HubID == "" || s.ApprovedRequestID == "" || s.ApprovedRequestVersion <= 0 || err != nil || len(digest) != 32 || hex.EncodeToString(digest) != s.ApprovedCandidateDigest {
		return errors.New("approved NodeControl startup coordinates are incomplete or mismatched")
	}
	if hub.approvedHubID == nil {
		hub.approvedHubID = &atomic.Pointer[string]{}
	}
	id := s.HubID
	if !hub.approvedHubID.CompareAndSwap(nil, &id) {
		if existing := hub.approvedHubID.Load(); existing == nil || *existing != id {
			return errors.New("approved Hub identity cannot replace the startup pin")
		}
	}
	hub.HubID = id
	return nil
}
