package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cicada-ai/cicada/internal/store"
)

func (b *machineAgentJoinBridge) regroupHTTP(sessionToken, route string, input, output any) error {
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > 4096 {
		return errors.New("invalid bounded regroup request")
	}
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost,
		b.baseURL+"/v2/fabric/node/regroup/"+route, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", "CicadaNode "+b.nodeToken)
	r.Header.Set("Cicada-Regroup-Session", "CicadaSession "+sessionToken)
	r.Header.Set("Content-Type", "application/json")
	response, err := (&http.Client{Timeout: 30 * time.Second, CheckRedirect: rejectNodeRedirect}).Do(r)
	if err != nil {
		return &localSealedSendError{message: "could not reach authorized Hub regroup route", retryable: true}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 16*1024))
	if err != nil || len(data) >= 16*1024 {
		return errors.New("Hub returned oversized regroup result")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &localSealedSendError{message: fmt.Sprintf("regroup request failed with HTTP %d", response.StatusCode),
			retryable: response.StatusCode == http.StatusRequestTimeout || response.StatusCode >= 500}
	}
	if err := decodeStrictBridgeJSON(data, output); err != nil {
		return errors.New("Hub returned invalid regroup result")
	}
	return nil
}

func (b *machineAgentJoinBridge) regroupSpace(request groupSpaceLocalRequest) (*groupSpaceLocalResult, error) {
	result := &groupSpaceLocalResult{}
	switch request.Operation {
	case "space_regroup_propose":
		if request.RegroupInput == nil || request.RegroupInput.SourceGroupID != request.GroupID {
			return nil, errors.New("regroup source must match the selected joined Group")
		}
		var proposal store.RegroupProposal
		if err := b.regroupHTTP(request.SessionToken, "propose", request.RegroupInput, &proposal); err != nil {
			return nil, err
		}
		if proposal.ProposalID == "" || proposal.Input.SourceGroupID != request.GroupID ||
			proposal.EndpointID != request.EndpointID || proposal.BindingEpoch != request.BindingEpoch {
			return nil, errors.New("Hub returned mismatched regroup proposal")
		}
		result.RegroupProposal = &proposal
	case "space_regroup_apply":
		if request.ProposalID == "" || request.DelegationID == "" {
			return nil, errors.New("regroup apply requires exact proposal and delegation")
		}
		var applied store.RegroupApplyResult
		if err := b.regroupHTTP(request.SessionToken, "apply", map[string]string{
			"proposal_id": request.ProposalID, "delegation_id": request.DelegationID}, &applied); err != nil {
			return nil, err
		}
		if applied.ProposalID != request.ProposalID || applied.DelegationID != request.DelegationID || applied.AuditID == "" {
			return nil, errors.New("Hub returned mismatched delegated regroup result")
		}
		result.RegroupApply = &applied
	default:
		return nil, errors.New("invalid regroup operation")
	}
	return result, nil
}
