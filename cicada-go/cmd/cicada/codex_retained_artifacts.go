package main

import (
	"context"
	"errors"
)

// This proves storage continuity only. It deliberately cannot return a live
// connection, caller context, ticket or permission to dispatch an old request.
type codexArtifactValidator func(context.Context, LocalNodeConnectionPin, LocalNodeConnectionPin) error

func validateCodexStoredArtifact(ctx context.Context, historical, current LocalNodeConnectionPin, adopt codexAdoptionResolver, retained codexArtifactValidator) error {
	if sameLocalNodeAuthority(historical, current) {
		return nil
	}
	if validateCodexAdoption(ctx, historical, current, adopt) == nil {
		return nil
	}
	if retained == nil || validateLocalNodePin(historical) != nil || validateLocalNodePin(current) != nil || current.ConnectionID == "" || historical.ConnectionEpoch >= current.ConnectionEpoch || historical.ConnectionID != "" && historical.ConnectionID != current.ConnectionID {
		return ErrLocalNodeBindingChanged
	}
	// Only local admission coordinates may differ. Original keys, binding,
	// paths and Hub trust still compare under the existing strict rules.
	storage := current
	storage.ConnectionID, storage.ConnectionEpoch = historical.ConnectionID, historical.ConnectionEpoch
	if !sameLocalNodeAuthority(historical, storage) {
		return ErrLocalNodeBindingChanged
	}
	if err := retained(ctx, historical, current); err != nil {
		return err
	}
	return nil
}

func validateCodexCachedArtifact(cached *mcpCachedSession, current *LocalNodeConnection, adopt codexAdoptionResolver, retained codexArtifactValidator) error {
	err := validateCodexCachedConnection(cached, current)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrLocalNodeBindingChanged) || cached == nil || cached.ConnectionPin == nil || current == nil {
		return err
	}
	if err := validateCodexStoredArtifact(context.Background(), *cached.ConnectionPin, current.Pin, adopt, retained); err != nil {
		return codexLocalNodeError(err)
	}
	return nil
}

// An original intent may be located and compared as data before current
// authorization. callForConnection separately requires its private fresh Host
// authorizer before exchange or returning a completed result across epochs.
func (c *codexOperatorIntentClient) validateIntentArtifact(current, historical *LocalNodeConnectionPin) error {
	if c.sameConnectionPin(current, historical) {
		return nil
	}
	if current == nil || historical == nil {
		return ErrLocalNodeBindingChanged
	}
	return validateCodexStoredArtifact(context.Background(), *historical, *current, c.adoptConnection, c.retainedArtifacts)
}

type codexRetainedIntentAuthorizer func(localEndpointRequest, LocalNodeConnection) (*endpointGroupsOperatorContextProof, error)

func (c *codexOperatorIntentClient) authorizeRetainedIntent(original localEndpointRequest, current LocalNodeConnection) (*endpointGroupsOperatorContextProof, error) {
	if c.retainedInvocation == nil || original.EndpointGroupsVersion != 1 {
		return nil, errCodexMCPContext
	}
	if err := revalidateCodexLocalNode(context.Background(), &current); err != nil {
		return nil, err
	}
	proof, err := c.retainedInvocation(original, current)
	if err != nil || proof == nil || !localContextHex(proof.ContextTicketID, 64) || !localContextHex(proof.ContextConnectionNonce, 64) || proof.ContextTicketID == original.ContextTicketID || proof.ContextConnectionNonce == original.ContextConnectionNonce {
		return nil, errCodexMCPContext
	}
	if err := revalidateCodexLocalNode(context.Background(), &current); err != nil {
		return nil, err
	}
	return proof, nil
}
