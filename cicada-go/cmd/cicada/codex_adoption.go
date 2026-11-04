package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
)

// The production resolver is the common Manager's verified explicit
// from-service receipt. This private adapter never widens pin equality or
// infers adoption from matching IDs, paths, an empty epoch or a cached hint.
type codexAdoptionResolver func(context.Context, LocalNodeConnectionPin) (LocalNodeConnection, error)

func validateCodexAdoption(ctx context.Context, original, current LocalNodeConnectionPin, resolve codexAdoptionResolver) error {
	if resolve == nil || original.ConnectionID != "" || original.ConnectionEpoch != 0 || current.ConnectionID == "" || current.ConnectionEpoch != 1 || validateLocalNodePin(original) != nil || validateLocalNodePin(current) != nil {
		return ErrLocalNodeBindingChanged
	}
	legacy := current
	legacy.ConnectionID, legacy.ConnectionEpoch = "", 0
	if !sameLocalNodeAuthority(original, legacy) {
		return ErrLocalNodeBindingChanged
	}
	verified, err := resolve(ctx, original)
	if err != nil || !sameLocalNodeAuthority(verified.Pin, current) {
		return ErrLocalNodeBindingChanged
	}
	return nil
}

func validateCodexCachedAdoption(cached *mcpCachedSession, current *LocalNodeConnection, resolve codexAdoptionResolver) error {
	err := validateCodexCachedConnection(cached, current)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrLocalNodeBindingChanged) || cached == nil || cached.ConnectionPin == nil || current == nil {
		return err
	}
	if err := validateCodexAdoption(context.Background(), *cached.ConnectionPin, current.Pin, resolve); err != nil {
		return codexLocalNodeError(err)
	}
	return nil
}

func (m *mcpServer) validateCachedConnection(cached *mcpCachedSession) error {
	if err := validateCodexCachedAdoption(cached, m.localNode, m.adoptConnection); err != nil {
		return err
	}
	m.sessionMu.Lock()
	m.sessionStoragePin = nil
	if cached != nil && cached.ConnectionPin != nil && m.localNode != nil && !sameLocalNodeAuthority(*cached.ConnectionPin, m.localNode.Pin) {
		original := *cached.ConnectionPin
		m.sessionStoragePin = &original
	}
	m.sessionMu.Unlock()
	return nil
}

// The fence was installed in the main DB before WAL was enabled. Reading only
// that immutable metadata is sufficient here; operation lookup uses mode=ro to
// include the WAL. Neither path upgrades or replaces the historical DB pin.
func readCodexOriginalOutboxPin(path string) (*LocalNodeConnectionPin, error) {
	before, err := codexOperatorPrivateFile(path, true)
	if err != nil {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	if before == nil {
		return nil, nil
	}
	db, err := sql.Open("sqlite", mcpOutboxSQLiteURI(path, "mode=ro&immutable=1"))
	if err != nil {
		return nil, errMCPOutboxPersistence
	}
	defer db.Close()
	var count int
	if db.QueryRow("SELECT count(*) FROM mcp_outbox_connection_pin").Scan(&count) != nil || count != 1 {
		return nil, ErrLocalNodeConfigRequired
	}
	var format string
	var raw []byte
	if db.QueryRow(`SELECT format,CASE WHEN length(CAST(pin AS BLOB))<=? THEN pin ELSE NULL END FROM mcp_outbox_connection_pin WHERE slot=1`, localNodeMaxPinBytes).Scan(&format, &raw) != nil || format != mcpOutboxConnectionFormat {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	var pin LocalNodeConnectionPin
	if decodeLocalNodeJSON(raw, &pin) != nil || validateLocalNodePin(pin) != nil {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) {
		return nil, ErrLocalNodeDiscoveryInvalid
	}
	return &pin, nil
}

func (m *mcpServer) bridgeOriginalOutbox() error {
	if m.localNode == nil || m.outbox == nil {
		return nil
	}
	store := m.outbox
	store.mu.Lock()
	defer store.mu.Unlock()
	original, err := readCodexOriginalOutboxPin(store.path)
	if err != nil {
		return err
	}
	if original == nil || sameLocalNodeAuthority(*original, m.localNode.Pin) {
		store.connectionPin = m.localNodePin()
		return nil
	}
	if err := validateCodexAdoption(context.Background(), *original, m.localNode.Pin, m.adoptConnection); err != nil {
		return codexLocalNodeError(err)
	}
	// Only the in-memory storage adapter references the retained old pin. The
	// actual child, live/epoch checks, socket and HTTP transport stay managed.
	store.connectionPin = original
	return nil
}

func (c *codexOperatorIntentClient) sameConnectionPin(current, original *LocalNodeConnectionPin) bool {
	if sameCodexOperatorConnectionPin(current, original) {
		return true
	}
	if current == nil || original == nil {
		return false
	}
	return validateCodexAdoption(context.Background(), *original, *current, c.adoptConnection) == nil
}
