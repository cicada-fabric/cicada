// client-recovery-fixture creates interrupted Client RPC states in a disposable
// Hub database. It is a test tool, never part of the Hub runtime image.
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/clientwire"
	"github.com/cicada-ai/cicada/internal/store"
	_ "modernc.org/sqlite"
)

const disposableMarker = ".cicada-disposable-recovery-fixture"

func main() {
	if err := run(os.Args[1:], os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, "recovery fixture:", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "fixture prepared")
}

func run(args []string, input io.Reader) error {
	flags := flag.NewFlagSet("client-recovery-fixture", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dbPath := flags.String("db", "", "disposable Hub SQLite database")
	mode := flags.String("mode", "", "processing, uncertain, or legacy")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("usage: client-recovery-fixture --db PATH --mode processing|uncertain|legacy < original-packet.json")
	}
	if *mode != "processing" && *mode != "uncertain" && *mode != "legacy" {
		return errors.New("invalid fixture mode")
	}
	if err := requireDisposableDatabase(*dbPath); err != nil {
		return err
	}
	packetBytes, err := io.ReadAll(io.LimitReader(input, 256*1024+1))
	if err != nil || len(packetBytes) == 0 || len(packetBytes) > 256*1024 {
		return errors.New("invalid packet size")
	}
	var packet clientwire.Packet
	if err := json.Unmarshal(packetBytes, &packet); err != nil ||
		packet.Route.Version != clientwire.Version ||
		packet.Route.Direction != clientwire.DirectionRequest || len(packet.Envelope) == 0 {
		return errors.New("invalid Client request packet")
	}
	db, err := store.New(*dbPath)
	if err != nil {
		return err
	}
	defer db.Close()
	hubID, err := db.GetClientHubID()
	if err != nil || packet.Route.HubID != hubID {
		return errors.New("packet targets a different Hub")
	}
	digest := sha256.Sum256(packetBytes)
	request := store.AcceptClientRequestInput{
		OwnerID: packet.Route.OwnerID, DeviceID: packet.Route.DeviceID,
		SessionEpoch: packet.Route.SessionEpoch, Sequence: packet.Route.Sequence,
		OperationID: packet.Route.OperationID, CiphertextDigest: hex.EncodeToString(digest[:]),
	}
	accepted, err := db.AcceptClientRequest(request)
	if err != nil {
		return err
	}
	if accepted.Outcome != store.ClientRequestOutcomeNew {
		return errors.New("fixture requires a fresh request; existing operation was not changed")
	}
	if *mode == "processing" {
		return nil
	}
	if *mode == "uncertain" {
		if _, err := db.ReserveClientRequestResponseSequence(request); err != nil {
			return err
		}
		// Leave PROCESSING. Only an actual Hub restart may fence this request
		// as UNCERTAIN; the fixture must not pretend that a crash happened.
		return nil
	}
	if _, err := db.UpdateClientRequestStatus(request.OwnerID, request.DeviceID,
		request.OperationID, store.ClientRequestUncertain); err != nil {
		return err
	}
	// A pre-v29 accepted request has no response-reservation row. Delete only
	// this newly created marker; never alter the schema or another request.
	legacyDB, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		return err
	}
	defer legacyDB.Close()
	removed, err := legacyDB.Exec(`DELETE FROM client_device_request_recovery_v2 WHERE request_id=?`, accepted.Request.ID)
	if err != nil {
		return err
	}
	count, err := removed.RowsAffected()
	if err != nil || count != 1 {
		return errors.New("legacy marker removal failed")
	}
	return nil
}

func requireDisposableDatabase(path string) error {
	if path == "" {
		return errors.New("database path required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	root, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return err
	}
	temporary, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(temporary, root)
	if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || relative == ".." {
		return errors.New("fixture database must be inside a dedicated temporary directory")
	}
	marker, err := os.ReadFile(filepath.Join(root, disposableMarker))
	if err != nil || strings.TrimSpace(string(marker)) != "disposable" {
		return errors.New("missing disposable recovery fixture marker")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("fixture database does not exist")
	}
	return nil
}
