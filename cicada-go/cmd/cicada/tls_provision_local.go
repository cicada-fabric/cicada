package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

const tlsProvisionUsage = "usage: cicada tls-provision node-binding-request|hub-binding-export|node-prepare|hub-issuer-profile|hub-reserve|hub-inspect|hub-issue|node-stage|hub-ack|hub-activate|node-apply [--db HUB_DB] [--state-dir NODE_DIR --writer-root DIR --node-id ID --hub-id ID --origin URL] --input FILE --output NEW_FILE"
const tlsProvisionBindingAAD = "cicada/node/tls-provision-binding/v1\x00"

type tlsProvisionBindingRequest struct {
	Version          int                 `json:"version"`
	Nonce            string              `json:"nonce"`
	NodeID           string              `json:"node_id"`
	HubID            string              `json:"hub_id"`
	CredentialDigest string              `json:"credential_digest"`
	BindingID        string              `json:"binding_id"`
	BindingVersion   uint64              `json:"binding_version"`
	NodeKeyVersion   uint64              `json:"node_key_version"`
	NodeKeyEpoch     uint64              `json:"node_key_epoch"`
	HubKeyVersion    uint64              `json:"hub_key_version"`
	NodePublic       e2ee.PublicIdentity `json:"node_public"`
	HubPublic        e2ee.PublicIdentity `json:"hub_public"`
}
type tlsProvisionBindingReply struct {
	Version       int                           `json:"version"`
	RequestSHA256 string                        `json:"request_sha256"`
	IssuedAt      string                        `json:"issued_at"`
	ExpiresAt     string                        `json:"expires_at"`
	Binding       nodetransport.TLSLocalBinding `json:"binding"`
}

// Every Hub mutation acquires the existing state startup lease. Nodes never
// open a Hub database. This is a stopped-state operator ceremony, not an RPC,
// model tool, enrollment approval or a new Client capability.
func tlsProvisionLocalCommand(args []string, output io.Writer) error {
	if len(args) == 0 || output == nil {
		return errors.New(tlsProvisionUsage)
	}
	phase := args[0]
	f := flag.NewFlagSet("tls-provision "+phase, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	dbPath := f.String("db", "", "existing stopped private Hub database; Hub phases only")
	state := f.String("state-dir", "", "existing private Node state")
	writer := f.String("writer-root", "", "existing private Node writer root")
	nodeID := f.String("node-id", "", "existing independently approved Node ID")
	hubID := f.String("hub-id", "", "existing independently pinned Hub ID")
	origin := f.String("origin", "", "existing application origin")
	input := f.String("input", "", "bounded phase input JSON or sealed envelope")
	destination := f.String("output", "", "new private phase output")
	requestID := f.String("request-id", "", "existing TLS preparation request")
	challenge := f.String("challenge", "", "original private Node binding request")
	grant := f.String("grant", "", "canonical independently Owner-signed grant")
	ack := f.String("ack", "", "canonical NodeControl install ACK")
	issuerChain := f.String("issuer-chain", "", "reviewed issuer chain")
	issuerKey := f.String("issuer-key", "", "private issuer key; hub-issue only")
	root := f.String("root", "", "independently trusted root")
	preparation := f.String("preparation", "", "reviewed Node TLS preparation request JSON")
	hubTrust := f.String("hub-trust", "", "independently trusted Hub TLS root")
	hubKey := f.String("hub-key", "", "existing private HubControl identity; export/activate only")
	if f.Parse(args[1:]) != nil || len(f.Args()) != 0 || *destination == "" {
		return errors.New(tlsProvisionUsage)
	}
	if _, err := os.Lstat(*destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("phase output must not already exist")
	}
	var result any
	var raw []byte
	if strings.HasPrefix(phase, "hub-") {
		if *dbPath == "" || *state != "" || *writer != "" {
			return errors.New(tlsProvisionUsage)
		}
		canonical, err := canonicalExistingLocalHubDB(*dbPath)
		if err != nil {
			return err
		}
		db, err := store.NewForOfflineMaintenance(canonical)
		if err != nil {
			return err
		}
		defer db.Close()
		switch phase {
		case "hub-inspect":
			if *requestID == "" {
				return errors.New(tlsProvisionUsage)
			}
			snapshot, err := db.GetNodeTLSAuthorityReservationLocal(*requestID)
			if err != nil {
				return err
			}
			result = snapshot
		case "hub-issuer-profile":
			chain, err := readOwnerNetworkKeyFile(*issuerChain, 128<<10, false)
			if err != nil {
				return err
			}
			secret, err := recoveryReadPrivateFile(*issuerKey, 32<<10)
			if err != nil {
				return err
			}
			defer clear(secret)
			trust, err := readOwnerNetworkKeyFile(*root, 32<<10, false)
			if err != nil {
				return err
			}
			issuer, profile, err := pqtls.ImportTLSIssuer(chain, secret, trust, "node", time.Now().UTC().Truncate(time.Second))
			if err != nil {
				return err
			}
			defer issuer.Destroy()
			result = profile
		case "hub-binding-export":
			var req tlsProvisionBindingRequest
			data, err := tlsProvisionReadJSON(*input, &req)
			if err != nil {
				return err
			}
			b, err := db.NodeControlKeyForCredential(req.CredentialDigest, req.NodeID)
			if err != nil || req.Version != 1 || len(req.Nonce) != 64 || b.HubID != req.HubID || b.OwnerBindingID != req.BindingID || b.BindingVersion != req.BindingVersion || b.NodeKeyVersion != req.NodeKeyVersion || b.NodeKeyEpoch != req.NodeKeyEpoch || b.HubKeyVersion != req.HubKeyVersion || !reflect.DeepEqual(b.NodePublicIdentity, req.NodePublic) || !reflect.DeepEqual(b.HubPublicIdentity, req.HubPublic) {
				return errors.New("binding request differs from current approved Node")
			}
			if nonce, err := hex.DecodeString(req.Nonce); err != nil || len(nonce) != 32 {
				return errors.New("invalid binding nonce")
			}
			owner, err := db.GetOwnerApprovalKey(b.OwnerID, b.OwnerKeyID)
			if err != nil {
				return err
			}
			device, err := db.GetClientDevice(b.OwnerID, b.ClientDeviceID)
			if err != nil {
				return err
			}
			identity, err := control.LoadExistingNodeTLSHubIdentity(*hubKey)
			if err != nil || !reflect.DeepEqual(identity.Public(), b.HubPublicIdentity) {
				return errors.New("HubControl key differs from current approval")
			}
			at := time.Now().UTC().Truncate(time.Second)
			body, err := json.Marshal(tlsProvisionBindingReply{1, e2ee.NodeTLSAuthorityDigest(data), at.Format(time.RFC3339), at.Add(5 * time.Minute).Format(time.RFC3339), nodetransport.TLSLocalBinding{Control: *b, OwnerKeyVersion: uint64(owner.Version), ClientDeviceVersion: uint64(device.Version)}})
			if err != nil {
				return err
			}
			raw, err = e2ee.Seal(identity, b.NodePublicIdentity, body, []byte(tlsProvisionBindingAAD+req.Nonce), 1)
			if err != nil {
				return err
			}
		case "hub-reserve":
			var candidate store.NodeTLSCandidateInput
			if _, err := tlsProvisionReadJSON(*input, &candidate); err != nil {
				return err
			}
			snapshot, err := db.ReserveNodeTLSCandidate(candidate)
			if err != nil {
				return err
			}
			result = snapshot
		case "hub-issue", "hub-ack", "hub-activate":
			var action store.NodeTLSAuthorityActionInput
			if _, err := tlsProvisionReadJSON(*input, &action); err != nil {
				return err
			}
			var snapshot *store.NodeTLSAuthoritySnapshot
			if phase == "hub-issue" {
				proof, err := recoveryReadPrivateFile(*grant, e2ee.MaxNodeTLSProofBytes)
				if err != nil {
					return err
				}
				chain, err := readOwnerNetworkKeyFile(*issuerChain, 128<<10, false)
				if err != nil {
					return err
				}
				secret, err := recoveryReadPrivateFile(*issuerKey, 32<<10)
				if err != nil {
					return err
				}
				defer clear(secret)
				trust, err := readOwnerNetworkKeyFile(*root, 32<<10, false)
				if err != nil {
					return err
				}
				issuer, _, err := pqtls.ImportTLSIssuer(chain, secret, trust, "node", time.Now().UTC().Truncate(time.Second))
				if err != nil {
					return err
				}
				defer issuer.Destroy()
				snapshot, err = db.IssueNodeTLSLeaf(store.NodeTLSLeafIssueInput{NodeTLSAuthorityActionInput: action, Grant: proof}, issuer)
				if err != nil {
					return err
				}
			} else if phase == "hub-ack" {
				proof, err := recoveryReadPrivateFile(*ack, e2ee.MaxNodeTLSProofBytes)
				if err != nil {
					return err
				}
				snapshot, err = db.RecordNodeTLSInstallAck(store.NodeTLSInstallAckInput{NodeTLSAuthorityActionInput: action, InstallAck: proof})
				if err != nil {
					return err
				}
			} else {
				nonce := make([]byte, 32)
				if _, err := rand.Read(nonce); err != nil {
					return err
				}
				claims, err := db.PrepareNodeTLSActivation(action, hex.EncodeToString(nonce))
				if err != nil {
					return err
				}
				identity, err := control.LoadExistingNodeTLSHubIdentity(*hubKey)
				if err != nil {
					return err
				}
				proof, err := e2ee.SignNodeTLSActivation(identity, claims)
				if err != nil {
					return err
				}
				snapshot, err = db.ActivateNodeTLSGrant(store.NodeTLSActivationInput{NodeTLSAuthorityActionInput: action, Activation: proof})
				if err != nil {
					return err
				}
			}
			result = snapshot
		default:
			return errors.New(tlsProvisionUsage)
		}
	} else {
		if *dbPath != "" || *issuerKey != "" || *hubKey != "" || *state == "" || *nodeID == "" || *hubID == "" || *origin == "" {
			return errors.New(tlsProvisionUsage)
		}
		if *writer == "" {
			*writer = *state
		}
		hub := &machineHubContext{StateDir: *state, WriterRoot: *writer, NodeID: *nodeID, HubID: *hubID, Origin: *origin}
		client, token, err := loadMachineRecoveryClient(*state, *nodeID)
		if err != nil || client.state.HubID != *hubID || client.state.HubOrigin != *origin || !client.bindingReady() {
			return errors.New("existing Owner-approved local NodeControl binding required")
		}
		if phase == "node-binding-request" {
			nonce := make([]byte, 32)
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			result = tlsProvisionBindingRequest{Version: 1, Nonce: hex.EncodeToString(nonce), NodeID: *nodeID, HubID: *hubID, CredentialDigest: fabric.HashSessionCredential(token), BindingID: client.state.BindingID, BindingVersion: client.state.BindingVersion, NodeKeyVersion: client.state.NodeKeyVersion, NodeKeyEpoch: client.state.NodeKeyEpoch, HubKeyVersion: client.state.HubKeyVersion, NodePublic: client.identity.Public(), HubPublic: client.state.HubPublicIdentity}
		} else {
			var binding nodetransport.TLSLocalBinding
			var bindingChallengeBytes []byte
			var bindingChallengeNonce string
			if phase == "node-prepare" {
				var req tlsProvisionBindingRequest
				challengeBytes, err := tlsProvisionReadJSON(*challenge, &req)
				if err != nil {
					return err
				}
				sealed, err := recoveryReadPrivateFile(*input, 1<<20)
				if err != nil {
					return err
				}
				body, seq, err := e2ee.Open(client.identity, client.state.HubPublicIdentity, sealed, []byte(tlsProvisionBindingAAD+req.Nonce))
				if err != nil || seq != 1 {
					return errors.New("offline binding response authentication failed")
				}
				defer clear(body)
				var reply tlsProvisionBindingReply
				if decodeStrictBridgeJSON(body, &reply) != nil || reply.Version != 1 || reply.RequestSHA256 != e2ee.NodeTLSAuthorityDigest(challengeBytes) {
					return errors.New("offline binding response differs from Node challenge")
				}
				issued, e1 := time.Parse(time.RFC3339, reply.IssuedAt)
				expires, e2 := time.Parse(time.RFC3339, reply.ExpiresAt)
				at := time.Now().UTC()
				if e1 != nil || e2 != nil || at.Before(issued) || !at.Before(expires) || expires.Sub(issued) != 5*time.Minute {
					return errors.New("offline binding response expired")
				}
				binding = reply.Binding
				binding.Control.CredentialDigest = fabric.HashSessionCredential(token)
				bindingChallengeBytes = bytes.Clone(challengeBytes)
				bindingChallengeNonce = req.Nonce
			} else {
				var accepted struct {
					Version                                   int
					Request                                   nodetransport.TLSPreparationRequest
					Binding                                   nodetransport.TLSLocalBinding
					CredentialDigest, CSRDERHash, SPKIDERHash string
					Floor                                     uint64
				}
				base := filepath.Join(*state, ".node-tls", e2ee.NodeTLSAuthorityDigest([]byte(*hubID+"\x00"+*nodeID)), "prepared", e2ee.NodeTLSAuthorityDigest([]byte(*requestID)), "preparation.json")
				if _, err := tlsProvisionReadJSON(base, &accepted); err != nil || accepted.Request.RequestID != *requestID {
					return errors.New("independently retained original TLS preparation required")
				}
				binding = accepted.Binding
				binding.Control.CredentialDigest = accepted.CredentialDigest
			}
			installer, closeLocal, err := tlsProvisionNodeLocal(hub, binding)
			if err != nil {
				return err
			}
			defer closeLocal()
			at := time.Now().UTC().Truncate(time.Second)
			switch phase {
			case "node-prepare":
				var request nodetransport.TLSPreparationRequest
				if _, err := tlsProvisionReadJSON(*preparation, &request); err != nil {
					return err
				}
				trust, err := installer.OwnerTrust.GetNodeOwnerKeyTrustLocal(binding.Control.OwnerID, binding.Control.OwnerKeyID)
				if err != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive {
					return errors.New("independent active Node Owner trust required")
				}
				if err := tlsProvisionConsumeBinding(hub, bindingChallengeBytes, bindingChallengeNonce, request.RequestID); err != nil {
					return err
				}
				prepared, err := installer.Prepare(request, at)
				if err != nil {
					return err
				}
				result = prepared
			case "node-stage", "node-apply":
				var snapshot store.NodeTLSAuthoritySnapshot
				if _, err := tlsProvisionReadJSON(*input, &snapshot); err != nil {
					return err
				}
				if snapshot.Claims.RequestID != *requestID {
					return errors.New("snapshot differs from local preparation request")
				}
				if phase == "node-stage" {
					trust, err := readOwnerNetworkKeyFile(*hubTrust, 32<<10, false)
					if err != nil {
						return err
					}
					raw, err = installer.Stage(snapshot, snapshot.IssuerChainPEM, snapshot.TrustAnchorPEM, trust, at)
					if err != nil {
						return err
					}
				} else {
					dir := filepath.Join(*state, ".node-tls", e2ee.NodeTLSAuthorityDigest([]byte(*hubID+"\x00"+*nodeID)), "epochs", strconv.FormatUint(snapshot.Claims.TLSEpoch, 10)+"-"+e2ee.NodeTLSAuthorityDigest(snapshot.Grant))
					var staged struct {
						Version     int
						Claims      e2ee.OwnerTLSLeafGrantClaims
						Grant, Ack  []byte
						LeafDERHash string
						Config      nodetransport.Config
					}
					if _, err := tlsProvisionReadJSON(filepath.Join(dir, "stage.json"), &staged); err != nil || staged.Claims != snapshot.Claims || !bytes.Equal(staged.Grant, snapshot.Grant) || !bytes.Equal(staged.Ack, snapshot.InstallAck) {
						return errors.New("independently verified local TLS stage required")
					}
					installer.CurrentActiveAuthority = func() (*store.NodeTLSAuthoritySnapshot, error) {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						return machineTLSQueryCurrentWithLocal(ctx, hub, &staged.Config, client, token, binding, installer)
					}
					cfg, err := installer.Apply(snapshot, at)
					if err != nil {
						return err
					}
					result = cfg
				}
			default:
				return errors.New(tlsProvisionUsage)
			}
		}
	}
	if raw == nil {
		var err error
		raw, err = json.Marshal(result)
		if err != nil {
			return err
		}
	}
	if err := tlsProvisionWriteNew(*destination, raw); err != nil {
		return err
	}
	return json.NewEncoder(output).Encode(map[string]any{"phase": phase, "output_sha256": e2ee.NodeTLSAuthorityDigest(raw)})
}

// A validated offline response is consumed once before Prepare. Failed/crashed
// preparation burns this challenge; obtain a fresh nonce rather than reusing a
// sequence-one envelope in a normal NodeControl conversation.
func tlsProvisionConsumeBinding(hub *machineHubContext, data []byte, nonce, requestID string) error {
	if len(data) == 0 || len(nonce) != 64 {
		return errors.New("authenticated binding challenge required")
	}
	writer, err := nodelock.AcquireWriterRootExclusive(hub.WriterRoot)
	if err != nil {
		return err
	}
	defer writer.Close()
	node, err := nodelock.AcquireMaintenanceExclusive(hub.StateDir, hub.NodeID)
	if err != nil {
		return err
	}
	defer node.Close()
	if err := rejectMachineRecoveryMutation(hub.StateDir, hub.WriterRoot, hub.NodeID); err != nil {
		return err
	}
	dir := filepath.Join(machineNodeStateDir(hub.StateDir, hub.NodeID), "tls-provision-consumed")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return err
	}
	err = parent.Sync()
	closeErr := parent.Close()
	if err != nil || closeErr != nil {
		return errors.New("offline nonce ledger directory is not durable")
	}
	if err := recoveryPrivatePath(dir, true); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) >= 100000 {
		return errors.New("offline binding nonce ledger unavailable or full")
	}
	marker := []byte(e2ee.NodeTLSAuthorityDigest(data) + "\n" + requestID)
	return tlsProvisionWriteNew(filepath.Join(dir, e2ee.NodeTLSAuthorityDigest([]byte(nonce))), marker)
}

func tlsProvisionReadJSON(path string, value any) ([]byte, error) {
	data, err := recoveryReadPrivateFile(path, 1<<20)
	if err != nil {
		return nil, err
	}
	if err := decodeStrictBridgeJSON(data, value); err != nil {
		return nil, errors.New("invalid bounded phase JSON")
	}
	return data, nil
}
func tlsProvisionWriteNew(path string, data []byte) error {
	if recoveryPrivatePath(filepath.Dir(path), true) != nil {
		return errors.New("phase output parent must already be private without symlinks")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(path)
		return errors.New("could not persist phase output")
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}

func tlsProvisionNodeLocal(hub *machineHubContext, binding nodetransport.TLSLocalBinding) (*nodetransport.LocalTLSInstaller, func(), error) {
	client, token, err := loadMachineRecoveryClient(hub.StateDir, hub.NodeID)
	if err != nil {
		return nil, nil, err
	}
	check := func() (nodetransport.TLSLocalBinding, error) {
		c, t, e := loadMachineRecoveryClient(hub.StateDir, hub.NodeID)
		if e != nil {
			return nodetransport.TLSLocalBinding{}, e
		}
		s, b := c.state, binding.Control
		if t != token || b.State != "ACTIVE" || b.HubID != hub.HubID || b.NodeID != hub.NodeID || s.HubOrigin != hub.Origin || s.HubID != b.HubID || b.CredentialDigest != fabric.HashSessionCredential(t) || s.BindingID != b.OwnerBindingID || s.BindingVersion != b.BindingVersion || s.NodeKeyID != b.NodeKeyID || s.NodeKeyVersion != b.NodeKeyVersion || s.NodeKeyEpoch != b.NodeKeyEpoch || s.NodeKeyFingerprint != b.NodeKeyFingerprint || s.HubKeyID != b.HubKeyID || s.HubKeyVersion != b.HubKeyVersion || s.HubFingerprint != b.HubKeyFingerprint || s.ApprovedRequestID != b.ApprovedRequestID || s.ApprovedRequestVersion != b.ApprovedRequestVersion || s.ApprovedCandidateDigest != b.ApprovedCandidateDigest || !reflect.DeepEqual(c.identity.Public(), b.NodePublicIdentity) || !reflect.DeepEqual(s.HubPublicIdentity, b.HubPublicIdentity) {
			return nodetransport.TLSLocalBinding{}, nodetransport.ErrTLSInstall
		}
		return binding, nil
	}
	if _, err := check(); err != nil {
		return nil, nil, err
	}
	reader, err := nodekeys.OpenExistingCryptoStateReadOnly(machineNodeStateDir(hub.StateDir, hub.NodeID))
	if err != nil {
		return nil, nil, err
	}
	current := func() (nodetransport.TLSLocalBinding, error) {
		if err := reader.CheckStable(); err != nil {
			return nodetransport.TLSLocalBinding{}, err
		}
		return check()
	}
	keys := func() ([][]byte, error) {
		known, err := reader.RetainedSigningPublicKeys()
		if err != nil {
			return nil, err
		}
		prepared := filepath.Join(hub.StateDir, ".node-tls", e2ee.NodeTLSAuthorityDigest([]byte(hub.HubID+"\x00"+hub.NodeID)), "prepared")
		if _, err := os.Lstat(prepared); err == nil {
			old, err := nodetransport.ReadRetainedTLSPreparationSigningPublicKeys(hub.StateDir, hub.WriterRoot, hub.HubID, hub.NodeID)
			if err != nil {
				return nil, err
			}
			known = append(known, old...)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		for _, identity := range []e2ee.PublicIdentity{client.state.HubCandidateIdentity, client.state.HubPublicIdentity, client.identity.Public()} {
			if identity.ID != "" {
				if e2ee.ValidatePublicIdentity(identity) != nil {
					return nil, nodetransport.ErrTLSInstall
				}
				known = append(known, bytes.Clone(identity.SigningPublic))
			}
		}
		if err := reader.CheckStable(); err != nil {
			return nil, err
		}
		return known, nil
	}
	i := &nodetransport.LocalTLSInstaller{StateRoot: hub.StateDir, WriterRoot: hub.WriterRoot, HubID: hub.HubID, NodeID: hub.NodeID, CurrentBinding: current, OwnerTrust: reader.State, NodeControlIdentity: client.identity, KnownApplicationPublicKeys: keys}
	return i, func() { reader.Close() }, nil
}
