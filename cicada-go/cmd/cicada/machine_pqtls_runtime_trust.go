package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodekeys"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/nodewire"
	"github.com/cicada-ai/cicada/internal/store"
)

func machineTLSExistingBinding(hub *machineHubContext) (*machineNodeControlClient, string, nodetransport.TLSLocalBinding, error) {
	return machineTLSExistingBindingIn(hub, nil)
}
func machineTLSExistingBindingIn(hub *machineHubContext, cap *nodetransport.TLSMaintenanceRead) (*machineNodeControlClient, string, nodetransport.TLSLocalBinding, error) {
	var zero nodetransport.TLSLocalBinding
	client, token, err := loadMachineRecoveryClient(hub.StateDir, hub.NodeID)
	if err != nil {
		return nil, "", zero, nodetransport.ErrTLSInstall
	}
	var b nodetransport.TLSLocalBinding
	if cap == nil {
		b, err = nodetransport.ReadAcceptedTLSRuntimeBinding(hub.StateDir, hub.WriterRoot, hub.HubID, hub.NodeID)
	} else {
		b, err = cap.ReadAcceptedBinding(hub.StateDir, hub.WriterRoot, hub.HubID, hub.NodeID)
	}
	if err != nil {
		return nil, "", zero, err
	}
	s := client.state
	v := b.Control
	p := client.identity.Public()
	if s.HubOrigin != hub.Origin || s.HubID != hub.HubID || s.NodeID != hub.NodeID || v.CredentialDigest != fabric.HashSessionCredential(token) || s.BindingID != v.OwnerBindingID || s.BindingVersion != v.BindingVersion || s.NodeKeyID != v.NodeKeyID || s.NodeKeyVersion != v.NodeKeyVersion || s.NodeKeyEpoch != v.NodeKeyEpoch || s.NodeKeyFingerprint != v.NodeKeyFingerprint || s.HubKeyID != v.HubKeyID || s.HubKeyVersion != v.HubKeyVersion || s.HubFingerprint != v.HubKeyFingerprint || s.ApprovedRequestID != v.ApprovedRequestID || s.ApprovedRequestVersion != v.ApprovedRequestVersion || s.ApprovedCandidateDigest != v.ApprovedCandidateDigest || p.ID != v.NodePublicIdentity.ID || !bytes.Equal(p.SigningPublic, v.NodePublicIdentity.SigningPublic) || !bytes.Equal(p.KEMPublic, v.NodePublicIdentity.KEMPublic) || s.HubPublicIdentity.ID != v.HubPublicIdentity.ID || !bytes.Equal(s.HubPublicIdentity.SigningPublic, v.HubPublicIdentity.SigningPublic) || !bytes.Equal(s.HubPublicIdentity.KEMPublic, v.HubPublicIdentity.KEMPublic) {
		return nil, "", zero, nodetransport.ErrTLSInstall
	}
	return client, token, b, nil
}

func machineTLSOpenLocal(hub *machineHubContext) (*nodetransport.LocalTLSInstaller, func(), error) {
	return machineTLSOpenLocalIn(hub, nil)
}
func machineTLSOpenLocalIn(hub *machineHubContext, cap *nodetransport.TLSMaintenanceRead) (*nodetransport.LocalTLSInstaller, func(), error) {
	client, _, binding, err := machineTLSExistingBindingIn(hub, cap)
	if err != nil {
		return nil, nil, err
	}
	reader, err := nodekeys.OpenExistingCryptoStateReadOnly(machineNodeStateDir(hub.StateDir, hub.NodeID))
	if err != nil {
		return nil, nil, err
	}
	current := func() (nodetransport.TLSLocalBinding, error) {
		if reader.CheckStable() != nil {
			return nodetransport.TLSLocalBinding{}, nodekeys.ErrRuntimeTrustUnavailable
		}
		_, _, b, err := machineTLSExistingBindingIn(hub, cap)
		if err != nil || !reflect.DeepEqual(b, binding) {
			return nodetransport.TLSLocalBinding{}, nodetransport.ErrTLSInstall
		}
		return b, nil
	}
	keys := func() ([][]byte, error) {
		retained, err := reader.RetainedSigningPublicKeys()
		if err != nil {
			return nil, err
		}
		var old [][]byte
		if cap == nil {
			old, err = nodetransport.ReadRetainedTLSPreparationSigningPublicKeys(hub.StateDir, hub.WriterRoot, hub.HubID, hub.NodeID)
		} else {
			old, err = cap.ReadRetainedSigningPublicKeys(hub.StateDir, hub.WriterRoot, hub.HubID, hub.NodeID)
		}
		if err != nil {
			return nil, err
		}
		retained = append(retained, old...)
		// Candidate and pending approved pins remain known application keys.
		for _, p := range []e2ee.PublicIdentity{client.state.HubCandidateIdentity, client.state.HubPublicIdentity, client.identity.Public()} {
			if p.ID != "" {
				if e2ee.ValidatePublicIdentity(p) != nil {
					return nil, nodetransport.ErrTLSInstall
				}
				retained = append(retained, bytes.Clone(p.SigningPublic))
			}
		}
		if reader.CheckStable() != nil {
			return nil, nodekeys.ErrRuntimeTrustUnavailable
		}
		return retained, nil
	}
	i := &nodetransport.LocalTLSInstaller{StateRoot: hub.StateDir, WriterRoot: hub.WriterRoot, HubID: hub.HubID, NodeID: hub.NodeID, OwnerTrust: reader.State, NodeControlIdentity: client.identity, CurrentBinding: current, KnownApplicationPublicKeys: keys}
	return i, func() { reader.Close() }, nil
}

func machineTLSWireBinding(b nodetransport.TLSLocalBinding) nodewire.Binding {
	v := b.Control
	return nodewire.Binding{HubID: v.HubID, NodeID: v.NodeID, BindingID: v.OwnerBindingID, BindingVersion: v.BindingVersion, NodeKeyEpoch: v.NodeKeyEpoch, HubKeyVersion: v.HubKeyVersion, NodeKeyVersion: v.NodeKeyVersion, NodeKey: v.NodePublicIdentity, HubKey: v.HubPublicIdentity}
}

// This temporary transport never reaches machineHubContext or a general HTTP
// client. The only outbound request is the exact sealed read-only fresh query.
func machineTLSQueryCurrent(ctx context.Context, hub *machineHubContext, cfg *nodetransport.Config) (*store.NodeTLSAuthoritySnapshot, error) {
	return machineTLSQueryCurrentIn(ctx, hub, cfg, nil)
}
func machineTLSQueryCurrentIn(ctx context.Context, hub *machineHubContext, cfg *nodetransport.Config, cap *nodetransport.TLSMaintenanceRead) (*store.NodeTLSAuthoritySnapshot, error) {
	client, token, b, err := machineTLSExistingBindingIn(hub, cap)
	if err != nil {
		return nil, err
	}
	local, closeLocal, err := machineTLSOpenLocalIn(hub, cap)
	if err != nil {
		return nil, err
	}
	defer closeLocal()
	trust, err := local.OwnerTrust.GetNodeOwnerKeyTrustLocal(b.Control.OwnerID, b.Control.OwnerKeyID)
	if err != nil || trust.State != nodekeys.NodeOwnerKeyTrustActive {
		return nil, nodetransport.ErrTLSInstall
	}
	if cfg == nil || cfg.LogicalOrigin() != hub.Origin || cfg.Identity.HubID != hub.HubID || cfg.Identity.NodeID != hub.NodeID {
		return nil, nodetransport.ErrTLSInstall
	}
	at := time.Now().UTC().Truncate(time.Second)
	q := nodewire.TLSCurrentRequest{Nonce: make([]byte, 32), Origin: hub.Origin, CredentialDigest: fabric.HashSessionCredential(token), IssuedAt: at.Format(time.RFC3339), ExpiresAt: at.Add(nodewire.TLSCurrentLifetime).Format(time.RFC3339)}
	if _, err := rand.Read(q.Nonce); err != nil {
		return nil, err
	}
	packet, err := nodewire.SealTLSCurrentRequest(client.identity, machineTLSWireBinding(b), q, at)
	if err != nil {
		return nil, err
	}
	transport, err := nodetransport.NewTransport(cfg)
	if err != nil {
		return nil, err
	}
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hub.Origin+"/v2/node/control/rpc", bytes.NewReader(packet))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "CicadaNode "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: rejectNodeRedirect}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nodetransport.ErrTLSCurrentAuthorityUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, nodewire.MaxTLSCurrentPacketBytes+1))
	if err != nil || len(data) > nodewire.MaxTLSCurrentPacketBytes {
		return nil, nodetransport.ErrTLSCurrentAuthorityUnavailable
	}
	status, err := nodewire.OpenTLSCurrentResponse(client.identity, machineTLSWireBinding(b), q, packet, data, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	var binding store.NodeControlKeyBinding
	d := json.NewDecoder(bytes.NewReader(status.CurrentBinding))
	d.DisallowUnknownFields()
	if d.Decode(&binding) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		return nil, nodetransport.ErrTLSInstall
	}
	binding.CredentialDigest = q.CredentialDigest
	if !reflect.DeepEqual(binding, b.Control) || status.OwnerKeyVersion != b.OwnerKeyVersion || status.ClientDeviceVersion != b.ClientDeviceVersion {
		return nil, nodetransport.ErrTLSInstall
	}
	if _, err = local.CurrentBinding(); err != nil {
		return nil, err
	}
	a := status.CurrentAuthority
	return &store.NodeTLSAuthoritySnapshot{State: a.State, RowVersion: a.RowVersion, ReservationVersion: a.ReservationVersion, Claims: a.Claims, Grant: a.Grant, CSRPEM: a.CSRPEM, IssuerChainPEM: a.IssuerChainPEM, TrustAnchorPEM: a.TrustAnchorPEM, LeafCertificatePEM: a.LeafCertificatePEM, LeafDERHash: a.LeafDERHash, InstallAck: a.InstallAck, Activation: a.Activation}, nil
}

func machineTLSRecoveryQuery(ctx context.Context, cap *nodetransport.TLSMaintenanceRead, hub *machineHubContext, configPath string, client *machineNodeControlClient, token string, q nodewire.RecoveryRequest, packet []byte) (nodewire.RecoveryStatus, error) {
	o := nodetransport.RuntimeOptions{StateRoot: hub.StateDir, WriterRoot: hub.WriterRoot, HubID: hub.HubID, NodeID: hub.NodeID, ApplicationOrigin: hub.Origin, ConfigPath: configPath, OpenLocal: func() (*nodetransport.LocalTLSInstaller, func(), error) { return machineTLSOpenLocalIn(hub, cap) }, QueryCurrent: func(ctx context.Context, cfg *nodetransport.Config) (*store.NodeTLSAuthoritySnapshot, error) {
		return machineTLSQueryCurrentIn(ctx, hub, cfg, cap)
	}}
	data, err := cap.QueryRecovery(ctx, o, token, packet)
	if err != nil {
		return nodewire.RecoveryStatus{}, err
	}
	return nodewire.OpenRecoveryResponse(client.identity, machineNodeControlBindingFromState(client), q, packet, data)
}
