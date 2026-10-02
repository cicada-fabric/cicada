package server

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/fabric"
	"github.com/cicada-ai/cicada/internal/nodetransport"
	"github.com/cicada-ai/cicada/internal/pqtls"
	"github.com/cicada-ai/cicada/internal/store"
)

type nodeTransportCheckKey struct{}
type nodeTransportCheck func() bool

func enrolledNodePath(path string) bool {
	return nodetransport.IsEnrolledNodePath(path)
}

// WithNodePQTransport is applied to BOTH listeners when strict transport is on.
// The frontdoor keeps Client and unpaired bootstrap; no enrolled peer route can
// execute there. TLS state comes only from the trusted listener ConnContext.
func WithNodePQTransport(inner http.Handler, service *fabric.Service, cfg *nodetransport.Config, nodeListener bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protected := enrolledNodePath(r.URL.Path)
		if nodeListener && !protected && r.URL.Path != "/healthz" && r.URL.Path != "/v2/node/identity" {
			writeError(w, http.StatusNotFound, errors.New("route is unavailable on enrolled Node transport"))
			return
		}
		if !protected {
			inner.ServeHTTP(w, r)
			return
		}
		state, err := pqtls.StateFromContext(r.Context())
		if !nodeListener || err != nil || service == nil || cfg == nil {
			writeError(w, http.StatusForbidden, errors.New("enrolled Node PQ transport is required"))
			return
		}
		networkID := ""
		if strings.HasPrefix(r.URL.Path, "/v2/fabric/networks/") {
			networkID = strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/fabric/networks/"), "/")[0]
		}
		check := nodeTransportCheck(func() bool {
			if !state.ValidAt(time.Now()) || state.TLSVersion != "TLSv1.3" || state.Group != "MLKEM768" || state.CipherSuite != "TLS_AES_256_GCM_SHA384" || state.PeerSignature != "ML-DSA-65" || state.ALPN != "http/1.1" || state.VerificationResult != 0 || !state.HostnameVerified {
				return false
			}
			binding, err := service.NodeForTransportAuthorization(r.Header.Get("Authorization"), r.Header.Get("Cicada-Group-Scope"), networkID)
			if err != nil {
				return false
			}
			if !nodeTLSAuthorityMatches(binding, state, time.Now()) {
				return false
			}
			for _, p := range cfg.Peers {
				if state.Peer != p.Identity.TLSIdentity() || binding.HubID != p.Identity.HubID || binding.NodeID != p.Identity.NodeID || binding.OwnerID != p.OwnerID || binding.OwnerKeyID != p.OwnerKeyID || binding.BindingID != p.BindingID || binding.BindingVersion != p.BindingVersion || binding.CredentialVersion != p.CredentialVersion {
					continue
				}
				hash := state.CertificateSHA256
				if p.PinKind == "spki-sha256" {
					hash = state.SPKISHA256
				}
				return hex.EncodeToString(hash[:]) == p.PinSHA256
			}
			return false
		})
		if !check() {
			writeError(w, http.StatusUnauthorized, errors.New("current Node certificate binding is not authorized"))
			return
		}
		inner.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nodeTransportCheckKey{}, check)))
	})
}

// Store supplies this snapshot only after rechecking the current approved
// NodeControl, Owner/device and credential. Operator coordinates can narrow it.
func nodeTLSAuthorityMatches(binding *store.NodeTransportBinding, state pqtls.State, at time.Time) bool {
	if binding == nil || binding.TLSAuthority == nil {
		return false
	}
	a := binding.TLSAuthority
	c := a.Claims
	if a.State != "ACTIVE" || a.RowVersion == 0 || e2ee.ValidateOwnerTLSLeafGrantClaims(c) != nil || len(a.Grant) == 0 || len(a.InstallAck) == 0 || len(a.Activation) == 0 || len(a.LeafCertificatePEM) == 0 {
		return false
	}
	before, err := time.Parse(time.RFC3339, c.NotBefore)
	if err != nil {
		return false
	}
	after, err := time.Parse(time.RFC3339, c.NotAfter)
	return err == nil && !at.Before(before) && at.Before(after) && state.Peer.Kind == "node" &&
		c.HubID == binding.HubID && c.NodeID == binding.NodeID && c.OwnerID == binding.OwnerID && c.OwnerKeyID == binding.OwnerKeyID &&
		c.OwnerBindingID == binding.BindingID && c.OwnerBindingVersion == uint64(binding.BindingVersion) && c.CredentialVersion == uint64(binding.CredentialVersion) &&
		state.Peer.HubID == c.HubID && state.Peer.NodeID == c.NodeID && state.Peer.DNSName == c.DNSName && state.Peer.BindingEpoch == c.TLSEpoch &&
		a.LeafDERHash == hex.EncodeToString(state.CertificateSHA256[:]) && c.SPKIDERHash == hex.EncodeToString(state.SPKISHA256[:])
}

func nodePQTransportCurrent(ctx context.Context) bool {
	if check, ok := ctx.Value(nodeTransportCheckKey{}).(nodeTransportCheck); ok {
		return check()
	}
	return true // Strict listeners install the policy before any enrolled route.
}

// Each queued event checks current authority before writing. This completed
// check is the authorization point; bytes already sent cannot be recalled.
func nodePQTransportValidityCurrent(ctx context.Context) bool {
	if _, strict := ctx.Value(nodeTransportCheckKey{}).(nodeTransportCheck); !strict {
		return true
	}
	state, err := pqtls.StateFromContext(ctx)
	return err == nil && state.ValidAt(time.Now()) && nodePQTransportCurrent(ctx)
}
