package hubaccountwire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/nodewire"
)

// One local secret item, never an HTTP DTO. Preserve base64 case; only its
// decoded Selector may enter the old code normalizer/preview.
type NodePairTrustScopedCode struct {
	Origin, HubID, HubFingerprint, NodeControlFingerprint string
	AttemptID, ContextDigest, Selector                    string
	OOBSecret                                             []byte
	ExpiresAt                                             string
	AuthorityNodeID                                       string
}

func (NodePairTrustScopedCode) String() string   { return "NodePairTrustScopedCode[redacted]" }
func (NodePairTrustScopedCode) GoString() string { return "NodePairTrustScopedCode[redacted]" }
func nodePairScopedCodeArray(c NodePairTrustScopedCode) []any {
	return []any{2, c.Origin, c.HubID, c.HubFingerprint, c.NodeControlFingerprint, c.AttemptID, c.ContextDigest, c.Selector, base64.RawURLEncoding.EncodeToString(c.OOBSecret), c.ExpiresAt, c.AuthorityNodeID}
}
func validateNodePairScopedCode(c NodePairTrustScopedCode) error {
	if !appNodeScopedNodeID(c.AuthorityNodeID) || !nodePairOrigin(c.Origin) || !validID(c.HubID) || len(c.HubID) > 96 || !isHex(c.HubFingerprint, 32) || !isHex(c.NodeControlFingerprint, 32) || !isHex(c.AttemptID, 16) || !isHex(c.ContextDigest, 32) || len(c.OOBSecret) != 32 || validateCanonicalTime(c.ExpiresAt) != nil {
		return ErrInvalid
	}
	if c.Selector != "" {
		n, e := NormalizeAppNodeCode(c.Selector)
		if e != nil || n != c.Selector {
			return ErrInvalid
		}
	}
	return nil
}
func EncodeNodePairTrustScopedCode(c NodePairTrustScopedContext, selector string, secret []byte) (string, error) {
	d, e := NodePairTrustScopedContextDigest(c)
	fp, fe := HubFingerprint(c.Hub)
	if e != nil || fe != nil || len(secret) != 32 {
		return "", ErrInvalid
	}
	var nc e2ee.PublicIdentity
	if c.Mode == NodePairTrustScopedInitial {
		selector, e = NormalizeAppNodeCode(selector)
		digest, de := AppNodeCodeDigest(c.Hub.HubID, selector)
		if e != nil || de != nil || digest != c.Candidate.CodeDigest {
			return "", ErrInvalid
		}
		nc = c.Candidate.HubNodeControlPublic
	} else {
		if selector != "" {
			return "", ErrInvalid
		}
		nc = c.Binding.HubNodeControlPublic
	}
	code := NodePairTrustScopedCode{c.Origin, c.Hub.HubID, fp, nodewire.IdentityFingerprint(nc), c.AttemptID, d, selector, secret, c.ExpiresAt, c.AuthorityNodeID}
	if validateNodePairScopedCode(code) != nil {
		return "", ErrInvalid
	}
	raw, e := json.Marshal(nodePairScopedCodeArray(code))
	if e != nil {
		return "", ErrInvalid
	}
	defer clear(raw)
	text := NodePairTrustScopedCodePrefix + base64.RawURLEncoding.EncodeToString(raw)
	if len(text) > MaxNodePairTrustScopedCodeBytes {
		return "", ErrInvalid
	}
	return text, nil
}
func DecodeNodePairTrustScopedCode(text string, now time.Time) (NodePairTrustScopedCode, error) {
	var out NodePairTrustScopedCode
	if now.IsZero() || len(text) > MaxNodePairTrustScopedCodeBytes || !strings.HasPrefix(text, NodePairTrustScopedCodePrefix) {
		return out, ErrInvalid
	}
	encoded := strings.TrimPrefix(text, NodePairTrustScopedCodePrefix)
	raw, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if e != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return out, ErrInvalid
	}
	defer clear(raw)
	var a []json.RawMessage
	if json.Unmarshal(raw, &a) != nil || len(a) != 11 || !bytes.Equal(a[0], []byte("2")) {
		return out, ErrInvalid
	}
	var fields [10]string
	for i := range fields {
		if json.Unmarshal(a[i+1], &fields[i]) != nil {
			return out, ErrInvalid
		}
	}
	s, e := base64.RawURLEncoding.Strict().DecodeString(fields[7])
	if e != nil {
		return out, ErrInvalid
	}
	out = NodePairTrustScopedCode{fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], s, fields[8], fields[9]}
	canonical, e := json.Marshal(nodePairScopedCodeArray(out))
	defer clear(canonical)
	end, ee := parseCanonicalUTC(out.ExpiresAt)
	if e != nil || ee != nil || validateNodePairScopedCode(out) != nil || !bytes.Equal(canonical, raw) || !now.Before(end) {
		clear(out.OOBSecret)
		return NodePairTrustScopedCode{}, ErrInvalid
	}
	return out, nil
}

// Both expected public identities come from the App's independently retained
// Hub profile/signed transport, not the code or this candidate's own response.
func MatchNodePairTrustScopedCode(t NodePairTrustScopedCode, c NodePairTrustScopedContext, trustedHub HubIdentity, trustedNC e2ee.PublicIdentity, trustedOrigin, trustedDescriptorDigest string, now time.Time) (string, error) {
	if now.IsZero() || validateNodePairScopedCode(t) != nil || ValidateNodePairTrustScopedContext(c, now) != nil || !reflect.DeepEqual(c.Hub, trustedHub) || e2ee.ValidatePublicIdentity(trustedNC) != nil || !nodePairOrigin(trustedOrigin) || c.Origin != trustedOrigin || !isHex(trustedDescriptorDigest, 32) || c.DescriptorDigest != trustedDescriptorDigest {
		return "", ErrInvalid
	}
	d, _ := NodePairTrustScopedContextDigest(c)
	fp, _ := HubFingerprint(trustedHub)
	if t.AuthorityNodeID != c.AuthorityNodeID || t.Origin != c.Origin || t.HubID != c.Hub.HubID || t.HubFingerprint != fp || t.NodeControlFingerprint != nodewire.IdentityFingerprint(trustedNC) || t.AttemptID != c.AttemptID || t.ContextDigest != d || t.ExpiresAt != c.ExpiresAt {
		return "", ErrInvalid
	}
	var nc e2ee.PublicIdentity
	if c.Mode == NodePairTrustScopedInitial {
		nc = c.Candidate.HubNodeControlPublic
		digest, e := AppNodeCodeDigest(c.Hub.HubID, t.Selector)
		if e != nil || digest != c.Candidate.CodeDigest {
			return "", ErrInvalid
		}
	} else {
		nc = c.Binding.HubNodeControlPublic
		if t.Selector != "" {
			return "", ErrInvalid
		}
	}
	if !reflect.DeepEqual(nc, trustedNC) {
		return "", ErrInvalid
	}
	return NodePairTrustScopedOOBCommitment(d, t.OOBSecret)
}

func (NodePairTrustScopedOwnerPrepare) String() string {
	return "NodePairTrustScopedOwnerPrepare[redacted]"
}
func (NodePairTrustScopedOwnerPrepare) GoString() string {
	return "NodePairTrustScopedOwnerPrepare[redacted]"
}
func (NodePairTrustScopedOwnerComplete) String() string {
	return "NodePairTrustScopedOwnerComplete[redacted]"
}
func (NodePairTrustScopedOwnerComplete) GoString() string {
	return "NodePairTrustScopedOwnerComplete[redacted]"
}
func (NodePairTrustScopedOwnerStatus) String() string {
	return "NodePairTrustScopedOwnerStatus[redacted]"
}
func (NodePairTrustScopedOwnerStatus) GoString() string {
	return "NodePairTrustScopedOwnerStatus[redacted]"
}
func (NodePairTrustScopedOwnerLookup) String() string {
	return "NodePairTrustScopedOwnerLookup[redacted]"
}
func (NodePairTrustScopedOwnerLookup) GoString() string {
	return "NodePairTrustScopedOwnerLookup[redacted]"
}
