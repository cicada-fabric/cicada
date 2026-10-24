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
type NodePairTrustCode struct {
	Origin, HubID, HubFingerprint, NodeControlFingerprint string
	AttemptID, ContextDigest, Selector                    string
	OOBSecret                                             []byte
	ExpiresAt                                             string
}

func (NodePairTrustCode) String() string   { return "NodePairTrustCode[redacted]" }
func (NodePairTrustCode) GoString() string { return "NodePairTrustCode[redacted]" }
func nodePairCodeArray(c NodePairTrustCode) []any {
	return []any{1, c.Origin, c.HubID, c.HubFingerprint, c.NodeControlFingerprint, c.AttemptID, c.ContextDigest, c.Selector, base64.RawURLEncoding.EncodeToString(c.OOBSecret), c.ExpiresAt}
}
func validateNodePairCode(c NodePairTrustCode) error {
	if !nodePairOrigin(c.Origin) || !validID(c.HubID) || len(c.HubID) > 96 || !isHex(c.HubFingerprint, 32) || !isHex(c.NodeControlFingerprint, 32) || !isHex(c.AttemptID, 16) || !isHex(c.ContextDigest, 32) || len(c.OOBSecret) != 32 || validateCanonicalTime(c.ExpiresAt) != nil {
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
func EncodeNodePairTrustCode(c NodePairTrustContext, selector string, secret []byte) (string, error) {
	d, e := NodePairTrustContextDigest(c)
	fp, fe := HubFingerprint(c.Hub)
	if e != nil || fe != nil || len(secret) != 32 {
		return "", ErrInvalid
	}
	var nc e2ee.PublicIdentity
	if c.Mode == NodePairTrustInitial {
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
	code := NodePairTrustCode{c.Origin, c.Hub.HubID, fp, nodewire.IdentityFingerprint(nc), c.AttemptID, d, selector, secret, c.ExpiresAt}
	if validateNodePairCode(code) != nil {
		return "", ErrInvalid
	}
	raw, e := json.Marshal(nodePairCodeArray(code))
	if e != nil {
		return "", ErrInvalid
	}
	defer clear(raw)
	text := NodePairTrustCodePrefix + base64.RawURLEncoding.EncodeToString(raw)
	if len(text) > MaxNodePairTrustCodeBytes {
		return "", ErrInvalid
	}
	return text, nil
}
func DecodeNodePairTrustCode(text string, now time.Time) (NodePairTrustCode, error) {
	var out NodePairTrustCode
	if now.IsZero() || len(text) > MaxNodePairTrustCodeBytes || !strings.HasPrefix(text, NodePairTrustCodePrefix) {
		return out, ErrInvalid
	}
	encoded := strings.TrimPrefix(text, NodePairTrustCodePrefix)
	raw, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if e != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return out, ErrInvalid
	}
	defer clear(raw)
	var a []json.RawMessage
	if json.Unmarshal(raw, &a) != nil || len(a) != 10 || !bytes.Equal(a[0], []byte("1")) {
		return out, ErrInvalid
	}
	var fields [9]string
	for i := range fields {
		if json.Unmarshal(a[i+1], &fields[i]) != nil {
			return out, ErrInvalid
		}
	}
	s, e := base64.RawURLEncoding.Strict().DecodeString(fields[7])
	if e != nil {
		return out, ErrInvalid
	}
	out = NodePairTrustCode{fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], s, fields[8]}
	canonical, e := json.Marshal(nodePairCodeArray(out))
	defer clear(canonical)
	end, ee := parseCanonicalUTC(out.ExpiresAt)
	if e != nil || ee != nil || validateNodePairCode(out) != nil || !bytes.Equal(canonical, raw) || !now.Before(end) {
		clear(out.OOBSecret)
		return NodePairTrustCode{}, ErrInvalid
	}
	return out, nil
}

// Both expected public identities come from the App's independently retained
// Hub profile/signed transport, not the code or this candidate's own response.
func MatchNodePairTrustCode(t NodePairTrustCode, c NodePairTrustContext, trustedHub HubIdentity, trustedNC e2ee.PublicIdentity, trustedOrigin, trustedDescriptorDigest string, now time.Time) (string, error) {
	if now.IsZero() || validateNodePairCode(t) != nil || ValidateNodePairTrustContext(c, now) != nil || !reflect.DeepEqual(c.Hub, trustedHub) || e2ee.ValidatePublicIdentity(trustedNC) != nil || !nodePairOrigin(trustedOrigin) || c.Origin != trustedOrigin || !isHex(trustedDescriptorDigest, 32) || c.DescriptorDigest != trustedDescriptorDigest {
		return "", ErrInvalid
	}
	d, _ := NodePairTrustContextDigest(c)
	fp, _ := HubFingerprint(trustedHub)
	if t.Origin != c.Origin || t.HubID != c.Hub.HubID || t.HubFingerprint != fp || t.NodeControlFingerprint != nodewire.IdentityFingerprint(trustedNC) || t.AttemptID != c.AttemptID || t.ContextDigest != d || t.ExpiresAt != c.ExpiresAt {
		return "", ErrInvalid
	}
	var nc e2ee.PublicIdentity
	if c.Mode == NodePairTrustInitial {
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
	return NodePairTrustOOBCommitment(d, t.OOBSecret)
}

func (NodePairTrustOwnerPrepare) String() string    { return "NodePairTrustOwnerPrepare[redacted]" }
func (NodePairTrustOwnerPrepare) GoString() string  { return "NodePairTrustOwnerPrepare[redacted]" }
func (NodePairTrustOwnerComplete) String() string   { return "NodePairTrustOwnerComplete[redacted]" }
func (NodePairTrustOwnerComplete) GoString() string { return "NodePairTrustOwnerComplete[redacted]" }
func (NodePairTrustOwnerStatus) String() string     { return "NodePairTrustOwnerStatus[redacted]" }
func (NodePairTrustOwnerStatus) GoString() string   { return "NodePairTrustOwnerStatus[redacted]" }
func (NodePairTrustOwnerLookup) String() string     { return "NodePairTrustOwnerLookup[redacted]" }
func (NodePairTrustOwnerLookup) GoString() string   { return "NodePairTrustOwnerLookup[redacted]" }
