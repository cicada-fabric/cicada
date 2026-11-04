package appcore

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/appkeys"
	"github.com/cicada-ai/cicada/internal/appvault"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

const (
	appUnbindNamespace     = "appcore.app-unbind.v1"
	appRebindNamespace     = "appcore.app-rebind.v1"
	appBindingRecordFormat = "cicada.native-app-binding.v1"
)

// Typed prepares contain their original nonce and, for unlink, the session
// token. This record stays inside the encrypted vault and is never a Snapshot.
type appBindingRecord struct {
	Format          string                 `json:"format"`
	Scope           appvault.Scope         `json:"scope"`
	DeviceKeyID     string                 `json:"device_key_id"`
	Generation      uint64                 `json:"generation"`
	Unbind          *wire.AppUnbindPrepare `json:"unbind,omitempty"`
	Rebind          *wire.AppRebindPrepare `json:"rebind,omitempty"`
	PreparePacket   []byte                 `json:"prepare_packet"`
	ChallengePacket []byte                 `json:"challenge_packet,omitempty"`
	CompletePacket  []byte                 `json:"complete_packet,omitempty"`
	ResultPacket    []byte                 `json:"result_packet,omitempty"`
}

func (*appBindingRecord) String() string   { return "appBindingRecord[redacted]" }
func (*appBindingRecord) GoString() string { return "appBindingRecord[redacted]" }

type appBindingRuntime struct {
	generation                     uint64
	unbind, rebind                 *appBindingRecord
	unbindVersion, rebindVersion   uint64
	unbound                        bool
	unbindRejected, rebindRejected bool
	candidate                      appvault.AppDeviceCandidate
	candidateKey                   *appkeys.Identity
}

func (c *nativeController) appIsUnbound() bool { return c.appBinding.unbound }

func (c *nativeController) appBindingActive() *appBindingRecord {
	if c.appBinding.rebind != nil && !c.appBinding.rebindRejected {
		return c.appBindingUnsettled(c.appBinding.rebind)
	}
	if c.appBinding.unbind != nil && !c.appBinding.unbound && !c.appBinding.unbindRejected {
		return c.appBindingUnsettled(c.appBinding.unbind)
	}
	return nil
}

func (c *nativeController) appBindingUnsettled(record *appBindingRecord) *appBindingRecord {
	if len(record.CompletePacket) == 0 && len(record.ChallengePacket) != 0 {
		challenge, _, err := c.openAppBindingRecord(record)
		if err == nil && !c.cfg.Now().UTC().Before(parseExpiry(challenge.Binding.ExpiresAt)) {
			// An authenticated prepare has no unbinding/rebinding effect. Only
			// a new explicit review may replace an expired, unsent challenge.
			return nil
		}
	}
	return record
}

func (c *nativeController) appBindingKey(record *appBindingRecord) *appkeys.Identity {
	if record != nil && record.Rebind != nil {
		return c.appBinding.candidateKey
	}
	return c.device
}

func (c *nativeController) openAppBindingRecord(record *appBindingRecord) (wire.AppBindingChallenge, *wire.AppBindingResult, error) {
	var challenge wire.AppBindingChallenge
	if record == nil || record.Format != appBindingRecordFormat || record.Scope != cardScope(c.connection) ||
		(record.Unbind == nil) == (record.Rebind == nil) || c.owner == nil || len(record.PreparePacket) == 0 ||
		len(record.PreparePacket) > wire.MaxAppBindingOriginalBytes || len(record.ChallengePacket) > maxDurablePacketSize ||
		len(record.CompletePacket) > maxDurablePacketSize || len(record.ResultPacket) > maxDurablePacketSize {
		return challenge, nil, appvault.ErrScopeMismatch
	}
	key := c.appBindingKey(record)
	if key == nil || key.Public().ID != record.DeviceKeyID {
		return challenge, nil, appvault.ErrScopeMismatch
	}
	operation := wire.OperationAppUnbindPrepare
	var prepare any = record.Unbind
	var deviceID, requestID, origin, account, owner string
	if q := record.Unbind; q != nil {
		deviceID, requestID, origin, account, owner = q.DeviceID, q.RequestID, q.Origin, q.AccountID, q.OwnerID
		if q.HubID != record.Scope.HubID || !reflect.DeepEqual(q.OwnerPublic, c.owner.Public()) || q.DeviceID != c.state.DeviceID ||
			record.DeviceKeyID != c.state.DeviceKeyID || record.Generation == 0 {
			return challenge, nil, appvault.ErrScopeMismatch
		}
	} else {
		q := record.Rebind
		operation, prepare = wire.OperationAppRebindPrepare, q
		deviceID, requestID, origin, account, owner = q.DeviceID, q.RequestID, q.Origin, q.AccountID, q.OwnerID
		if q.HubID != record.Scope.HubID || !reflect.DeepEqual(q.OwnerPublic, c.owner.Public()) || !c.appBinding.unbound ||
			q.PreviousDeviceID != c.state.DeviceID || record.Generation != c.appBinding.candidate.Generation ||
			record.DeviceKeyID != c.appBinding.candidate.KeyID {
			return challenge, nil, appvault.ErrScopeMismatch
		}
		unboundChallenge, _, err := c.openAppBindingRecord(c.appBinding.unbind)
		if err != nil || q.UnbindBindingDigest != unboundChallenge.Binding.Digest() {
			return challenge, nil, appvault.ErrScopeMismatch
		}
	}
	p, err := wire.PreflightRequest(record.PreparePacket, operation)
	if err != nil || p.Packet.Route.OperationID != requestID || p.Packet.Route.DeviceID != deviceID ||
		p.Packet.Route.HubID != record.Scope.HubID || p.Packet.Route.OwnerID != owner || !reflect.DeepEqual(p.SenderPublicIdentity, key.Public()) ||
		origin != record.Scope.Origin || account != record.Scope.AccountID || owner != record.Scope.OwnerID {
		return challenge, nil, appvault.ErrScopeMismatch
	}
	if len(record.ChallengePacket) == 0 {
		if len(record.CompletePacket) != 0 || len(record.ResultPacket) != 0 {
			return challenge, nil, appvault.ErrScopeMismatch
		}
		return challenge, nil, nil
	}
	cryptoKey, err := key.E2EE()
	if err != nil || wire.OpenClientResponse(cryptoKey, c.hub, record.PreparePacket, record.ChallengePacket, &challenge) != nil ||
		wire.ValidateAppBindingPreparedResponse(prepare, record.PreparePacket, challenge, c.hub, time.Time{}) != nil {
		return challenge, nil, appvault.ErrScopeMismatch
	}
	if len(record.CompletePacket) == 0 {
		if len(record.ResultPacket) != 0 {
			return challenge, nil, appvault.ErrScopeMismatch
		}
		return challenge, nil, nil
	}
	completeOperation := wire.OperationAppUnbindComplete
	if record.Rebind != nil {
		completeOperation = wire.OperationAppRebindComplete
	}
	complete, err := wire.PreflightRequest(record.CompletePacket, completeOperation)
	if err != nil || complete.Packet.Route.DeviceID != deviceID || complete.Packet.Route.HubID != record.Scope.HubID ||
		complete.Packet.Route.OwnerID != owner || !reflect.DeepEqual(complete.SenderPublicIdentity, key.Public()) {
		return challenge, nil, appvault.ErrScopeMismatch
	}
	if len(record.ResultPacket) == 0 {
		return challenge, nil, nil
	}
	var result wire.AppBindingResult
	if wire.OpenClientResponse(cryptoKey, c.hub, record.CompletePacket, record.ResultPacket, &result) != nil ||
		wire.ValidateAppBindingResultTarget(result, record.CompletePacket, challenge.Binding) != nil {
		return challenge, nil, appvault.ErrScopeMismatch
	}
	return challenge, &result, nil
}

func (c *nativeController) loadAppBinding() error {
	c.clearAppBindingRuntime()
	status, err := c.vault.AppDeviceStatus()
	if err != nil {
		return err
	}
	if status.Candidate != nil {
		c.appBinding.candidate = *status.Candidate
		c.appBinding.candidateKey, err = c.vault.OpenPendingAppDevice(*status.Candidate)
		if err != nil {
			return err
		}
	}
	c.appBinding.generation = status.Generation
	for _, item := range []struct {
		namespace string
		version   *uint64
		record    **appBindingRecord
	}{{appUnbindNamespace, &c.appBinding.unbindVersion, &c.appBinding.unbind}, {appRebindNamespace, &c.appBinding.rebindVersion, &c.appBinding.rebind}} {
		raw, version, _, err := c.vault.LoadState(item.namespace)
		*item.version = version
		if err != nil {
			clear(raw)
			return err
		}
		if len(raw) == 0 {
			continue
		}
		var record appBindingRecord
		err = decodeStateJSON(raw, &record)
		clear(raw)
		if err != nil || (item.namespace == appUnbindNamespace) != (record.Unbind != nil) ||
			record.Unbind != nil && record.Generation != status.Generation {
			return appvault.ErrScopeMismatch
		}
		*item.record = &record
		_, result, err := c.openAppBindingRecord(&record)
		if err != nil {
			return err
		}
		if result != nil {
			if record.Unbind != nil {
				c.appBinding.unbound = result.State == wire.AppBindingUnbound
				c.appBinding.unbindRejected = result.State == wire.AppBindingRejected
			} else {
				c.appBinding.rebindRejected = result.State == wire.AppBindingRejected
			}
		}
	}
	if c.state.AppDeviceUnbound && !c.appBinding.unbound {
		return appvault.ErrScopeMismatch
	}
	return nil
}

func (c *nativeController) persistAppBindingRecord(record *appBindingRecord) error {
	namespace, version := appUnbindNamespace, &c.appBinding.unbindVersion
	if record.Rebind != nil {
		namespace, version = appRebindNamespace, &c.appBinding.rebindVersion
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return c.failStorage("APP_BINDING_STORAGE_FAILED", err)
	}
	defer clear(raw)
	*version, err = c.vault.CompareAndSwapState(namespace, *version, raw)
	if err != nil {
		return c.failStorage("APP_BINDING_STORAGE_FAILED", err)
	}
	return nil
}

func (c *nativeController) clearAppBindingRuntime() {
	for _, record := range []*appBindingRecord{c.appBinding.unbind, c.appBinding.rebind} {
		if record == nil {
			continue
		}
		if record.Unbind != nil {
			clear(record.Unbind.SessionToken)
		}
		clear(record.PreparePacket)
		clear(record.ChallengePacket)
		clear(record.CompletePacket)
		clear(record.ResultPacket)
	}
	if c.appBinding.candidateKey != nil {
		c.appBinding.candidateKey.Close()
	}
	c.appBinding = appBindingRuntime{}
}
