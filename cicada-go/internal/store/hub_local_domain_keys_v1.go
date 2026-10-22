package store

import (
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

func localDomainGroupGrants() []string {
	return []string{"directory.read", "message.ask", "message.receive", "message.reply", "message.send"}
}

func localDomainProjectedManifestTx(tx *sql.Tx, p *hubLocalDomain, m wire.LocalDomainMember, issued string, at time.Time) (wire.LocalDomainKeyManifest, error) {
	current, err := readGroupEndpointKeyGrantSnapshotTx(tx, p.policy.OwnerID, p.policy.GroupID, m.EndpointID, p.policy.OwnerPublic.ID, issued, p.policy.ExpiresAt, at)
	if err != nil {
		return wire.LocalDomainKeyManifest{}, err
	}
	raw, err := json.Marshal(current)
	if err != nil {
		return wire.LocalDomainKeyManifest{}, err
	}
	var manifest wire.LocalDomainKeyManifest
	if json.Unmarshal(raw, &manifest) != nil {
		return manifest, ErrNetworkPermission
	}
	if m.State == wire.LocalDomainMemberJoinedZero {
		manifest.MembershipRevision++
	}
	manifest.CandidateBindingDigest, err = wire.LocalDomainGroupBindingDigest(manifest)
	if err != nil {
		return manifest, err
	}
	manifest.Digest, err = wire.LocalDomainGroupManifestDigest(manifest)
	return manifest, err
}

func localDomainKeyPrepareTx(tx *sql.Tx, in HubLocalDomainNodeInput, p *hubLocalDomain, q wire.LocalDomainNodeKeyPrepare) (any, error) {
	m, err := readLocalDomainMember(tx, q.MemberID)
	if err != nil || m == nil || m.member.Selection != q.Selection || m.member.Revision != q.ExpectedRevision {
		return nil, ErrNetworkPermission
	}
	live, err := localDomainMemberSnapshotTx(tx, p, m.member, in.At)
	if err != nil {
		return nil, err
	}
	manifest, err := localDomainProjectedManifestTx(tx, p, live, appNodeStamp(in.At), in.At)
	if err != nil {
		return nil, err
	}
	if live.State == wire.LocalDomainMemberJoinedZero {
		var grants string
		if tx.QueryRow(`SELECT grants_json FROM memberships WHERE group_id=? AND principal_id=? AND revision=? AND status='active'`, p.policy.GroupID, live.PrincipalID, live.MembershipRevision).Scan(&grants) != nil || grants != "[]" {
			return nil, ErrNetworkPermission
		}
	}
	id, err := wire.NewRequestID()
	if err != nil {
		return nil, err
	}
	projected := live
	projected.Revision++
	projected.State = wire.LocalDomainMemberActive
	projected.MembershipRevision = uint64(manifest.MembershipRevision)
	projected.CandidateVersion = uint64(manifest.CandidateVersion)
	projected.CandidateKeyID = manifest.CandidateKeyID
	projected.CandidateFingerprint = manifest.CandidateFingerprint
	projected.CandidateProofDigest = manifest.CandidateProofDigest
	end := in.At.Add(e2ee.LocalDomainRequestLifetime)
	var lease string
	if tx.QueryRow(`SELECT lease_expires_at FROM session_bindings WHERE id=? AND epoch=?`, live.BindingID, live.BindingEpoch).Scan(&lease) != nil {
		return nil, ErrNetworkPermission
	}
	for _, stamp := range []string{lease, p.policy.ExpiresAt} {
		if stamp != "" {
			t, e := time.Parse(time.RFC3339Nano, stamp)
			if e != nil {
				return nil, ErrNetworkPermission
			}
			if t.Before(end) {
				end = t
			}
		}
	}
	memberDigest, err := wire.LocalDomainMemberDigest(projected)
	if err != nil {
		return nil, err
	}
	claims := e2ee.LocalDomainEndpointKeyClaims{Version: 1, Purpose: e2ee.LocalDomainEndpointKeyPurpose, PolicyID: p.policy.PolicyID, PolicyEpoch: p.policy.Epoch, PolicyDigest: live.Selection.PolicyDigest, MemberID: live.MemberID, MemberRevision: projected.Revision, MemberDigest: memberDigest, ManifestDigest: manifest.Digest, CandidateBindingDigest: manifest.CandidateBindingDigest, IssuedAt: manifest.IssuedAt, ExpiresAt: p.policy.ExpiresAt}
	challenge := wire.LocalDomainKeyChallenge{ContractRevision: wire.LocalDomainContractRevision, ChallengeID: id, ExpectedRevision: live.Revision, Member: projected, Manifest: manifest, Claims: claims, ExpiresAt: appNodeStamp(end)}
	raw, err := json.Marshal(challenge)
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO hub_local_domain_challenges_v1 VALUES(?,?,?,?,?,'PREPARED',?,?)`, id, p.policy.PolicyID, live.MemberID, live.Revision, string(raw), challenge.ExpiresAt, appNodeStamp(in.At))
	return challenge, err
}

func localDomainKeyCompleteTx(tx *sql.Tx, in HubLocalDomainNodeInput, p *hubLocalDomain, q wire.LocalDomainNodeKeyComplete) (any, error) {
	var raw, state, expires, policy, member string
	var revision uint64
	err := tx.QueryRow(`SELECT challenge_json,state,expires_at,policy_id,member_id,expected_revision FROM hub_local_domain_challenges_v1 WHERE challenge_id=?`, q.ChallengeID).Scan(&raw, &state, &expires, &policy, &member, &revision)
	if err != nil || state != "PREPARED" || !appNodeBefore(in.At, expires) || policy != p.policy.PolicyID || member != q.MemberID || revision != q.ExpectedRevision {
		return nil, ErrNetworkPermission
	}
	var challenge wire.LocalDomainKeyChallenge
	if json.Unmarshal([]byte(raw), &challenge) != nil || challenge.ChallengeID != q.ChallengeID || challenge.ExpectedRevision != revision || challenge.Member.MemberID != q.MemberID || challenge.Member.Selection != q.Selection || challenge.ExpiresAt != expires {
		return nil, ErrNetworkPermission
	}
	claims, err := e2ee.VerifyLocalDomainEndpointKey(p.policy, q.NodeProof, in.At)
	if err != nil || !reflect.DeepEqual(claims, challenge.Claims) {
		return nil, ErrNetworkPermission
	}
	m, err := readLocalDomainMember(tx, q.MemberID)
	if err != nil || m == nil || m.member.Revision != q.ExpectedRevision || m.member.Selection != q.Selection {
		return nil, ErrNetworkPermission
	}
	live, err := localDomainMemberSnapshotTx(tx, p, m.member, in.At)
	if err != nil {
		return nil, err
	}
	manifest, err := localDomainProjectedManifestTx(tx, p, live, challenge.Manifest.IssuedAt, in.At)
	if err != nil || !reflect.DeepEqual(manifest, challenge.Manifest) {
		return nil, ErrNetworkPermission
	}
	projected := live
	projected.Revision++
	projected.State = wire.LocalDomainMemberActive
	projected.MembershipRevision = uint64(manifest.MembershipRevision)
	projected.CandidateVersion = uint64(manifest.CandidateVersion)
	projected.CandidateKeyID = manifest.CandidateKeyID
	projected.CandidateFingerprint = manifest.CandidateFingerprint
	projected.CandidateProofDigest = manifest.CandidateProofDigest
	if !reflect.DeepEqual(projected, challenge.Member) {
		return nil, ErrNetworkPermission
	}
	if live.State == wire.LocalDomainMemberJoinedZero {
		grants, _ := json.Marshal(localDomainGroupGrants())
		r, err := tx.Exec(`UPDATE memberships SET grants_json=?,revision=revision+1,version=version+1,updated_at=? WHERE group_id=? AND principal_id=? AND status='active' AND grants_json='[]' AND revision=?`, string(grants), appNodeStamp(in.At), p.policy.GroupID, live.PrincipalID, live.MembershipRevision)
		if err != nil {
			return nil, err
		}
		if n, e := r.RowsAffected(); e != nil || n != 1 {
			return nil, ErrNetworkPermission
		}
	}
	grant := wire.LocalDomainEndpointKeyGrant{ContractRevision: wire.LocalDomainContractRevision, Member: projected, Manifest: manifest, PolicyProof: append([]byte(nil), p.proof...), NodeProof: append([]byte(nil), q.NodeProof...)}
	if _, err = wire.VerifyLocalDomainEndpointKeyGrant(grant, in.Hub, p.policy.OwnerID, p.policy.OwnerPublic, in.At); err != nil {
		return nil, ErrNetworkPermission
	}
	memberJSON, err := json.Marshal(projected)
	if err != nil {
		return nil, err
	}
	grantJSON, err := json.Marshal(grant)
	if err != nil {
		return nil, err
	}
	r, err := tx.Exec(`UPDATE hub_local_domain_members_v1 SET member_json=?,state='ACTIVE',revision=revision+1,key_grant_json=? WHERE member_id=? AND policy_id=? AND revision=? AND state IN('JOINED_ZERO','ACTIVE')`, string(memberJSON), string(grantJSON), live.MemberID, p.policy.PolicyID, live.Revision)
	if err != nil {
		return nil, err
	}
	if n, e := r.RowsAffected(); e != nil || n != 1 {
		return nil, ErrNetworkPermission
	}
	if _, err = tx.Exec(`UPDATE hub_local_domain_challenges_v1 SET state=CASE WHEN challenge_id=? THEN 'COMPLETED' ELSE 'INVALIDATED' END WHERE member_id=? AND state='PREPARED'`, q.ChallengeID, live.MemberID); err != nil {
		return nil, err
	}
	d, err := localDomainDescriptionTx(tx, p, in.At)
	if err != nil {
		return nil, err
	}
	return wire.LocalDomainNodeKeyResult{ContractRevision: wire.LocalDomainContractRevision, Description: d, Member: projected, Grant: grant}, nil
}
