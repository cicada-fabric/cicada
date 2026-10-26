package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
)

var endpointGroupsRelationStates = []string{"NONE", "PENDING_KEY", "ACTIVE", "REMOVED", "EXPIRED"}

// A cursor binds the complete private scope and observed listing, not just an
// offset. It supplies no authority: every page repeats current Owner/Node checks.
func endpointGroupsPageCursor(scope, digest, last string) string {
	return "v1:" + endpointGroupsDigest(scope+":"+digest) + ":" + last
}
func endpointGroupsCursorAfter(cursor, scope, digest string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	parts := strings.SplitN(cursor, ":", 3)
	if len(parts) != 3 || parts[0] != "v1" || parts[1] != endpointGroupsDigest(scope+":"+digest) || parts[2] == "" {
		return "", ErrNetworkPermission
	}
	return parts[2], nil
}

func endpointGroupsRelationCardsTx(tx *sql.Tx, r *hubEndpointGroupsRegistration, at time.Time) ([]wire.OwnerEndpointGroupsRelationCard, error) {
	rows, err := tx.Query(`SELECT group_id FROM hub_endpoint_groups_relations_v1 WHERE endpoint_id=? UNION SELECT group_id FROM hub_endpoint_groups_heads_v1 WHERE native_digest=? UNION SELECT p.group_id FROM hub_local_domains_v1 p WHERE p.policy_id=? ORDER BY 1`, r.anchor.Registration.EndpointID, r.nativeDigest, r.originPolicy)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	cards := []wire.OwnerEndpointGroupsRelationCard{}
	for _, id := range ids {
		card, _, _, e := endpointGroupsResolveTx(tx, r, id, at, true)
		if e != nil {
			return nil, e
		}
		cards = append(cards, card)
	}
	return cards, nil
}

func endpointGroupsReadTx(tx *sql.Tx, in HubEndpointGroupsInput, a *hubAppNodeActor, q wire.OwnerEndpointGroupsReadRequest) (wire.OwnerEndpointGroupsResult, string, error) {
	result := wire.OwnerEndpointGroupsResult{Threads: []wire.OwnerEndpointGroupsThreadCard{}, Groups: []wire.OwnerEndpointGroupsGroupCard{}, Relations: []wire.OwnerEndpointGroupsRelationCard{}}
	_, _, err := endpointGroupsScopeTx(tx, in, a, q.Body.NodeID, q.Body.NetworkID)
	if err != nil {
		return result, "TARGET_NOT_AUTHORIZED", nil
	}
	result.ScopeActions = &wire.OwnerEndpointGroupsScopeActions{NodeID: q.Body.NodeID, NetworkID: q.Body.NetworkID, AllowedActions: []string{wire.OwnerEndpointGroupsCreateGroup}}
	limit := q.Body.Limit
	if limit == 0 {
		limit = 64
	}
	scope := fmt.Sprintf("%s/%s/%s/%s/%s/%s", a.scope.OwnerID, q.Context.DeviceID, q.Body.NodeID, q.Body.NetworkID, q.Body.View, q.Body.EndpointID)
	if q.Body.View == "THREADS" {
		rows, e := tx.Query(`SELECT endpoint_id FROM hub_endpoint_groups_registrations_v1 WHERE owner_id=? AND node_id=? AND network_id=? UNION SELECT m.endpoint_id FROM hub_local_domain_members_v1 m JOIN hub_local_domains_v1 p ON p.policy_id=m.policy_id WHERE m.owner_id=? AND m.node_id=? AND p.network_id=? AND m.state IN('JOINED_ZERO','ACTIVE') AND p.state='ACTIVE' ORDER BY 1`, a.scope.OwnerID, q.Body.NodeID, q.Body.NetworkID, a.scope.OwnerID, q.Body.NodeID, q.Body.NetworkID)
		if e != nil {
			return result, "", e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return result, "", e
			}
			if q.Body.EndpointID == "" || id == q.Body.EndpointID {
				ids = append(ids, id)
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return result, "", e
		}
		cards := []wire.OwnerEndpointGroupsThreadCard{}
		for _, id := range ids {
			r, e := endpointGroupsEnsureRegistrationTx(tx, a.scope.OwnerID, q.Body.NodeID, q.Body.NetworkID, id, in.Hub, in.NodeControlPublic, in.At)
			if e != nil {
				continue
			}
			relations, e := endpointGroupsRelationCardsTx(tx, r, in.At)
			if e != nil {
				return result, "", e
			}
			var name string
			if e = tx.QueryRow(`SELECT name FROM fabric_endpoints WHERE id=?`, id).Scan(&name); e != nil {
				return result, "", e
			}
			presence := "offline"
			if r.anchor.State == "REVOKED" {
				presence = "left"
			} else if appNodeBefore(in.At, r.anchor.LeaseExpiresAt) {
				presence = "LEASE_RECENT"
			}
			card := wire.OwnerEndpointGroupsThreadCard{EndpointID: id, PrincipalID: r.anchor.Registration.PrincipalID, NodeID: q.Body.NodeID, NetworkID: q.Body.NetworkID, Name: name, Workspace: r.anchor.Registration.Workspace, Harness: r.anchor.Registration.Harness, RegistrationDigest: r.anchor.RegistrationDigest, RegistrationRevision: r.anchor.RegistrationRevision, Presence: presence, Relations: relations, RelationStates: append([]string(nil), endpointGroupsRelationStates...), RelationsRevision: r.listing, RelationsComplete: true}
			if len(relations) > 8 {
				card.Relations = relations[:8]
				card.RelationsComplete = false
				card.RelationsNextCursor = endpointGroupsPageCursor(fmt.Sprintf("%s/%s/%s/%s/RELATIONS/%s", a.scope.OwnerID, q.Context.DeviceID, q.Body.NodeID, q.Body.NetworkID, id), endpointGroupsDigest(relations), relations[7].GroupID)
			}
			cards = append(cards, card)
		}
		digest := endpointGroupsDigest(cards)
		after, e := endpointGroupsCursorAfter(q.Body.Cursor, scope, digest)
		if e != nil {
			return result, "CURSOR_STALE", nil
		}
		for i, card := range cards {
			if card.EndpointID <= after {
				continue
			}
			result.Threads = append(result.Threads, card)
			raw, _ := json.Marshal(result)
			if len(raw) > wire.MaxOwnerEndpointGroupsPageBytes-4096 {
				result.Threads = result.Threads[:len(result.Threads)-1]
				if len(result.Threads) == 0 {
					return result, "UNSUPPORTED_PROFILE", nil
				}
				result.NextCursor = endpointGroupsPageCursor(scope, digest, result.Threads[len(result.Threads)-1].EndpointID)
				break
			}
			if len(result.Threads) == limit {
				if i+1 < len(cards) {
					result.NextCursor = endpointGroupsPageCursor(scope, digest, card.EndpointID)
				}
				break
			}
		}
		return result, "", nil
	}
	r, err := endpointGroupsEnsureRegistrationTx(tx, a.scope.OwnerID, q.Body.NodeID, q.Body.NetworkID, q.Body.EndpointID, in.Hub, in.NodeControlPublic, in.At)
	if err != nil {
		return result, "UNSUPPORTED_PROFILE", nil
	}
	if q.Body.View == "CANDIDATE_GROUPS" {
		rows, e := tx.Query(`SELECT `+groupColumns+` FROM groups WHERE owner_principal_id=? AND network_id=? AND state=? AND context_policy='group_scoped' ORDER BY id`, a.scope.OwnerID, q.Body.NetworkID, GroupStateActive)
		if e != nil {
			return result, "", e
		}
		groups := []*Group{}
		for rows.Next() {
			g, e := scanGroup(rows)
			if e != nil {
				rows.Close()
				return result, "", e
			}
			groups = append(groups, g)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return result, "", e
		}
		cards := []wire.OwnerEndpointGroupsGroupCard{}
		for _, g := range groups {
			if _, e = endpointGroupsGroupTx(tx, a.scope.OwnerID, q.Body.NetworkID, g.ID); e != nil {
				continue
			}
			card := endpointGroupsGroupCard(g)
			code := ""
			if g.Revision != g.Version {
				code = "UNSUPPORTED_PROFILE"
			} else if e = guardDedicatedThreadGroupEndpointTx(tx, r.anchor.Registration.EndpointID, g.ID, in.At); e != nil {
				code = "TARGET_NOT_AUTHORIZED"
			} else if e = endpointGroupsAdmissionSafeTx(tx, r, g.ID, in.At); e != nil {
				code = "SHARED_MEMBERSHIP_CONFLICT"
			} else {
				if e = endpointGroupsExpireTx(tx, r, g.ID, in.At); e != nil {
					return result, "", e
				}
				p, e := endpointGroupsPolicyForRelationTx(tx, r, g.ID)
				if e != nil {
					return result, "", e
				}
				if p != nil && p.state == "ACTIVE" {
					code = "MANUAL_SOURCE_ALREADY_ACTIVE"
				}
				if p != nil && p.state == "PENDING_KEY" {
					code = "RELATION_PENDING"
				}
			}
			if code != "" {
				card.AllowedActions = []string{}
				card.UnavailableReason = code
			}
			cards = append(cards, card)
		}
		digest := endpointGroupsDigest(cards)
		after, e := endpointGroupsCursorAfter(q.Body.Cursor, scope, digest)
		if e != nil {
			return result, "CURSOR_STALE", nil
		}
		for i, card := range cards {
			if card.GroupID <= after {
				continue
			}
			result.Groups = append(result.Groups, card)
			if len(result.Groups) == limit {
				if i+1 < len(cards) {
					result.NextCursor = endpointGroupsPageCursor(scope, digest, card.GroupID)
				}
				break
			}
		}
		return result, "", nil
	}
	cards, err := endpointGroupsRelationCardsTx(tx, r, in.At)
	if err != nil {
		return result, "", err
	}
	sort.Slice(cards, func(i, j int) bool { return cards[i].GroupID < cards[j].GroupID })
	digest := endpointGroupsDigest(cards)
	after, e := endpointGroupsCursorAfter(q.Body.Cursor, scope, digest)
	if e != nil {
		return result, "CURSOR_STALE", nil
	}
	for i, card := range cards {
		if card.GroupID <= after {
			continue
		}
		result.Relations = append(result.Relations, card)
		if len(result.Relations) == limit {
			if i+1 < len(cards) {
				result.NextCursor = endpointGroupsPageCursor(scope, digest, card.GroupID)
			}
			break
		}
	}
	result.RelationPage = &wire.OwnerEndpointGroupsRelationPage{EndpointID: r.anchor.Registration.EndpointID, NetworkID: r.anchor.NetworkID, States: append([]string(nil), endpointGroupsRelationStates...), RelationsRevision: r.listing, Complete: result.NextCursor == "", NextCursor: result.NextCursor}
	return result, "", nil
}
