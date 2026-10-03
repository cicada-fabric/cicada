package control

import (
	"encoding/json"
	"testing"
	"time"
)

func TestClientGroupDirectoryPermissionUnionAndUntrustedEntry(t *testing.T) {
	c := newClientStatusControl(t, time.Minute)
	group, err := c.CreateGroup(GroupCreateInput{Name: "Synthetic directory Group"})
	if err != nil {
		t.Fatal(err)
	}
	principal, _, _ := createClientTopologyEndpoint(t, c, group.ID, "synthetic-dir-agent", "synthetic-dir-endpoint", "synthetic-dir-node")
	member, err := c.store.GetMembershipByPrincipalGroup(principal.ID, group.ID)
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	valid := ClientTopologyAction{Kind: ClientTopologySetDirectoryPermission, SetDirectoryPermission: &ClientTopologySetDirectoryPermissionAction{GroupID: group.ID, MembershipID: member.ID, Enabled: &yes, ExpectedMembershipVersion: member.Version}}
	cases := []struct {
		name   string
		action ClientTopologyAction
	}{
		{"missing_payload", ClientTopologyAction{Kind: ClientTopologySetDirectoryPermission}},
		{"mismatched_payload", ClientTopologyAction{Kind: ClientTopologyBindRole, SetDirectoryPermission: valid.SetDirectoryPermission}},
		{"multiple_payloads", ClientTopologyAction{Kind: ClientTopologySetDirectoryPermission, SetDirectoryPermission: valid.SetDirectoryPermission, BindRole: &ClientTopologyBindRoleAction{}}},
		{"missing_flag", ClientTopologyAction{Kind: ClientTopologySetDirectoryPermission, SetDirectoryPermission: &ClientTopologySetDirectoryPermissionAction{GroupID: group.ID, MembershipID: member.ID, ExpectedMembershipVersion: member.Version}}},
		{"legacy_no_request", valid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := c.ApplyClientTopologyChange(c.Identity().ID, tc.action); err == nil {
				t.Fatal("untrusted action accepted")
			}
		})
	}
	if _, err := c.ApplyClientTopologyChangeForClientRequest("forged-owner", "forged-request", valid); err == nil {
		t.Fatal("forged Owner accepted")
	}
	if _, err := c.ApplyClientTopologyChangeForClientRequest(c.Identity().ID, "forged-request", valid); err == nil {
		t.Fatal("forged accepted request accepted")
	}
	snapshot, err := c.BuildClientTopologySnapshot(c.Identity().ID)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, m := range snapshot.Memberships {
		if m.MembershipID == member.ID {
			found = true
			if !m.DirectoryPermissionEnabled || m.Version != member.Version {
				t.Fatal("snapshot failed explicit directory projection")
			}
		}
	}
	if !found {
		t.Fatal("member not projected")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatal(err)
	}
	var projected []map[string]any
	if err := json.Unmarshal(raw["memberships"], &projected); err != nil {
		t.Fatal(err)
	}
	for _, m := range projected {
		if _, ok := m["directory_permission_enabled"]; !ok {
			t.Fatal("required flag missing from JSON")
		}
	}
}
