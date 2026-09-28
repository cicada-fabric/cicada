package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

func TestNetworkPermissionPresetsHaveExactLeastPrivilegeGrants(t *testing.T) {
	cases := []struct {
		name   string
		grants []string
	}{
		{"directory_guest", []string{"directory.discover"}},
		{"network_collaborator", []string{"direct.receive", "direct.send", "directory.discover", "directory.publish"}},
		{"network_admin_inviter", []string{"network.admin.invite"}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			grants, err := selectNetworkPermissionGrants("", test.name, true)
			if err != nil || !slices.Equal(grants, test.grants) {
				t.Fatalf("preset grants=%v want=%v err=%v", grants, test.grants, err)
			}
			for _, grant := range grants {
				if strings.HasPrefix(grant, "broadcast.") || strings.HasPrefix(grant, "task.") || grant == "*" {
					t.Fatalf("preset expanded to unimplemented or broad authority: %q", grant)
				}
			}
		})
	}
	if _, err := selectNetworkPermissionGrants("directory.discover", "network_collaborator", true); err == nil {
		t.Fatal("accepted both --grants and --preset")
	}
	if _, err := selectNetworkPermissionGrants("", "network_admin_inviter", false); err == nil {
		t.Fatal("NetworkAdmin preset could regrant NetworkAdmin authority")
	}
	for _, grant := range []string{"message.send", "task.read", "task.offer.claim", "broadcast.publish", "future.unknown"} {
		if _, err := selectNetworkPermissionGrants(grant, "", true); err == nil {
			t.Fatalf("accepted unsupported Network M1 grant %q", grant)
		}
	}
	if grants, err := selectNetworkPermissionGrants("directory.publish,direct.send", "", true); err != nil ||
		!slices.Equal(grants, []string{"direct.send", "directory.publish"}) {
		t.Fatalf("valid explicit Network grants=%v err=%v", grants, err)
	}
}

func TestNetworkOperatorInviteUsesPresetAsStoredExactInvitationGrants(t *testing.T) {
	root := t.TempDir()
	privateDir := filepath.Join(root, "private")
	if err := os.Mkdir(privateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(root, "hub.sqlite3")
	persistence, err := store.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := persistence.CreatePrincipal(store.Principal{ID: "preset_owner", Kind: store.PrincipalKindHuman,
		OwnerID: "preset_owner", TrustDomainID: "preset_domain", Name: "synthetic owner", Status: store.PrincipalStatusActive})
	if err != nil {
		t.Fatal(err)
	}
	hubID, err := persistence.GetClientHubID()
	if err != nil {
		t.Fatal(err)
	}
	network, err := persistence.CreateNetwork(store.Network{ID: "preset_network", HubID: hubID,
		Name: "synthetic preset Network", OwnerID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err := persistence.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		grants []string
	}{
		{"directory_guest", []string{"directory.discover"}},
		{"network_collaborator", []string{"direct.receive", "direct.send", "directory.discover", "directory.publish"}},
		{"network_admin_inviter", []string{"network.admin.invite"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			invitationPath := filepath.Join(privateDir, test.name+".invitation")
			var output bytes.Buffer
			err := networkOperatorCommand("invite", []string{"--db", dbPath, "--network", network.ID,
				"--target-owner", "target_" + test.name, "--invitation-file", invitationPath,
				"--preset", test.name, "--ttl", "15m"}, &output)
			if err != nil {
				t.Fatal(err)
			}
			info, err := os.Lstat(invitationPath)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("invitation file mode=%v err=%v", info, err)
			}
			secret, err := readPrivateNetworkFile(invitationPath, 16*1024)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(output.Bytes(), bytes.TrimSpace(secret)) {
				t.Fatal("operator CLI printed invitation token")
			}
			check, err := store.New(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer check.Close()
			invitation, err := check.GetNetworkInvitation(string(bytes.TrimSpace(secret)))
			if err != nil || !slices.Equal(invitation.Grants, test.grants) {
				t.Fatalf("stored invitation grants=%v want=%v err=%v", invitation.Grants, test.grants, err)
			}
		})
	}
}

func TestNetworkConsentSignPresetSignsExactOwnerApprovedGrantSet(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	identity, err := e2ee.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	private, err := identity.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "owner.key")
	invitationPath := filepath.Join(root, "invite")
	proofPath := filepath.Join(root, "proof.json")
	if err := os.WriteFile(privatePath, private, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invitationPath, []byte("synthetic-owner-approved-invitation-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = networkConsentSign([]string{"--owner-private", privatePath, "--proof-file", proofPath,
		"--invitation-file", invitationPath, "--owner", "preset_owner", "--hub", "preset_hub",
		"--network", "preset_network", "--node", "preset_node", "--session", "preset_session",
		"--preset", "network_admin_inviter"}, &output)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatal(err)
	}
	var grant e2ee.OwnerNetworkJoinGrant
	if err := json.Unmarshal(proof, &grant); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(grant.Grants, []string{"network.admin.invite"}) ||
		grant.OwnerID != "preset_owner" || grant.NetworkID != "preset_network" {
		t.Fatalf("Owner consent did not sign exact preset: %#v", grant)
	}
	if bytes.Contains(output.Bytes(), []byte("network.admin.invite")) {
		t.Fatal("consent CLI printed the signed grant body")
	}
}
