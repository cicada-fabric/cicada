package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/clientoperator"
	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/mattn/go-isatty"
)

const clientOperatorUsage = "usage: cicada client prepare|manifest|enroll|capabilities|status|recover|retry|nodes preview|nodes confirm|nodes list --profile PRIVATE_DIR [options]"

func clientOperatorCommand(args []string, input io.Reader, output io.Writer) error {
	if len(args) == 0 || output == nil {
		return errors.New(clientOperatorUsage)
	}
	command := args[0]
	args = args[1:]
	if command == "nodes" {
		if len(args) == 0 {
			return errors.New(clientOperatorUsage)
		}
		command = "nodes " + args[0]
		args = args[1:]
	}
	allowed := map[string]bool{"prepare": true, "manifest": true, "enroll": true, "capabilities": true, "status": true, "recover": true, "retry": true, "nodes preview": true, "nodes confirm": true, "nodes list": true}
	if !allowed[command] {
		return errors.New(clientOperatorUsage)
	}
	flags := flag.NewFlagSet("client "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	profileDir := flags.String("profile", "", "existing independent mode 0700 Client profile directory")
	var origin, hubPath, ownerID, ownerPath, grantPath, codePath *string
	var allowHTTP *bool
	if command == "prepare" {
		origin = flags.String("origin", "", "independently selected HTTPS origin")
		hubPath = flags.String("hub-identity", "", "independently supplied complete public Hub identity document")
		ownerID = flags.String("owner-id", "", "existing Owner principal ID")
		ownerPath = flags.String("owner-public", "", "independently supplied Owner public identity")
		allowHTTP = flags.Bool("allow-loopback-http", false, "explicit development use of literal loopback HTTP")
	}
	if command == "enroll" {
		grantPath = flags.String("grant-file", "", "exact Owner Grant in a mode 0600 file")
	}
	if command == "nodes preview" {
		codePath = flags.String("code-file", "", "Node device code in a mode 0600 file")
	}
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 || *profileDir == "" {
		return errors.New(clientOperatorUsage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if command == "prepare" {
		if *origin == "" || *hubPath == "" || *ownerID == "" || *ownerPath == "" {
			return errors.New(clientOperatorUsage)
		}
		var hub clientoperator.HubIdentity
		var owner e2ee.PublicIdentity
		if err := readClientOperatorPublic(*hubPath, &hub); err != nil {
			return err
		}
		if err := readClientOperatorPublic(*ownerPath, &owner); err != nil {
			return err
		}
		profile, err := clientoperator.Prepare(*profileDir, *origin, *ownerID, hub, owner, *allowHTTP)
		if err != nil {
			return err
		}
		defer profile.Close()
		path, err := profile.WriteManifest()
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(struct {
			State        string `json:"state"`
			ManifestFile string `json:"manifest_file"`
			DeviceID     string `json:"device_id"`
		}{"NEEDS_OWNER_GRANT", path, profile.Manifest().DeviceID})
	}
	profile, err := clientoperator.Open(*profileDir)
	if err != nil {
		return err
	}
	defer profile.Close()
	if command == "manifest" {
		path, err := profile.WriteManifest()
		if err != nil {
			return err
		}
		return json.NewEncoder(output).Encode(struct {
			ManifestFile string `json:"manifest_file"`
			DeviceID     string `json:"device_id"`
		}{path, profile.Manifest().DeviceID})
	}
	var response *clientoperator.Response
	switch command {
	case "enroll":
		if *grantPath == "" {
			return errors.New(clientOperatorUsage)
		}
		grant, err := clientoperator.ReadPrivateFile(*grantPath, 16*1024)
		if err != nil {
			return err
		}
		if err = profile.Enroll(ctx, grant); err != nil {
			return err
		}
		response, err = profile.Capabilities(ctx)
	case "capabilities":
		response, err = profile.Capabilities(ctx)
	case "status":
		response, err = profile.Status(ctx)
	case "recover":
		response, err = profile.Recover(ctx)
	case "retry":
		response, err = profile.Retry(ctx)
	case "nodes list":
		response, err = profile.Nodes(ctx)
	case "nodes preview":
		if *codePath == "" {
			return errors.New(clientOperatorUsage)
		}
		code, readErr := clientoperator.ReadPrivateFile(*codePath, 128)
		if readErr != nil {
			return readErr
		}
		response, err = profile.PreviewNode(ctx, string(code))
	case "nodes confirm":
		candidate, reviewErr := profile.NodeReview()
		if reviewErr != nil {
			return reviewErr
		}
		if candidate.Mode == "UPGRADE" && (candidate.BindingID == "" || candidate.BindingVersion == 0) {
			return clientoperator.ErrUpgradeReview
		}
		if err = clientOperatorApproval(input, output, candidate); err != nil {
			return err
		}
		// Human review is governed by candidate expiry, not an HTTP timeout.
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		response, err = profile.ConfirmNode(ctx, candidate)
	}
	if err != nil {
		return err
	}
	if response == nil {
		return errors.New("Client operation returned no authenticated result")
	}
	if !response.OK {
		if response.ErrorCode == "OUTCOME_UNCERTAIN" {
			return clientoperator.ErrUncertain
		}
		return errors.New("authenticated Hub refused the Client operation")
	}
	return json.NewEncoder(output).Encode(response.Result)
}

func readClientOperatorPublic(path string, dst any) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot read independently supplied public identity")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) == 0 || len(data) > 65536 {
		return errors.New("public identity document has invalid size")
	}
	if err = decodeStrictBridgeJSON(data, dst); err != nil {
		return errors.New("public identity document is invalid")
	}
	return nil
}

func clientOperatorApproval(input io.Reader, output io.Writer, c clientoperator.NodeCandidate) error {
	f, ok := input.(*os.File)
	if !ok {
		return errors.New("Node approval requires an interactive terminal")
	}
	if !isatty.IsTerminal(f.Fd()) {
		return errors.New("Node approval requires an interactive terminal")
	}
	terminalOutput, ok := output.(*os.File)
	if !ok || !isatty.IsTerminal(terminalOutput.Fd()) {
		return errors.New("Node approval details must be visible on an interactive terminal")
	}
	fmt.Fprint(output, clientOperatorReviewText(c))
	line, err := bufio.NewReader(io.LimitReader(input, 128)).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "approve" {
		return errors.New("Node approval was not confirmed")
	}
	return nil
}

func clientOperatorReviewText(c clientoperator.NodeCandidate) string {
	return fmt.Sprintf("Approve Node %q (%s) at Hub %s?\nMode: %s; Node key epoch: %d\nTarget binding: %s version %d\nNode key: %s\nNode fingerprint: %s\nHub Node-Control key: %s version %d\nHub Node-Control fingerprint: %s\nCandidate: %s version %d, expires %s\nCompare these values with the Node's local display. Type approve to confirm: ",
		c.NodeName, c.NodeID, c.HubID, c.Mode, c.NodeKeyEpoch, c.BindingID, c.BindingVersion, c.NodeKeyID, c.NodeKeyFingerprint, c.HubNodeControlKeyID, c.HubNodeControlKeyVersion, c.HubNodeControlFingerprint, c.CandidateDigest, c.Version, c.ExpiresAt)
}
