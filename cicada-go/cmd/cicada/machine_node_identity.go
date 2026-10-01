package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/fabric"
)

const machineNodeIdentityVersion = 1

const machineNodeBindingPollInterval = 5 * time.Second

type machineNodeIdentity struct {
	Version    int    `json:"version"`
	NodeID     string `json:"node_id"`
	RelayToken string `json:"-"`
}

type machineNodeDeviceCode struct {
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
}

type machineNodeDeviceCodeRequest struct {
	NodeID           string `json:"node_id"`
	NodeName         string `json:"node_name"`
	CredentialDigest string `json:"credential_digest"`
}

// loadOrCreateMachineNodeIdentity creates the Node bearer locally. The Hub
// only receives its digest in the separate device-code request.
func loadOrCreateMachineNodeIdentity(stateDir, nodeID string) (*machineNodeIdentity, string, error) {
	nodeID = strings.TrimSpace(nodeID)
	directory := machineNodeStateDir(stateDir, nodeID)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, "", fmt.Errorf("create Node identity directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, "", fmt.Errorf("protect Node identity directory: %w", err)
	}
	path := filepath.Join(directory, "identity.json")
	tokenPath := machineNodeCredentialPath(stateDir, nodeID)
	identity := &machineNodeIdentity{}
	data, err := os.ReadFile(path)
	if err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			return nil, "", fmt.Errorf("inspect Node identity: %w", statErr)
		}
		if !info.Mode().IsRegular() {
			return nil, "", errors.New("Node identity path must be a regular file")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, "", fmt.Errorf("protect Node identity: %w", err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(identity); err != nil {
			return nil, "", fmt.Errorf("decode Node identity: %w", err)
		}
		if identity.Version != machineNodeIdentityVersion || identity.NodeID != nodeID {
			return nil, "", errors.New("stored Node identity version or node_id does not match this Node")
		}
		tokenData, tokenErr := os.ReadFile(tokenPath)
		if tokenErr != nil {
			return nil, "", fmt.Errorf("read local Node credential: %w", tokenErr)
		}
		tokenInfo, tokenStatErr := os.Lstat(tokenPath)
		if tokenStatErr != nil {
			return nil, "", fmt.Errorf("inspect local Node credential: %w", tokenStatErr)
		}
		if !tokenInfo.Mode().IsRegular() {
			return nil, "", errors.New("Node credential path must be a regular file")
		}
		if err := os.Chmod(tokenPath, 0o600); err != nil {
			return nil, "", fmt.Errorf("protect local Node credential: %w", err)
		}
		identity.RelayToken = strings.TrimSpace(string(tokenData))
		if _, err := fabric.NodeCredentialFromAuthorization("CicadaNode " + identity.RelayToken); err != nil {
			return nil, "", errors.New("stored Node identity contains an invalid Relay credential")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, "", fmt.Errorf("read Node identity: %w", err)
	} else {
		token, _, err := fabric.NewNodeCredential()
		if err != nil {
			return nil, "", fmt.Errorf("generate local Node credential: %w", err)
		}
		identity = &machineNodeIdentity{Version: machineNodeIdentityVersion, NodeID: nodeID, RelayToken: token}
		if err := persistMachineNodeIdentity(path, tokenPath, identity); err != nil {
			return nil, "", err
		}
	}
	return identity, fabric.HashSessionCredential(identity.RelayToken), nil
}

func machineNodeCredentialPath(stateDir, nodeID string) string {
	return filepath.Join(machineNodeStateDir(stateDir, nodeID), "relay.token")
}

func persistMachineNodeIdentity(path, tokenPath string, identity *machineNodeIdentity) error {
	if identity == nil || identity.Version != machineNodeIdentityVersion || identity.NodeID == "" || identity.RelayToken == "" {
		return errors.New("invalid local Node identity")
	}
	if _, err := fabric.NodeCredentialFromAuthorization("CicadaNode " + identity.RelayToken); err != nil {
		return errors.New("local Node identity contains an invalid Relay credential")
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("encode local Node identity: %w", err)
	}
	if err := persistNodeSecretFile(tokenPath, []byte(identity.RelayToken+"\n"), ".node-token-*"); err != nil {
		return err
	}
	return persistNodeSecretFile(path, append(data, '\n'), ".node-identity-*")
}

func persistNodeSecretFile(path string, data []byte, pattern string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create Node identity directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("protect Node identity directory: %w", err)
	}
	temporary, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return fmt.Errorf("create protected Node identity file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("protect Node identity file: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write Node identity file: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("sync Node identity file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close Node identity file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install Node identity file: %w", err)
	}
	directory, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open Node identity directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync Node identity directory: %w", err)
	}
	return nil
}

// requestMachineNodeDeviceCode deliberately sends no Authorization header.
// The candidate Node bearer remains local; only its digest reaches Hub.
func requestMachineNodeDeviceCode(ctx context.Context, base, nodeID, nodeName, credentialDigest string) (*machineNodeDeviceCode, error) {
	if err := requireSecureNodeEnrollmentTransport(base); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(machineNodeDeviceCodeRequest{
		NodeID: nodeID, NodeName: nodeName, CredentialDigest: credentialDigest,
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/v2/nodes/device-code", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	client, err := machineNodeHTTPClient(ctx, 15*time.Second)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return nil, &machineAPIError{StatusCode: response.StatusCode, Status: response.Status,
			Body: strings.TrimSpace(string(body))}
	}
	var code machineNodeDeviceCode
	if err := json.NewDecoder(io.LimitReader(response.Body, 8*1024)).Decode(&code); err != nil {
		return nil, fmt.Errorf("decode Node device code: %w", err)
	}
	if !validFormattedNodeDeviceCode(code.UserCode) {
		return nil, errors.New("Hub returned an invalid Node device code")
	}
	if _, err := resolveNodeDeviceVerificationURL(base, code.VerificationURI); err != nil {
		return nil, err
	}
	return &code, nil
}

// awaitMachineNodeBinding prints the one-time pairing code, then only proceeds
// when Relay authenticates the locally-held bearer as an owner-bound Node.
func awaitMachineNodeBinding(ctx context.Context, base, nodeID, nodeName, token, credentialDigest string, once bool, output io.Writer) error {
	if output == nil {
		output = io.Discard
	}
	bound, probeErr := probeMachineNodeBinding(ctx, base, nodeID, token)
	if probeErr == nil && bound {
		return nil
	}
	if probeErr != nil && once {
		return fmt.Errorf("check owner-confirmed Node binding: %w", probeErr)
	}
	if probeErr != nil {
		fmt.Fprintln(output, "Node binding check:", probeErr)
	}
	challenge, err := requestMachineNodeDeviceCode(ctx, base, nodeID, nodeName, credentialDigest)
	if err != nil {
		return fmt.Errorf("request Node device code: %w", err)
	}
	verificationURL, err := resolveNodeDeviceVerificationURL(base, challenge.VerificationURI)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Android Client verification path (Client flow pending): %s\nDevice code: %s (valid for %s). Relay starts after owner confirmation.\n",
		verificationURL, challenge.UserCode, control.NodeDeviceCodeLifetime)
	if once {
		return errors.New("Node binding is waiting for owner confirmation; keep the agent running or start it again after approval")
	}
	codeExpires := time.Now().Add(control.NodeDeviceCodeLifetime - time.Minute)
	for {
		if err := waitMachineNodeBindingPoll(ctx); err != nil {
			return err
		}
		bound, probeErr = probeMachineNodeBinding(ctx, base, nodeID, token)
		if probeErr == nil && bound {
			return nil
		}
		if probeErr != nil {
			fmt.Fprintln(output, "Node binding check:", probeErr)
		}
		if time.Now().After(codeExpires) {
			challenge, err = requestMachineNodeDeviceCode(ctx, base, nodeID, nodeName, credentialDigest)
			if err != nil {
				var apiErr *machineAPIError
				if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusConflict {
					return fmt.Errorf("request replacement Node device code: %w", err)
				}
				fmt.Fprintln(output, "request replacement Node device code:", err)
				continue
			}
			verificationURL, err = resolveNodeDeviceVerificationURL(base, challenge.VerificationURI)
			if err != nil {
				return err
			}
			fmt.Fprintf(output, "The previous code expired. Android Client verification path (Client flow pending): %s\nDevice code: %s (valid for %s).\n",
				verificationURL, challenge.UserCode, control.NodeDeviceCodeLifetime)
			codeExpires = time.Now().Add(control.NodeDeviceCodeLifetime - time.Minute)
		}
	}
}

func waitMachineNodeBindingPoll(ctx context.Context) error {
	timer := time.NewTimer(machineNodeBindingPollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func probeMachineNodeBinding(ctx context.Context, base, nodeID, token string) (bool, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet,
		strings.TrimRight(base, "/")+"/v2/relay/nodes/"+url.PathEscape(nodeID)+"/events", nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Authorization", "CicadaNode "+token)
	client, err := machineNodeHTTPClient(ctx, 0)
	if err != nil {
		return false, err
	}
	response, err := client.Do(request)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return false, nil
	}
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return false, &machineAPIError{StatusCode: response.StatusCode, Status: response.Status,
			Body: strings.TrimSpace(string(body))}
	}
	if !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "text/event-stream") {
		return false, errors.New("Relay authorization probe did not return an event stream")
	}
	return true, nil
}

func sendMachineNodeHeartbeat(ctx context.Context, base, nodeID, token string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(base, "/")+"/v2/relay/nodes/"+url.PathEscape(nodeID)+"/heartbeat", bytes.NewReader([]byte(`{}`)))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "CicadaNode "+token)
	client, err := machineNodeHTTPClient(ctx, 10*time.Second)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return &machineAPIError{StatusCode: response.StatusCode, Status: response.Status,
			Body: strings.TrimSpace(string(body))}
	}
	return nil
}

func requireSecureNodeEnrollmentTransport(base string) error {
	parsed, err := url.Parse(base)
	if err != nil || parsed == nil || parsed.Hostname() == "" {
		return errors.New("invalid Hub URL for Node enrollment")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := strings.Trim(strings.ToLower(parsed.Hostname()), "[]")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return nil
	}
	if address := net.ParseIP(host); address != nil && address.IsLoopback() {
		return nil
	}
	return errors.New("remote Node enrollment requires an HTTPS Hub URL")
}

func resolveNodeDeviceVerificationURL(base, raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed == nil || parsed.IsAbs() || parsed.Host != "" || parsed.User != nil ||
		!strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("Hub returned an unsafe Node verification URI")
	}
	return strings.TrimRight(base, "/") + parsed.EscapedPath(), nil
}

func validFormattedNodeDeviceCode(value string) bool {
	if len(value) != 14 || value[4] != '-' || value[9] != '-' {
		return false
	}
	for index, character := range value {
		if index == 4 || index == 9 {
			continue
		}
		if !strings.ContainsRune("23456789ABCDEFGHJKLMNPQRSTUVWXYZ", character) {
			return false
		}
	}
	return true
}

func rejectNodeRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
