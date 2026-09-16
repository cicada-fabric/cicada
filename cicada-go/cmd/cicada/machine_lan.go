package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cicada-ai/cicada/internal/control"
)

const (
	lanDiscoveryProtocol = "cicada-machine-discovery-v1"
	lanDiscoveryPort     = 8788
	lanDiscoveryWait     = 2 * time.Second
)

type lanDiscoveryMessage struct {
	Protocol     string         `json:"protocol"`
	Request      string         `json:"request,omitempty"`
	Nonce        string         `json:"nonce,omitempty"`
	Response     string         `json:"response,omitempty"`
	ID           string         `json:"id,omitempty"`
	Name         string         `json:"name,omitempty"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
}

// runMachineLANDiscovery only prints discovered profiles. Registration remains
// an explicit operator action because a LAN response is unauthenticated and
// must never establish trust by itself.
func runMachineLANDiscovery(args []string) error {
	flags := newFlagSet("machine discover-lan")
	port := flags.Int("port", lanDiscoveryPort, "UDP discovery port")
	wait := flags.Duration("wait", lanDiscoveryWait, "time to wait for profiles")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *port < 1 || *port > 65535 || *wait <= 0 || *wait > 30*time.Second {
		return errors.New("LAN discovery requires a valid port and wait between 1ns and 30s")
	}
	profiles, err := discoverLAN(context.Background(), *port, *wait)
	if err != nil {
		return err
	}
	return printJSON(profiles)
}

func discoverLAN(ctx context.Context, port int, wait time.Duration) ([]lanDiscoveryMessage, error) {
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("open LAN discovery socket: %w", err)
	}
	defer connection.Close()
	if err := connection.SetWriteBuffer(64 << 10); err != nil {
		return nil, err
	}
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	request, _ := json.Marshal(lanDiscoveryMessage{Protocol: lanDiscoveryProtocol, Request: "discover", Nonce: hex.EncodeToString(nonceBytes)})
	if _, err := connection.WriteToUDP(request, &net.UDPAddr{IP: net.IPv4bcast, Port: port}); err != nil {
		return nil, fmt.Errorf("broadcast LAN discovery: %w", err)
	}
	deadline := time.Now().Add(wait)
	profiles := make([]lanDiscoveryMessage, 0, 4)
	seen := map[string]bool{}
	for {
		if err := connection.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		var buffer [machineDiscoveryOutputLimit]byte
		n, _, readErr := connection.ReadFromUDP(buffer[:])
		if readErr != nil {
			if timeoutError(readErr) || errors.Is(readErr, net.ErrClosed) {
				break
			}
			return nil, readErr
		}
		var response lanDiscoveryMessage
		if json.Unmarshal(buffer[:n], &response) != nil || response.Protocol != lanDiscoveryProtocol || response.Response != "profile" || response.ID == "" || seen[response.ID] {
			continue
		}
		seen[response.ID] = true
		response.Capabilities = cloneMap(response.Capabilities)
		profiles = append(profiles, response)
		select {
		case <-ctx.Done():
			return profiles, nil
		default:
		}
	}
	return profiles, nil
}

func serveLANDiscovery(ctx context.Context, id, name string, port int) error {
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return err
	}
	defer connection.Close()
	go func() {
		<-ctx.Done()
		_ = connection.Close()
	}()
	for {
		var buffer [64 << 10]byte
		n, address, readErr := connection.ReadFromUDP(buffer[:])
		if readErr != nil {
			if ctx.Err() != nil || errors.Is(readErr, net.ErrClosed) {
				return nil
			}
			return readErr
		}
		var request lanDiscoveryMessage
		if json.Unmarshal(buffer[:n], &request) != nil || request.Protocol != lanDiscoveryProtocol || request.Request != "discover" || strings.TrimSpace(request.Nonce) == "" {
			continue
		}
		response, _ := json.Marshal(lanDiscoveryMessage{
			Protocol: lanDiscoveryProtocol, Response: "profile", Nonce: request.Nonce,
			ID: id, Name: name, Capabilities: control.DiscoverMachineCapabilities(),
		})
		_, _ = connection.WriteToUDP(response, address)
	}
}

func timeoutError(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}
