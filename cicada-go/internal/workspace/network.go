package workspace

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"
)

var lookupIP = net.DefaultResolver.LookupIPAddr

func validatePublicGitHost(ctx context.Context, rawURL string) error {
	target, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	host := strings.ToLower(strings.TrimSuffix(target.Hostname(), "."))
	if host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") ||
		strings.HasSuffix(host, ".home.arpa") {
		return errors.New("workspace Git host is local or private")
	}
	addresses, err := lookupIP(ctx, host)
	if err != nil || len(addresses) == 0 {
		return errors.New("workspace Git host could not be resolved")
	}
	for _, address := range addresses {
		if !publicIP(address.IP) {
			return errors.New("workspace Git host resolved to a non-public address")
		}
	}
	return nil
}

func publicIP(ip net.IP) bool {
	return ip != nil && !ip.IsLoopback() && !ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified() && !ip.IsMulticast()
}
