//go:build !linux || !amd64 || !cgo || !cicada_pqtls

package pqtls

import "time"

func runTLSCertificate(int, []byte, []byte, []byte, []byte, TLSLeafParameters, time.Time) (tlsCertificateResult, error) {
	return tlsCertificateResult{}, ErrUnavailable
}
