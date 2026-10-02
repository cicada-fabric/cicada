//go:build !linux || !amd64 || !cgo || !cicada_pqtls

package pqtls

func generateTLSCSR(TLSCSRParameters) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, ErrUnavailable
}
func inspectTLSCSR([]byte, TLSCSRParameters) ([]byte, error) {
	return nil, ErrUnavailable
}
