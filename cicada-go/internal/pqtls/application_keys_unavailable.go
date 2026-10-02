//go:build !linux || !amd64 || !cgo || !cicada_pqtls

package pqtls

const tlsApplicationNativeBuild = false

func tlsIssuerSigningSPKIDER([]byte) ([]byte, error) {
	return nil, ErrUnavailable
}

func tlsApplicationSigningPublicFromSPKI([]byte) ([]byte, error) {
	return nil, ErrUnavailable
}

func checkTLSApplicationSigningPublicSeparation([]byte, []byte) error {
	return ErrUnavailable
}
