//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

/*
#include <stdlib.h>
#include "certificate_bridge.h"
*/
import "C"

import (
	"time"
	"unsafe"
)

func certificateNativeError(code C.int) error {
	switch code {
	case C.PQ_CERT_PROFILE:
		return ErrProfile
	case C.PQ_CERT_INVALID:
		return ErrCertificate
	case C.PQ_CERT_ISSUER:
		return ErrIssuer
	case C.PQ_CERT_TIME:
		return ErrCertificateValidity
	default:
		return ErrUnavailable
	}
}
func runTLSCertificate(operation int, chain, root, key, object []byte, p TLSLeafParameters, at time.Time) (tlsCertificateResult, error) {
	chainC, rootC := C.CBytes(chain), C.CBytes(root)
	defer C.free(chainC)
	defer C.free(rootC)
	var keyC, objectC unsafe.Pointer
	if len(key) > 0 {
		keyC = C.CBytes(key)
		defer C.pq_certificate_secret_free(keyC, C.size_t(len(key)))
	}
	if len(object) > 0 {
		objectC = C.CBytes(object)
		defer C.free(objectC)
	}
	var params C.pq_certificate_parameters
	if p.Role == "hub" {
		params.hub = 1
	}
	for i, b := range []byte(p.DNSName) {
		params.dns[i] = C.char(b)
	}
	for i, b := range p.Serial {
		params.serial[i] = C.uchar(b)
	}
	for i, b := range p.ExpectedSPKIHash {
		params.spki[i] = C.uchar(b)
	}
	params.not_before = C.int64_t(p.NotBefore.Unix())
	params.not_after = C.int64_t(p.NotAfter.Unix())
	params.at = C.int64_t(at.Unix())
	var output C.pq_certificate_output
	defer C.pq_certificate_output_free(&output)
	code := C.pq_certificate_run(C.int(operation), (*C.uchar)(chainC), C.size_t(len(chain)), (*C.uchar)(rootC), C.size_t(len(root)),
		(*C.uchar)(keyC), C.size_t(len(key)), (*C.uchar)(objectC), C.size_t(len(object)), &params, &output)
	if code != C.PQ_CERT_OK {
		return tlsCertificateResult{}, certificateNativeError(code)
	}
	v := tlsCertificateResult{NotBefore: time.Unix(int64(output.verified_not_before), 0).UTC(), NotAfter: time.Unix(int64(output.verified_not_after), 0).UTC()}
	for i := range v.SPKIHash {
		v.SPKIHash[i] = byte(output.spki[i])
		v.IssuerHash[i] = byte(output.issuer[i])
	}
	if output.certificate_der_len > 0 {
		v.CertificateDER = C.GoBytes(unsafe.Pointer(output.certificate_der), C.int(output.certificate_der_len))
	}
	return v, nil
}
