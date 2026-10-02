//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

/*
#include <stdlib.h>
#include "csr_bridge.h"
*/
import "C"

import "unsafe"

func csrNativeError(result C.int) error {
	switch result {
	case C.PQ_CSR_PROFILE:
		return ErrProfile
	case C.PQ_CSR_INVALID:
		return ErrCSR
	default:
		return ErrUnavailable
	}
}

func csrRole(role string) C.int {
	if role == "hub" {
		return 1
	}
	return 0
}

func generateTLSCSR(p TLSCSRParameters) ([]byte, []byte, []byte, error) {
	dns := C.CString(p.DNSName)
	defer C.free(unsafe.Pointer(dns))
	var out C.pq_csr_output
	defer C.pq_csr_output_free(&out)
	if result := C.pq_csr_generate(dns, csrRole(p.Role), &out); result != C.PQ_CSR_OK {
		return nil, nil, nil, csrNativeError(result)
	}
	return C.GoBytes(unsafe.Pointer(out.private_key), C.int(out.private_key_len)),
		C.GoBytes(unsafe.Pointer(out.csr_der), C.int(out.csr_der_len)),
		C.GoBytes(unsafe.Pointer(out.spki_der), C.int(out.spki_der_len)), nil
}

func inspectTLSCSR(der []byte, p TLSCSRParameters) ([]byte, error) {
	dns := C.CString(p.DNSName)
	defer C.free(unsafe.Pointer(dns))
	data := C.CBytes(der)
	defer C.free(data)
	var out C.pq_csr_output
	defer C.pq_csr_output_free(&out)
	if result := C.pq_csr_inspect((*C.uchar)(data), C.size_t(len(der)), dns, csrRole(p.Role), &out); result != C.PQ_CSR_OK {
		return nil, csrNativeError(result)
	}
	return C.GoBytes(unsafe.Pointer(out.spki_der), C.int(out.spki_der_len)), nil
}
