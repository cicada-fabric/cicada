//go:build windows

package appvault

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const dpapiProtectorID = "WINDOWS-DPAPI-CURRENT-USER-v1"

type currentUserProtector struct{}

func NewPlatformProtector() (Protector, error) { return currentUserProtector{}, nil }
func (currentUserProtector) ID() string        { return dpapiProtectorID }

func (currentUserProtector) WrapKey(context, key []byte) ([]byte, error) {
	if len(key) != 32 || len(context) == 0 || len(context) > 2048 {
		return nil, ErrInvalidVault
	}
	return dpapi(key, context, true)
}

func (currentUserProtector) UnwrapKey(context, wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 || len(wrapped) > maxWrappedKeyBytes || len(context) == 0 || len(context) > 2048 {
		return nil, ErrInvalidVault
	}
	return dpapi(wrapped, context, false)
}

func dpapi(input, entropy []byte, protect bool) ([]byte, error) {
	in := windows.DataBlob{Size: uint32(len(input))}
	if len(input) > 0 {
		in.Data = &input[0]
	}
	extra := windows.DataBlob{Size: uint32(len(entropy))}
	if len(entropy) > 0 {
		extra.Data = &entropy[0]
	}
	var out windows.DataBlob
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN)
	var err error
	if protect {
		err = windows.CryptProtectData(&in, nil, &extra, 0, nil, flags, &out)
	} else {
		var description *uint16
		err = windows.CryptUnprotectData(&in, &description, &extra, 0, nil, flags, &out)
		if description != nil {
			_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(description)))
		}
	}
	if err != nil || out.Data == nil || out.Size == 0 || out.Size > maxWrappedKeyBytes {
		if out.Data != nil {
			_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
		}
		return nil, ErrInvalidVault
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) }()
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}

var _ Protector = currentUserProtector{}
