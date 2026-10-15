//go:build windows

package appvault

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/gofrs/flock"
	"golang.org/x/sys/windows"
)

// MoveFileEx with MOVEFILE_WRITE_THROUGH supplies the Windows write-through
// publication path; Go has no portable directory-fsync equivalent here.
var syncVaultParentDirectory = func(string) error { return nil }

func ensurePrivateDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || rejectReparseComponents(path) != nil {
		return ErrInvalidVault
	}
	volume := filepath.VolumeName(path)
	current := volume + string(filepath.Separator)
	parts := strings.Split(strings.TrimLeft(strings.TrimPrefix(path, current), string(filepath.Separator)), string(filepath.Separator))
	created := false
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		attr, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			security, secErr := privateSecurityAttributes(true)
			if secErr != nil {
				return ErrInvalidVault
			}
			name, nameErr := windows.UTF16PtrFromString(current)
			if nameErr != nil {
				return ErrInvalidVault
			}
			if createErr := windows.CreateDirectory(name, security); createErr != nil && !errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
				return ErrInvalidVault
			}
			created = true
			attr, err = windows.GetFileAttributes(name)
		}
		if err != nil || attr&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || attr&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrInvalidVault
		}
		if created && verifyVaultACL(current, true) != nil {
			return ErrInvalidVault
		}
	}
	if verifyVaultACL(path, true) != nil {
		return ErrInvalidVault
	}
	return nil
}

func ensureLockFile(path string) error {
	if validatePrivateParent(filepath.Dir(path)) != nil {
		return ErrInvalidVault
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if err := createProtectedFile(path, nil); err != nil {
			return ErrInvalidVault
		}
	} else if err != nil {
		return ErrInvalidVault
	}
	if verifyVaultACL(path, false) != nil {
		return ErrInvalidVault
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return ErrInvalidVault
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrInvalidVault
	}
	return nil
}

func verifyLockFile(path string, lock *flock.Flock) error {
	if lock == nil || !lock.Locked() || lock.Path() != path || validatePrivateParent(filepath.Dir(path)) != nil || verifyVaultACL(path, false) != nil {
		return ErrInvalidVault
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ErrInvalidVault
	}
	return nil
}

func validatePlatformVaultFile(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() || verifyVaultACL(path, false) != nil || validatePrivateParent(filepath.Dir(path)) != nil {
		return ErrInvalidVault
	}
	return nil
}

func writeVaultAtomic(path string, data []byte, replace bool) (bool, error) {
	parent := filepath.Dir(path)
	if validatePrivateParent(parent) != nil || len(data) == 0 || len(data) > maxVaultFileBytes {
		return false, ErrInvalidVault
	}
	if replace {
		if _, err := checkVaultFile(path); err != nil {
			return false, ErrInvalidVault
		}
	} else if _, err := os.Lstat(path); err == nil {
		return false, ErrVaultExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, ErrInvalidVault
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return false, ErrInvalidVault
	}
	temporary := filepath.Join(parent, ".cicada-appvault-"+hexString(random[:]))
	if err := createProtectedFile(temporary, data); err != nil {
		return false, ErrInvalidVault
	}
	flags := uint32(windows.MOVEFILE_WRITE_THROUGH)
	if replace {
		flags |= windows.MOVEFILE_REPLACE_EXISTING
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return false, ErrInvalidVault
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		_ = os.Remove(temporary)
		return false, ErrInvalidVault
	}
	if err := windows.MoveFileEx(from, to, flags); err != nil {
		committed := fileMatches(path, data)
		_ = os.Remove(temporary)
		return committed, ErrInvalidVault
	}
	return true, nil
}

func createProtectedFile(path string, data []byte) error {
	if validatePrivateParent(filepath.Dir(path)) != nil {
		return ErrInvalidVault
	}
	security, err := privateSecurityAttributes(false)
	if err != nil {
		return ErrInvalidVault
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrInvalidVault
	}
	handle, err := windows.CreateFile(name,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return ErrInvalidVault
	}
	f := os.NewFile(uintptr(handle), path)
	if f == nil {
		_ = windows.CloseHandle(handle)
		_ = os.Remove(path)
		return ErrInvalidVault
	}
	if err = verifyVaultACL(path, false); err == nil && len(data) > 0 {
		err = writeAll(f, data)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		_ = os.Remove(path)
		return ErrInvalidVault
	}
	return nil
}

func fileMatches(path string, expected []byte) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	defer clear(data)
	if len(data) != len(expected) {
		return false
	}
	for i := range data {
		if data[i] != expected[i] {
			return false
		}
	}
	return true
}

func validatePrivateParent(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || rejectReparseComponents(path) != nil || verifyVaultACL(path, true) != nil {
		return ErrInvalidVault
	}
	return nil
}

func rejectReparseComponents(path string) error {
	clean := filepath.Clean(path)
	if clean != path {
		return ErrInvalidVault
	}
	volume := filepath.VolumeName(path)
	current := volume + string(filepath.Separator)
	rest := strings.TrimPrefix(path, current)
	missing := false
	for _, part := range strings.Split(rest, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		if missing {
			continue
		}
		attr, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(current))
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			missing = true
			continue
		}
		if err != nil || attr&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrInvalidVault
		}
	}
	return nil
}

func privateSecurityAttributes(directory bool) (*windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, ErrInvalidVault
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sddl := "O:" + user.User.Sid.String() + "D:P(A;" + inherit + ";FA;;;" + user.User.Sid.String() + ")(A;" + inherit + ";FA;;;SY)"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, ErrInvalidVault
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}, nil
}

func verifyVaultACL(path string, directory bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return ErrInvalidVault
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrInvalidVault
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return ErrInvalidVault
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return ErrInvalidVault
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return ErrInvalidVault
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !owner.Equals(user.User.Sid) {
		return ErrInvalidVault
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrInvalidVault
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return ErrInvalidVault
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return ErrInvalidVault
	}
	seenUser, seenSystem := false, false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != windows.ACCESS_MASK(0x001F01FF) {
			return ErrInvalidVault
		}
		aceSID := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)))
		switch {
		case aceSID.Equals(user.User.Sid) && !seenUser:
			seenUser = true
		case aceSID.Equals(system) && !seenSystem:
			seenSystem = true
		default:
			return ErrInvalidVault
		}
		wantFlags := uint8(0)
		if directory {
			wantFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		}
		if ace.Header.AceFlags != wantFlags {
			return ErrInvalidVault
		}
	}
	if !seenUser || !seenSystem {
		return ErrInvalidVault
	}
	return nil
}
