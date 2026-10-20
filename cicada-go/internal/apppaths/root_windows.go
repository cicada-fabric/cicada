//go:build windows

package apppaths

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validatePlatformRoot(selected string) error {
	// Device paths, UNC roots and Win32 filename aliases have different
	// locking/ACL semantics; they are not silently normalized into local roots.
	if strings.HasPrefix(selected, `\\`) || len(filepath.VolumeName(selected)) != 2 {
		return ErrInvalidRoot
	}
	current := selected
	checkedAccess := false
	for {
		info, err := os.Lstat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err == nil {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return ErrInvalidRoot
			}
			wide, err := windows.UTF16PtrFromString(current)
			if err != nil {
				return err
			}
			attrs, err := windows.GetFileAttributes(wide)
			if err != nil || attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				return ErrInvalidRoot
			}
			// The nearest existing directory must protect creation/writes.
			// Every ancestor must also prevent an unrelated user replacing
			// the protected child or granting themselves that permission.
			if err := checkRootACL(current, info, !checkedAccess); err != nil {
				return err
			}
			checkedAccess = true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		part := filepath.Base(current)
		if !filepath.IsLocal(part) || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return ErrInvalidRoot
		}
		current = parent
	}
}

func checkRootACL(path string, before os.FileInfo, nearest bool) error {
	wide, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(wide, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return ErrInvalidRoot
	}
	defer file.Close()
	opened, statErr := file.Stat()
	after, afterErr := os.Lstat(path)
	var info windows.ByHandleFileInformation
	if statErr != nil || afterErr != nil || !os.SameFile(before, opened) || !os.SameFile(before, after) ||
		windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return ErrInvalidRoot
	}
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return ErrInvalidRoot
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return ErrInvalidRoot
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	trusted := func(sid *windows.SID) bool {
		if sid == nil {
			return false
		}
		if sid.Equals(user.User.Sid) || sid.Equals(system) || sid.Equals(admins) {
			return true
		}
		// Windows may give an OS ancestor to the servicing identity. Resolve
		// only a local service SID; arbitrary/domain owners remain refused.
		if !strings.HasPrefix(sid.String(), "S-1-5-80-") {
			return false
		}
		account, domain, _, err := sid.LookupAccount("")
		return err == nil && strings.EqualFold(domain, "NT SERVICE") && strings.EqualFold(account, "TrustedInstaller")
	}
	owner, _, err := sd.Owner()
	if err != nil || !trusted(owner) {
		return ErrInvalidRoot
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return ErrInvalidRoot
	}
	// FILE_DELETE_CHILD from WinNT.h is not exported by the pinned x/sys.
	const fileDeleteChild = 0x0040
	const writeMask = windows.GENERIC_WRITE | windows.GENERIC_ALL | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | fileDeleteChild
	// Creating siblings in an OS ancestor does not itself allow replacing the
	// private child. DELETE_CHILD/ACL/owner replacement rights do.
	mask := windows.ACCESS_MASK(windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | fileDeleteChild | windows.GENERIC_ALL)
	if nearest {
		mask = writeMask
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace == nil {
			return ErrInvalidRoot
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrInvalidRoot
		}
		if ace.Mask&mask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)))
		if !trusted(sid) {
			return ErrInvalidRoot
		}
	}
	return nil
}
