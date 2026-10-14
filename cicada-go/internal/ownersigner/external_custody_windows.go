//go:build windows

package ownersigner

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func validateExternalRegularPath(path string, max int64) error {
	if err := validateWindowsPathComponents(path, false); err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || (max > 0 && info.Size() > max) {
		return errors.New("path is not a bounded regular file")
	}
	return nil
}

func validateExternalPrivateFile(path string, max int64) error {
	return validateExternalRegularPath(path, max)
}

func checkExternalPrivateFile(path string) error {
	if err := validateWindowsPathComponents(path, false); err != nil {
		return err
	}
	return verifyExternalACL(path, false)
}

func openExternalRegularFile(path string) (*os.File, error) {
	if err := validateExternalRegularPath(path, 0); err != nil {
		return nil, err
	}
	return os.Open(path)
}

func checkExternalPrivateDirectory(path string) error {
	if err := validateWindowsPathComponents(path, true); err != nil {
		return err
	}
	return verifyExternalACL(path, true)
}

func validateExternalParentDirectory(path string) error {
	if err := validateWindowsPathComponents(path, true); err != nil {
		return err
	}
	return nil
}

func createExternalPrivateDirectory(path string) error {
	if err := validateWindowsPathComponents(filepath.Dir(path), true); err != nil {
		return err
	}
	security, err := privateSecurityAttributes(true)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(name, security); err != nil {
		return err
	}
	if err := checkExternalPrivateDirectory(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func createExternalPrivateTempDir(parent string) (string, error) {
	if err := checkExternalPrivateDirectory(parent); err != nil {
		return "", err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	path := filepath.Join(parent, "openssl-op-"+hex.EncodeToString(random[:]))
	if err := createExternalPrivateDirectory(path); err != nil {
		return "", err
	}
	return path, nil
}

func createExternalPrivateFile(dir, prefix string, data []byte) (string, error) {
	if err := checkExternalPrivateDirectory(dir); err != nil || strings.ContainsAny(prefix, `/\\`) {
		return "", errors.New("private temporary directory is unsafe")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	path := filepath.Join(dir, prefix+hex.EncodeToString(random[:]))
	if err := createExternalPrivateFileAt(path, data); err != nil {
		return "", err
	}
	return path, nil
}

func createExternalPrivateFileAt(path string, data []byte) error {
	if err := validateWindowsPathComponents(filepath.Dir(path), true); err != nil {
		return err
	}
	security, err := privateSecurityAttributes(false)
	if err != nil {
		return err
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ, security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		_ = os.Remove(path)
		return errors.New("could not open protected temporary file")
	}
	if err = verifyExternalACL(path, false); err == nil && len(data) != 0 {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func readExternalPrivateFile(path string, max int64) ([]byte, error) {
	if err := checkExternalPrivateFile(path); err != nil {
		return nil, err
	}
	file, err := openExternalRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("private profile file size is invalid")
	}
	return data, nil
}

func replaceExternalAtomic(path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := checkExternalPrivateDirectory(parent); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := checkExternalPrivateFile(path); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := filepath.Join(parent, ".owner-signer-state-"+hex.EncodeToString(random[:]))
	if err := createExternalPrivateFileAt(temporary, data); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func writeExternalPublicExclusiveOrSame(path string, data []byte) error {
	absolute, err := filepath.Abs(path)
	if err != nil || !safePathText(absolute) || filepath.Clean(absolute) != absolute {
		return errors.New("public manifest path is not absolute and canonical")
	}
	parent := filepath.Dir(absolute)
	if err := validateWindowsPathComponents(parent, true); err != nil {
		return err
	}
	if existing, err := os.Lstat(absolute); err == nil {
		if err := verifyNoReparse(absolute, false); err != nil || !existing.Mode().IsRegular() {
			return errors.New("existing public manifest is not a regular non-reparse file")
		}
		current, err := os.ReadFile(absolute)
		if err != nil || len(current) > maxProfileBytes || !bytes.Equal(current, data) {
			return errors.New("existing public manifest differs from this Owner profile")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	temporary := filepath.Join(parent, ".owner-public-"+hex.EncodeToString(random[:]))
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	to, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func writeExternalPrivateExclusive(path string, data []byte) error {
	if len(data) == 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || validateExternalParentDirectory(filepath.Dir(path)) != nil {
		return errors.New("private grant output path is invalid")
	}
	return createExternalPrivateFileAt(path, data)
}

func writeExternalPublicExclusive(path string, data []byte) error {
	if len(data) == 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || validateExternalParentDirectory(filepath.Dir(path)) != nil {
		return errors.New("public summary output path is invalid")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return err
	}
	parent := filepath.Dir(path)
	temporary := filepath.Join(parent, ".owner-summary-"+hex.EncodeToString(random[:]))
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	from, err := windows.UTF16PtrFromString(temporary)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func readExternalOperationFile(path string, max int64) ([]byte, error) {
	if err := validateExternalPrivateFile(path, max); err != nil {
		return nil, err
	}
	file, err := openExternalRegularFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("OpenSSL output size is invalid")
	}
	return data, nil
}

func validateWindowsPathComponents(path string, wantDir bool) error {
	if !filepath.IsAbs(path) || !safePathText(path) || filepath.Clean(path) != path {
		return errors.New("path is not absolute and canonical")
	}
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' || strings.HasPrefix(path, `\\`) {
		return errors.New("only local drive paths are supported for Owner custody")
	}
	current := volume + string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(path, volume), string(filepath.Separator)), string(filepath.Separator))
	for i, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		isFinal := i == len(parts)-1
		if err := verifyNoReparse(current, !isFinal || wantDir); err != nil {
			return err
		}
	}
	return nil
}

func verifyNoReparse(path string, wantDir bool) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if wantDir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("path contains a reparse point or unavailable component")
	}
	if wantDir && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return errors.New("path component is not a directory")
	}
	if !wantDir && info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return errors.New("path is a directory, not a regular file")
	}
	return nil
}

func privateSecurityAttributes(directory bool) (*windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, errors.New("current Windows account SID is unavailable")
	}
	sid := user.User.Sid.String()
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sddl := "O:" + sid + "D:P(A;" + inherit + ";FA;;;" + sid + ")(A;" + inherit + ";FA;;;SY)"
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}, nil
}

func verifyExternalACL(path string, directory bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return errors.New("current Windows account SID is unavailable")
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(name, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("private path is a reparse point")
	}
	if directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return errors.New("private path type changed")
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || descriptor == nil {
		return errors.New("private path ACL could not be read")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || !owner.Equals(user.User.Sid) {
		return errors.New("private path is not owned by the current Windows account")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return errors.New("private path DACL is not protected from inherited access")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return errors.New("private path ACL is not the required user-and-System allowlist")
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	seenUser, seenSystem := false, false
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask != windows.ACCESS_MASK(0x001F01FF) {
			return errors.New("private path ACL contains an unexpected permission")
		}
		aceSID := (*windows.SID)(unsafe.Pointer(uintptr(unsafe.Pointer(ace)) + unsafe.Offsetof(windows.ACCESS_ALLOWED_ACE{}.SidStart)))
		switch {
		case aceSID.Equals(user.User.Sid) && !seenUser:
			seenUser = true
		case aceSID.Equals(system) && !seenSystem:
			seenSystem = true
		default:
			return errors.New("private path ACL grants access to an unexpected account")
		}
		wantFlags := uint8(0)
		if directory {
			wantFlags = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		}
		if ace.Header.AceFlags != wantFlags {
			return errors.New("private path ACL inheritance flags are unexpected")
		}
	}
	if !seenUser || !seenSystem {
		return errors.New("private path ACL does not contain the expected principals")
	}
	return nil
}
