//go:build windows

package native

import (
	"errors"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ownerFilePickerAvailable = true
	ofnNoChangeDir           = 0x00000008
	ofnPathMustExist         = 0x00000800
	ofnFileMustExist         = 0x00001000
	ofnNoDereferenceLink     = 0x00100000
	ofnDontAddToRecent       = 0x02000000
	ofnExplorer              = 0x00080000
)

type openFilenameW struct {
	structSize       uint32
	hwndOwner        uintptr
	hInstance        uintptr
	filter           *uint16
	customFilter     *uint16
	maxCustFilter    uint32
	filterIndex      uint32
	file             *uint16
	maxFile          uint32
	fileTitle        *uint16
	maxFileTitle     uint32
	initialDir       *uint16
	title            *uint16
	flags            uint32
	fileOffset       uint16
	fileExtension    uint16
	defaultExtension *uint16
	customData       uintptr
	hook             uintptr
	templateName     *uint16
	reserved         unsafe.Pointer
	reservedValue    uint32
	flagsEx          uint32
}

var (
	commonDialog      = windows.NewLazySystemDLL("comdlg32.dll")
	getOpenFileName   = commonDialog.NewProc("GetOpenFileNameW")
	getSaveFileName   = commonDialog.NewProc("GetSaveFileNameW")
	commonDialogError = commonDialog.NewProc("CommDlgExtendedError")
)

func chooseOwnerPublicDestination(title string) (string, error) {
	filter := append(utf16.Encode([]rune("Public JSON (*.json)\x00*.json\x00")), 0)
	titleUTF16, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return "", errors.New("file picker configuration failed")
	}
	pathBuffer := make([]uint16, 32768)
	copy(pathBuffer, utf16.Encode([]rune("owner-public.json")))
	of := openFilenameW{structSize: uint32(unsafe.Sizeof(openFilenameW{})), filter: &filter[0], filterIndex: 1, file: &pathBuffer[0], maxFile: uint32(len(pathBuffer)), title: titleUTF16,
		flags: ofnNoChangeDir | ofnPathMustExist | ofnNoDereferenceLink | ofnDontAddToRecent | ofnExplorer}
	result, _, _ := getSaveFileName.Call(uintptr(unsafe.Pointer(&of)))
	if result == 0 {
		code, _, _ := commonDialogError.Call()
		if code == 0 {
			return "", errOwnerImportCancelled
		}
		return "", errors.New("native file picker failed")
	}
	path := syscall.UTF16ToString(pathBuffer)
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("native file picker returned an invalid path")
	}
	return filepath.Clean(path), nil
}

func choosePEMFile(title string) (string, error) {
	filter := append(utf16.Encode([]rune("PEM files (*.pem)\x00*.pem\x00All files (*.*)\x00*.*\x00")), 0)
	titleUTF16, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return "", errors.New("file picker configuration failed")
	}
	pathBuffer := make([]uint16, 32768)
	of := openFilenameW{
		structSize:  uint32(unsafe.Sizeof(openFilenameW{})),
		filter:      &filter[0],
		filterIndex: 1,
		file:        &pathBuffer[0],
		maxFile:     uint32(len(pathBuffer)),
		title:       titleUTF16,
		flags:       ofnNoChangeDir | ofnPathMustExist | ofnFileMustExist | ofnNoDereferenceLink | ofnDontAddToRecent | ofnExplorer,
	}
	result, _, _ := getOpenFileName.Call(uintptr(unsafe.Pointer(&of)))
	if result == 0 {
		code, _, _ := commonDialogError.Call()
		if code == 0 {
			return "", errOwnerImportCancelled
		}
		return "", errors.New("native file picker failed")
	}
	path := syscall.UTF16ToString(pathBuffer)
	if path == "" || strings.ContainsRune(path, '\x00') {
		return "", errors.New("native file picker returned an invalid path")
	}
	return filepath.Clean(path), nil
}
