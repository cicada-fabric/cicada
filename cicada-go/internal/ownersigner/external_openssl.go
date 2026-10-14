package ownersigner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/mattn/go-isatty"
)

const (
	maxExternalPEMBytes = 1 << 20
	maxOpenSSLMessage   = 64 << 10
)

var openSSLVersionPattern = regexp.MustCompile(`^OpenSSL ([0-9]+)\.([0-9]+)\.([0-9]+)(?:[ .-]|$)`)

// OpenSSLPaths contains only paths. Encrypted private PEM bytes and
// passphrases are never opened or retained by Go.
type OpenSSLPaths struct {
	Executable     string `json:"executable"`
	KEMPrivate     string `json:"kem_private"`
	SigningPrivate string `json:"signing_private"`
}

// OpenSSLOperations adapts OpenSSL 3.5+ CLI private operations to the existing
// Owner proof protocol. ML-DSA signatures use OpenSSL's default empty context;
// ML-KEM shared secrets are captured only in bounded process-pipe memory.
type OpenSSLOperations struct {
	paths   OpenSSLPaths
	tempDir string
}

// CheckOpenSSL validates the executable version without opening either key.
// The caller supplies an absolute path so PATH lookup cannot select a program.
func CheckOpenSSL(executable string) error {
	if !filepath.IsAbs(executable) || !safePathText(executable) {
		return errors.New("OpenSSL executable path must be absolute and contain no control characters")
	}
	if err := validateExternalRegularPath(executable, 128<<20); err != nil {
		return errors.New("OpenSSL executable is not a safe regular file")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "version")
	command.Stdin, command.Stderr = nil, io.Discard
	command.Env = openSSLEnvironment()
	var output limitedBuffer
	output.limit = 1024
	command.Stdout = &output
	if err := command.Run(); err != nil {
		return errors.New("OpenSSL version check failed")
	}
	version := strings.TrimSpace(string(output.data.Bytes()))
	match := openSSLVersionPattern.FindStringSubmatch(version)
	if match == nil {
		return errors.New("private-key operations require OpenSSL 3.5 or newer")
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	if major < 3 || (major == 3 && minor < 5) {
		return errors.New("private-key operations require OpenSSL 3.5 or newer")
	}
	return nil
}

// NewOpenSSLOperations validates public path metadata only. Private PEM bytes
// remain exclusively in the OpenSSL process when an operation runs.
func NewOpenSSLOperations(paths OpenSSLPaths, tempDir string) (*OpenSSLOperations, error) {
	if err := CheckOpenSSL(paths.Executable); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(paths.KEMPrivate) || !filepath.IsAbs(paths.SigningPrivate) ||
		!safePathText(paths.KEMPrivate) || !safePathText(paths.SigningPrivate) ||
		!filepath.IsAbs(tempDir) || !safePathText(tempDir) {
		return nil, errors.New("OpenSSL private-key and protected temporary paths must be absolute and safe")
	}
	if err := validateExternalPrivateFile(paths.KEMPrivate, maxExternalPEMBytes); err != nil {
		return nil, errors.New("ML-KEM private PEM path is unsafe")
	}
	if err := validateExternalPrivateFile(paths.SigningPrivate, maxExternalPEMBytes); err != nil {
		return nil, errors.New("ML-DSA private PEM path is unsafe")
	}
	if err := rejectEmptyPassphrase(paths.Executable, paths.KEMPrivate); err != nil {
		return nil, errors.New("ML-KEM private PEM must be encrypted with a nonempty passphrase")
	}
	if err := rejectEmptyPassphrase(paths.Executable, paths.SigningPrivate); err != nil {
		return nil, errors.New("ML-DSA private PEM must be encrypted with a nonempty passphrase")
	}
	if err := checkExternalPrivateDirectory(tempDir); err != nil {
		return nil, errors.New("OpenSSL operation directory is not protected")
	}
	return &OpenSSLOperations{paths: paths, tempDir: tempDir}, nil
}

func rejectEmptyPassphrase(executable, privatePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "pkey", "-in", privatePath, "-noout", "-passin", "pass:")
	command.Stdin, command.Stdout, command.Stderr = nil, io.Discard, io.Discard
	command.Env = openSSLEnvironment()
	if err := command.Run(); err == nil {
		return errors.New("unencrypted private PEM")
	}
	return nil
}

func (o *OpenSSLOperations) Sign(message []byte) ([]byte, error) {
	if o == nil || len(message) == 0 || len(message) > maxOpenSSLMessage {
		return nil, e2ee.ErrPrivateOperation
	}
	if err := requireOpenSSLTerminal(); err != nil {
		return nil, e2ee.ErrPrivateOperation
	}
	inputPath, outputPath, cleanup, err := o.operationFiles(message)
	if err != nil {
		return nil, e2ee.ErrPrivateOperation
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, o.paths.Executable, "pkeyutl", "-sign", "-rawin", "-inkey", o.paths.SigningPrivate,
		"-in", inputPath, "-out", outputPath)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, io.Discard, os.Stderr
	command.Env = openSSLEnvironment()
	if err := command.Run(); err != nil {
		return nil, e2ee.ErrPrivateOperation
	}
	signature, err := readExternalOperationFile(outputPath, mldsa65.SignatureSize)
	if err != nil || len(signature) != mldsa65.SignatureSize {
		return nil, e2ee.ErrPrivateOperation
	}
	return signature, nil
}

func (o *OpenSSLOperations) MLKEMDecapsulate(ciphertext []byte) ([]byte, error) {
	if o == nil || len(ciphertext) != mlkem768.CiphertextSize {
		return nil, e2ee.ErrPrivateOperation
	}
	if err := requireOpenSSLTerminal(); err != nil {
		return nil, e2ee.ErrPrivateOperation
	}
	inputPath, _, cleanup, err := o.operationFiles(ciphertext)
	if err != nil {
		return nil, e2ee.ErrPrivateOperation
	}
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, o.paths.Executable, "pkeyutl", "-decap", "-inkey", o.paths.KEMPrivate,
		"-in", inputPath, "-secret", "-")
	command.Stdin, command.Stderr = os.Stdin, os.Stderr
	command.Env = openSSLEnvironment()
	var secret limitedBuffer
	secret.limit = mlkem768.SharedKeySize
	command.Stdout = &secret
	if err := command.Run(); err != nil || secret.data.Len() != mlkem768.SharedKeySize {
		clear(secret.data.Bytes())
		return nil, e2ee.ErrPrivateOperation
	}
	result := append([]byte(nil), secret.data.Bytes()...)
	clear(secret.data.Bytes())
	return result, nil
}

func (o *OpenSSLOperations) operationFiles(input []byte) (string, string, func(), error) {
	if err := checkExternalPrivateDirectory(o.tempDir); err != nil {
		return "", "", nil, err
	}
	directory, err := createExternalPrivateTempDir(o.tempDir)
	if err != nil {
		return "", "", nil, err
	}
	inputFile, err := createExternalPrivateFile(directory, "input-", input)
	if err != nil {
		_ = os.Remove(directory)
		return "", "", nil, err
	}
	outputFile, err := createExternalPrivateFile(directory, "output-", nil)
	if err != nil {
		_ = os.Remove(inputFile)
		_ = os.Remove(directory)
		return "", "", nil, err
	}
	cleanup := func() {
		_ = os.Remove(inputFile)
		_ = os.Remove(outputFile)
		_ = os.Remove(directory)
	}
	return inputFile, outputFile, cleanup, nil
}

func requireOpenSSLTerminal() error {
	if !isatty.IsTerminal(os.Stdin.Fd()) || !isatty.IsTerminal(os.Stderr.Fd()) {
		return errors.New("encrypted Owner PEM operations require an interactive terminal")
	}
	return nil
}

func openSSLEnvironment() []string {
	result := make([]string, 0, len(os.Environ())+1)
	for _, item := range os.Environ() {
		name, _, _ := strings.Cut(item, "=")
		if strings.EqualFold(name, "OPENSSL_CONF") || strings.EqualFold(name, "OPENSSL_MODULES") {
			continue
		}
		result = append(result, item)
	}
	config := "/dev/null"
	if runtime.GOOS == "windows" {
		config = "NUL"
	}
	return append(result, "OPENSSL_CONF="+config)
}

func safePathText(path string) bool {
	if !utf8.ValidString(path) || strings.TrimSpace(path) != path {
		return false
	}
	for _, r := range path {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func externalFileSHA256(path string) (string, error) {
	if err := validateExternalRegularPath(path, 128<<20); err != nil {
		return "", err
	}
	file, err := openExternalRegularFile(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, (128<<20)+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type limitedBuffer struct {
	data  bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if b.limit < 0 || len(data) > b.limit-b.data.Len() {
		return 0, errors.New("bounded OpenSSL output exceeded")
	}
	return b.data.Write(data)
}
