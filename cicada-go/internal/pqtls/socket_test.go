//go:build linux && amd64 && cgo && cicada_pqtls

package pqtls

import "syscall"

func syscallSetsockopt(fd int) error {
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 4096)
}
