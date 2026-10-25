package main

import (
	"io"
	"os"
	"syscall"
	"time"
)

// Inherited Linux stdin/stdout can be blocking NewFile descriptors. Closing
// those does not reliably interrupt a blocked syscall. Register an owned dup
// with Go's poller before any I/O; only the passed connection pipes are affected.
func prepareMCPStdioStreams(input io.Reader, output io.Writer) (io.Reader, io.Writer, func(), error) {
	prepare := func(value any) (*os.File, error) {
		file, ok := value.(*os.File)
		if !ok {
			return nil, nil
		}
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeNamedPipe == 0 || file.SetDeadline(time.Time{}) == nil {
			return nil, nil
		}
		connection, err := file.SyscallConn()
		if err != nil {
			return nil, err
		}
		fd := -1
		var duplicateErr error
		syscall.ForkLock.RLock()
		err = connection.Control(func(original uintptr) {
			fd, duplicateErr = syscall.Dup(int(original))
			if duplicateErr == nil {
				syscall.CloseOnExec(fd)
				duplicateErr = syscall.SetNonblock(fd, true)
			}
		})
		syscall.ForkLock.RUnlock()
		if err == nil {
			err = duplicateErr
		}
		if err != nil {
			if fd >= 0 {
				_ = syscall.Close(fd)
			}
			return nil, err
		}
		prepared := os.NewFile(uintptr(fd), file.Name())
		if err = prepared.SetDeadline(time.Time{}); err != nil {
			_ = prepared.Close()
			return nil, err
		}
		return prepared, nil
	}
	preparedInput, err := prepare(input)
	if err != nil {
		return nil, nil, nil, err
	}
	preparedOutput, err := prepare(output)
	if err != nil {
		if preparedInput != nil {
			_ = preparedInput.Close()
		}
		return nil, nil, nil, err
	}
	originalInput, originalOutput := input, output
	cleanup := func() {
		if preparedInput != nil {
			_ = originalInput.(io.Closer).Close()
		}
		if preparedOutput != nil {
			_ = originalOutput.(io.Closer).Close()
		}
	}
	if preparedInput != nil {
		input = preparedInput
	}
	if preparedOutput != nil {
		output = preparedOutput
	}
	return input, output, cleanup, nil
}
