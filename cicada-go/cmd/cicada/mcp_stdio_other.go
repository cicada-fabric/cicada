//go:build !linux

package main

import "io"

// Windows pipe File.Close cancels pending I/O. Keep the exact owned streams.
// Other platforms retain their existing File.Close interruption semantics.
func prepareMCPStdioStreams(input io.Reader, output io.Writer) (io.Reader, io.Writer, func(), error) {
	return input, output, nil, nil
}
