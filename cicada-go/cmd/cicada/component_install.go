package main

import (
	"io"

	"github.com/cicada-ai/cicada/internal/componentinstall"
)

func componentInstallCommand(args []string, output io.Writer) error {
	return componentinstall.Command(args, output)
}
