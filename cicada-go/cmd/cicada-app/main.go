//go:build windows

package main

import (
	"fmt"
	"os"

	"gioui.org/app"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui/native"
)

func main() {
	controller, err := appcore.OpenNativeController()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cicada App could not initialize its local core.")
		return
	}
	go func() {
		windowErr := native.RunWindow(controller)
		closeErr := controller.Close()
		exitCode := 0
		if windowErr != nil {
			fmt.Fprintln(os.Stderr, "Cicada App window closed with an error.")
			exitCode = 1
		}
		if closeErr != nil {
			fmt.Fprintln(os.Stderr, "Cicada App could not close local state cleanly.")
			exitCode = 1
		}
		os.Exit(exitCode)
	}()
	app.Main()
}
