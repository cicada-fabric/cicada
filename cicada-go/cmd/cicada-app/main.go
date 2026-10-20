//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"

	"gioui.org/app"
	"github.com/cicada-ai/cicada/internal/appcore"
	"github.com/cicada-ai/cicada/internal/appui/native"
)

func main() {
	flags := flag.NewFlagSet("cicada-app", flag.ContinueOnError)
	userRoot := flags.String("user-root", "", "absolute Cicada user-file root (default ~/.cicada)")
	if err := flags.Parse(os.Args[1:]); err != nil || len(flags.Args()) != 0 {
		os.Exit(2)
	}
	controller, err := appcore.OpenNativeControllerWithRoot(*userRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cicada App could not initialize its local core.")
		os.Exit(1)
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
