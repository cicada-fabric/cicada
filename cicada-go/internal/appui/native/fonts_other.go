//go:build !windows

package native

import "gioui.org/widget/material"

// Portable renderer tests use Gio's existing fonts. Windows keeps the original
// bounded current-system CJK loader; this does not add a non-Windows App entry.
func configureNativeFonts(*material.Theme) {}
