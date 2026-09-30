//go:build js && wasm && !cicada_interop_test

package main

import "syscall/js"

func registerInterop(js.Value) {}
