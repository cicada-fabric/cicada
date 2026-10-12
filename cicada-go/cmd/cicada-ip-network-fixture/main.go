// Disposable Docker network probe only. It is not shipped in CICADA packages.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	f := flag.NewFlagSet("synthetic IP network probe", flag.ExitOnError)
	address := f.String("address", "", "numeric IP socket")
	want := f.String("expect", "unreachable", "expected probe result")
	f.Parse(os.Args[2:])
	host, _, err := net.SplitHostPort(*address)
	if err != nil || net.ParseIP(host) == nil {
		os.Exit(2)
	}
	if os.Args[1] == "listen" {
		listener, err := net.Listen("tcp", *address)
		if err != nil {
			os.Exit(1)
		}
		defer listener.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		go func() { <-ctx.Done(); listener.Close() }()
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}
	if os.Args[1] != "probe" || (*want != "reachable" && *want != "unreachable") {
		os.Exit(2)
	}
	connection, err := (&net.Dialer{Timeout: time.Second}).Dial("tcp", *address)
	reachable := err == nil
	if connection != nil {
		connection.Close()
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"address": *address, "reachable": reachable, "expected": *want})
	if reachable != (*want == "reachable") {
		os.Exit(1)
	}
}
