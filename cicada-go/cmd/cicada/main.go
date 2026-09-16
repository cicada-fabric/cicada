package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/cicada-ai/cicada/internal/buildinfo"
	"github.com/cicada-ai/cicada/internal/control"
	"github.com/cicada-ai/cicada/internal/server"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "version", "--version", "-V":
		fmt.Println("cicada " + buildinfo.Version)
	case "push-vapid-keys":
		if len(os.Args) != 2 {
			fmt.Fprintln(os.Stderr, "usage: cicada push-vapid-keys")
			os.Exit(2)
		}
		privateKey, publicKey, err := webpush.GenerateVAPIDKeys()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("CICADA_PUSH_VAPID_PUBLIC_KEY=%s\nCICADA_PUSH_VAPID_PRIVATE_KEY=%s\n", publicKey, privateKey)
	case "goal", "machine", "worker", "thread", "snapshot":
		if err := clientCommand(os.Args[1:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "external":
		if len(os.Args) < 3 || os.Args[2] != "agent" {
			fmt.Fprintln(os.Stderr, "usage: cicada external agent [options]")
			os.Exit(2)
		}
		if err := runExternalAgent(os.Args[3:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "connector":
		if len(os.Args) < 3 || os.Args[2] != "telegram" {
			fmt.Fprintln(os.Stderr, "usage: cicada connector telegram [options]")
			os.Exit(2)
		}
		if err := runTelegramConnector(os.Args[3:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func serve(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	host := flags.String("host", envOr("CICADA_API_HOST", "127.0.0.1"), "listen host")
	port := flags.Int("port", envInt("CICADA_API_PORT", 8787), "listen port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	config := control.DefaultConfig()
	controlPlane, err := control.New(config)
	if err != nil {
		return err
	}
	if err := controlPlane.Start(); err != nil {
		return err
	}
	httpServer := &http.Server{Addr: fmt.Sprintf("%s:%d", *host, *port), Handler: server.NewHandler(controlPlane)}
	shutdownContext, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	go func() {
		<-shutdownContext.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
		_ = controlPlane.Shutdown(shutdown)
	}()
	fmt.Printf("Cicada Control listening on %s\n", httpServer.Addr)
	err = httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func clientCommand(args []string) error {
	baseURL := envOr("CICADA_API_URL", "http://127.0.0.1:8787")
	if len(args) == 0 {
		return errors.New("missing command")
	}
	var method, path string
	var body any
	switch args[0] {
	case "snapshot":
		if len(args) >= 2 && args[1] == "replicate" {
			return runSnapshotReplication(args[2:])
		}
		return errors.New("usage: cicada snapshot replicate [options]")
	case "machine":
		if len(args) >= 2 && args[1] == "agent" {
			return runMachineAgent(args[2:])
		}
		if len(args) >= 2 && args[1] == "pair" {
			return runMachinePair(args[2:])
		}
		if len(args) == 2 && args[1] == "discover" {
			return printJSON(control.DiscoverMachineCapabilities())
		}
		if len(args) != 2 || args[1] != "list" {
			return errors.New("usage: cicada machine list|discover|pair|agent [options]")
		}
		method, path = http.MethodGet, "/v1/machines"
	case "worker":
		if len(args) != 2 || args[1] != "list" {
			return errors.New("usage: cicada worker list")
		}
		method, path = http.MethodGet, "/v1/workers"
	case "thread":
		if len(args) < 2 {
			return errors.New("usage: cicada thread sessions|register|queue|deliveries|send")
		}
		switch args[1] {
		case "sessions":
			if len(args) != 2 {
				return errors.New("usage: cicada thread sessions")
			}
			method, path = http.MethodGet, "/v1/threads/sessions"
		case "register":
			if len(args) < 3 || len(args) > 5 {
				return errors.New("usage: cicada thread register THREAD_ID [LABEL] [WORKSPACE]")
			}
			registerBody := map[string]string{"thread_id": args[2]}
			if len(args) >= 4 {
				registerBody["label"] = args[3]
			}
			if len(args) == 5 {
				registerBody["workspace"] = args[4]
			}
			body = registerBody
			method, path = http.MethodPost, "/v1/threads/sessions"
		case "queue":
			if len(args) < 5 {
				return errors.New("usage: cicada thread queue FROM_THREAD_ID TO_THREAD_ID MESSAGE")
			}
			body = map[string]string{
				"from_thread_id": args[2],
				"to_thread_id":   args[3],
				"message":        strings.Join(args[4:], " "),
			}
			method, path = http.MethodPost, "/v1/threads/queue"
		case "deliveries":
			if len(args) != 2 {
				return errors.New("usage: cicada thread deliveries")
			}
			method, path = http.MethodGet, "/v1/threads/deliveries"
		case "send":
			if len(args) < 5 {
				return errors.New("usage: cicada thread send FROM_WORKER_ID TO_WORKER_ID MESSAGE")
			}
			body = map[string]string{
				"from_worker_id": args[2],
				"to_worker_id":   args[3],
				"message":        strings.Join(args[4:], " "),
			}
			method, path = http.MethodPost, "/v1/threads/messages"
		default:
			return errors.New("usage: cicada thread sessions|register|queue|deliveries|send")
		}
	case "goal":
		if len(args) < 2 {
			return errors.New("usage: cicada goal list|show|create|send|stop")
		}
		switch args[1] {
		case "list":
			if len(args) != 2 {
				return errors.New("usage: cicada goal list")
			}
			method, path = http.MethodGet, "/v1/goals"
		case "show":
			if len(args) != 3 {
				return errors.New("usage: cicada goal show GOAL_ID")
			}
			method, path = http.MethodGet, "/v1/goals/"+args[2]
		case "create":
			if len(args) < 3 {
				return errors.New("usage: cicada goal create OBJECTIVE")
			}
			body = map[string]any{"objective": strings.Join(args[2:], " ")}
			method, path = http.MethodPost, "/v1/goals"
		case "send":
			if len(args) < 4 {
				return errors.New("usage: cicada goal send GOAL_ID CORRECTION")
			}
			body = map[string]string{"command": strings.Join(args[3:], " ")}
			method, path = http.MethodPost, "/v1/goals/"+args[2]+"/commands"
		case "stop":
			if len(args) != 3 {
				return errors.New("usage: cicada goal stop GOAL_ID")
			}
			method, path = http.MethodPost, "/v1/goals/"+args[2]+"/stop"
		default:
			return errors.New("usage: cicada goal list|show|create|send|stop")
		}
	default:
		return errors.New("unknown command")
	}
	return requestJSON(baseURL+path, method, body)
}

func requestJSON(url, method string, body any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = strings.NewReader(string(encoded))
	}
	request, err := http.NewRequest(method, url, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token := strings.TrimSpace(os.Getenv("CICADA_API_TOKEN")); token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	if response.StatusCode >= 400 {
		return fmt.Errorf("API %s: %s", response.Status, strings.TrimSpace(string(data)))
	}
	var pretty any
	if json.Unmarshal(data, &pretty) == nil {
		encoded, _ := json.MarshalIndent(pretty, "", "  ")
		fmt.Println(string(encoded))
	} else {
		fmt.Print(string(data))
	}
	return nil
}

func printJSON(value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(encoded, '\n'))
	return err
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: cicada serve|goal|machine|worker|thread|snapshot|external|connector|version")
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envInt(name string, fallback int) int {
	if value := os.Getenv(name); value != "" {
		if parsed, err := strconv.Atoi(value); err == nil {
			return parsed
		}
	}
	return fallback
}
