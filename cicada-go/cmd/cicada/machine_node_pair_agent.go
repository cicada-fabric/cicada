package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cicada-ai/cicada/internal/e2ee"
	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/cicada-ai/cicada/internal/nodelock"
	"github.com/mattn/go-isatty"
)

func machineNodePairDisplayCode(s *machineNodePairState, output io.Writer) error {
	out, ok := output.(*os.File)
	if !ok || out == nil || !isatty.IsTerminal(out.Fd()) || !isatty.IsTerminal(os.Stdin.Fd()) {
		return errors.New("pairing code requires an interactive input and output TTY")
	}
	if s.Context == nil || s.OOB == "" || wire.ValidateNodePairTrustContext(*s.Context, time.Now().UTC()) != nil {
		return errMachineNodePairPending
	}
	code, e := wire.EncodeNodePairTrustCode(*s.Context, s.Selector, s.Secret)
	if e != nil {
		return errMachineNodePairState
	}
	_, e = fmt.Fprintln(out, code)
	return e
}
func machineNodePairingCodeCommand(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("machine pairing-code", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	id := flags.String("id", "", "original Node ID")
	stateDir := flags.String("state-dir", "", "original private Node state directory")
	if flags.Parse(args) != nil || len(flags.Args()) != 0 || *id == "" || *stateDir == "" {
		return errors.New("usage: cicada machine pairing-code --id NODE_ID --state-dir DIR")
	}
	out, ok := output.(*os.File)
	if !ok || out == nil || !isatty.IsTerminal(out.Fd()) || !isatty.IsTerminal(os.Stdin.Fd()) {
		return errors.New("pairing code requires an interactive input and output TTY")
	}
	maintenance, e := nodelock.AcquireMaintenance(*stateDir, *id)
	if e != nil {
		return e
	}
	defer maintenance.Close()
	keyPath, _ := machineNodeControlPaths(*stateDir, *id)
	raw, e := machineNodePairPrivateRead(keyPath, machineNodePairLocalMax)
	if e != nil {
		return e
	}
	identity, e := e2ee.UnmarshalIdentity(raw)
	clear(raw)
	if e != nil {
		return errMachineNodePairState
	}
	s, e := loadMachineNodePairState(*stateDir, *id, identity)
	if e != nil {
		return e
	}
	defer clear(s.Secret)
	if s.Stage != wire.NodePairTrustPending && s.Stage != "PINNED" {
		return errMachineNodePairPending
	}
	return machineNodePairDisplayCode(s, output)
}

func prepareMachineNodePairTrust(parent context.Context, stateDir, nodeID, name, address, expectedOrigin string, explicitOrigin, once, retry bool, output io.Writer, completed *bool) error {
	if machineNodePairNoSymlinkPath(machineNodeStateDir(stateDir, nodeID)) != nil {
		return errMachineNodePairState
	}
	writer, e := nodelock.AcquireWriterRoot(stateDir)
	if e != nil {
		return e
	}
	defer writer.Close()
	agent, e := nodelock.AcquireAgent(stateDir, nodeID)
	if e != nil {
		return e
	}
	defer agent.Close()
	if e = rejectMachineRecoveryMutation(stateDir, stateDir, nodeID); e != nil {
		return e
	}
	if e = rejectMachineNodePendingRecovery(stateDir, nodeID); e != nil {
		return e
	}
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	client, s, e := beginMachineNodePair(ctx, stateDir, nodeID, name, address, expectedOrigin, explicitOrigin)
	if e != nil {
		return e
	}
	defer clear(s.Secret)
	d, e := hubtransport.DecodeDescriptor(s.DescriptorText)
	if e != nil {
		return errMachineNodePairState
	}
	httpClient, e := hubtransport.NewHTTPClient(d, address, 15*time.Second)
	if e != nil {
		return e
	}
	defer httpClient.CloseIdleConnections()
	if retry {
		old := s
		s, e = retryMachineNodePair(ctx, stateDir, name, client, old, d, httpClient)
		clear(old.Secret)
		if e != nil {
			return e
		}
		defer clear(s.Secret)
	}
	displayed := false
	alreadyACKed := s.Stage == wire.NodePairTrustACKed
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.Stage == wire.NodePairTrustACKed {
			if e := installMachineNodePairBinding(stateDir, client, s, d); e != nil {
				return e
			}
			if completed != nil && !alreadyACKed {
				*completed = true
			}
			return nil
		}
		switch s.Stage {
		case wire.NodePairTrustExpired, wire.NodePairTrustCancelled, wire.NodePairTrustRevoked, wire.NodePairTrustFenced, "UNKNOWN":
			return fmt.Errorf("Node pairing is %s; original identity and pending evidence retained", s.Stage)
		}
		if s.PendingOperation == "" {
			now := time.Now().UTC()
			switch s.Stage {
			case "NEW":
				body, e := machineNodePairTypedBody(s.StartOperation, s.StartBody)
				if e != nil {
					return e
				}
				switch b := body.(type) {
				case wire.NodePairTrustStart:
					b.IssuedAt = now.Format(time.RFC3339Nano)
					body = b
				case wire.NodePairTrustExistingStart:
					b.IssuedAt = now.Format(time.RFC3339Nano)
					body = b
				default:
					return errMachineNodePairState
				}
				if e = newMachineNodePairRequest(stateDir, client.identity, s, d.Claims.Hub, s.StartOperation, body); e != nil {
					return e
				}
			case "COMMIT":
				if s.Context == nil {
					return errMachineNodePairState
				}
				body := wire.NodePairTrustCommit{Format: wire.NodePairTrustFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: now.Format(time.RFC3339Nano)}
				if e = newMachineNodePairRequest(stateDir, client.identity, s, d.Claims.Hub, wire.OperationNodePairTrustCommit, body); e != nil {
					return e
				}
			case wire.NodePairTrustPending:
				if !displayed {
					if machineNodePairDisplayCode(s, output) != nil && output != nil {
						fmt.Fprintln(output, "Node pairing is pending; use machine pairing-code from a local interactive terminal.")
					}
					displayed = true
				}
				if s.Context == nil {
					return errMachineNodePairState
				}
				body := wire.NodePairTrustPoll{Format: wire.NodePairTrustFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: now.Format(time.RFC3339Nano)}
				if e = newMachineNodePairRequest(stateDir, client.identity, s, d.Claims.Hub, wire.OperationNodePairTrustPoll, body); e != nil {
					return e
				}
			case "PINNED":
				if s.ACKBody != nil && len(s.ACKPacket) > 0 && !machineNodePairACKWasFenced(s, s.ACKPacket) {
					s.PendingOperation = wire.OperationNodePairTrustACK
					s.PendingPacket = append([]byte(nil), s.ACKPacket...)
					s.PendingBody, e = json.Marshal(*s.ACKBody)
					if e != nil {
						return e
					}
					if e = saveMachineNodePairState(stateDir, client.identity, s); e != nil {
						return e
					}
				} else {
					if s.PollBody == nil || s.Approval == nil {
						return errMachineNodePairState
					}
					pollAt, e := time.Parse(time.RFC3339Nano, s.PollBody.IssuedAt)
					end, ee := time.Parse(time.RFC3339Nano, s.Approval.AcceptBefore)
					if e != nil || ee != nil {
						return errMachineNodePairState
					}
					if now.After(pollAt.Add(50*time.Second)) || !now.Before(end) {
						s.Stage = wire.NodePairTrustPending
						if e = saveMachineNodePairState(stateDir, client.identity, s); e != nil {
							return e
						}
						continue
					}
					body, e := machineNodePairACKBody(stateDir, client, s, now)
					if e != nil {
						return e
					}
					if e = newMachineNodePairRequest(stateDir, client.identity, s, d.Claims.Hub, wire.OperationNodePairTrustACK, body); e != nil {
						clear(body.ACKNonce)
						return e
					}
					clear(body.ACKNonce)
				}
			default:
				return errMachineNodePairState
			}
		}
		if s.PendingOperation == wire.OperationNodePairTrustACK {
			body, e := machineNodePairTypedBody(s.PendingOperation, s.PendingBody)
			if e != nil {
				return e
			}
			ack := body.(wire.NodePairTrustACK)
			if len(s.ACKPacket) > 0 && !bytes.Equal(s.ACKPacket, s.PendingPacket) && !machineNodePairACKWasFenced(s, s.ACKPacket) {
				return errMachineNodePairState
			}
			s.ACKPacket = append([]byte(nil), s.PendingPacket...)
			s.ACKBody = &ack
			if e = saveMachineNodePairState(stateDir, client.identity, s); e != nil {
				return e
			}
		}
		r, receipt, e := sendMachineNodePairPending(ctx, stateDir, client.identity, s, d, httpClient)
		if e != nil {
			if !errors.Is(e, errMachineNodePairPending) || once {
				return e
			}
			if waitMachineNodeBindingPoll(ctx) != nil {
				return ctx.Err()
			}
			continue
		}
		if e = applyMachineNodePairResult(stateDir, client, s, d, r, receipt); e != nil {
			return e
		}
		if s.Stage == wire.NodePairTrustPending && s.PendingOperation == "" {
			if once {
				return errMachineNodePairPending
			}
			if waitMachineNodeBindingPoll(ctx) != nil {
				return ctx.Err()
			}
		}
	}
}
