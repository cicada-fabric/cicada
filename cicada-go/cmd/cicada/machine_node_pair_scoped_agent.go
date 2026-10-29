package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	wire "github.com/cicada-ai/cicada/internal/hubaccountwire"
	"github.com/cicada-ai/cicada/internal/hubtransport"
	"github.com/mattn/go-isatty"
)

func machineNodePairScopedDisplayCode(s *machineNodePairScopedState, output io.Writer) error {
	out, ok := output.(*os.File)
	if !ok || out == nil || !isatty.IsTerminal(out.Fd()) || !isatty.IsTerminal(os.Stdin.Fd()) {
		return errors.New("pairing code requires an interactive input and output TTY")
	}
	if s.Context == nil || s.OOB == "" || wire.ValidateNodePairTrustScopedContext(*s.Context, time.Now().UTC()) != nil {
		return errMachineNodePairPending
	}
	code, e := wire.EncodeNodePairTrustScopedCode(*s.Context, s.Selector, s.Secret)
	if e != nil {
		return errMachineNodePairState
	}
	_, e = fmt.Fprintln(out, code)
	return e
}
func runMachineNodePairScopedTrust(ctx context.Context, stateDir, nodeID, name, address, expectedOrigin string, explicitOrigin, once, retry bool, output io.Writer, completed *bool, descriptorText string) error {
	client, s, e := beginMachineNodePairScoped(ctx, stateDir, nodeID, name, address, expectedOrigin, explicitOrigin, descriptorText)
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
		s, e = retryMachineNodePairScoped(ctx, stateDir, name, client, old, d, httpClient)
		clear(old.Secret)
		if e != nil {
			return e
		}
		defer clear(s.Secret)
	}
	displayed := false
	alreadyACKed := s.Stage == wire.NodePairTrustScopedACKed
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.Stage == wire.NodePairTrustScopedACKed {
			if e := installMachineNodePairScopedBinding(stateDir, client, s, d); e != nil {
				return e
			}
			if completed != nil && !alreadyACKed {
				*completed = true
			}
			return nil
		}
		switch s.Stage {
		case wire.NodePairTrustScopedExpired, wire.NodePairTrustScopedCancelled, wire.NodePairTrustScopedRevoked, wire.NodePairTrustScopedFenced, "UNKNOWN":
			return fmt.Errorf("Node pairing is %s; original identity and pending evidence retained", s.Stage)
		}
		if s.PendingOperation == "" {
			if e := machineNodePairScopedAvailable(ctx, httpClient, d.Claims.Origin); e != nil {
				return e
			}
			now := time.Now().UTC()
			switch s.Stage {
			case "NEW":
				body, e := machineNodePairScopedTypedBody(s.StartOperation, s.StartBody)
				if e != nil {
					return e
				}
				switch b := body.(type) {
				case wire.NodePairTrustScopedStart:
					b.IssuedAt = now.Format(time.RFC3339Nano)
					body = b
				case wire.NodePairTrustScopedExistingStart:
					b.IssuedAt = now.Format(time.RFC3339Nano)
					body = b
				default:
					return errMachineNodePairState
				}
				if e = newMachineNodePairScopedRequest(stateDir, client.identity, s, d.Claims.Hub, s.StartOperation, body); e != nil {
					return e
				}
			case "COMMIT":
				if s.Context == nil {
					return errMachineNodePairState
				}
				body := wire.NodePairTrustScopedCommit{Format: wire.NodePairTrustScopedFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: now.Format(time.RFC3339Nano)}
				if e = newMachineNodePairScopedRequest(stateDir, client.identity, s, d.Claims.Hub, wire.OperationNodePairTrustScopedCommit, body); e != nil {
					return e
				}
			case wire.NodePairTrustScopedPending:
				if !displayed {
					if machineNodePairScopedDisplayCode(s, output) != nil && output != nil {
						fmt.Fprintln(output, "Node pairing is pending; use machine pairing-code from a local interactive terminal.")
					}
					displayed = true
				}
				if s.Context == nil {
					return errMachineNodePairState
				}
				body := wire.NodePairTrustScopedPoll{Format: wire.NodePairTrustScopedFormat, Context: *s.Context, OOBCommitment: s.OOB, IssuedAt: now.Format(time.RFC3339Nano)}
				if e = newMachineNodePairScopedRequest(stateDir, client.identity, s, d.Claims.Hub, wire.OperationNodePairTrustScopedPoll, body); e != nil {
					return e
				}
			case "PINNED":
				if s.ACKBody != nil && len(s.ACKPacket) > 0 && !machineNodePairScopedACKWasFenced(s, s.ACKPacket) {
					s.PendingOperation = wire.OperationNodePairTrustScopedACK
					s.PendingPacket = append([]byte(nil), s.ACKPacket...)
					s.PendingBody, e = json.Marshal(*s.ACKBody)
					if e != nil {
						return e
					}
					if e = saveMachineNodePairScopedState(stateDir, client.identity, s); e != nil {
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
						s.Stage = wire.NodePairTrustScopedPending
						if e = saveMachineNodePairScopedState(stateDir, client.identity, s); e != nil {
							return e
						}
						continue
					}
					body, e := machineNodePairScopedACKBody(stateDir, client, s, now)
					if e != nil {
						return e
					}
					if e = newMachineNodePairScopedRequest(stateDir, client.identity, s, d.Claims.Hub, wire.OperationNodePairTrustScopedACK, body); e != nil {
						clear(body.ACKNonce)
						return e
					}
					clear(body.ACKNonce)
				}
			default:
				return errMachineNodePairState
			}
		}
		if s.PendingOperation == wire.OperationNodePairTrustScopedACK {
			body, e := machineNodePairScopedTypedBody(s.PendingOperation, s.PendingBody)
			if e != nil {
				return e
			}
			ack := body.(wire.NodePairTrustScopedACK)
			if len(s.ACKPacket) > 0 && !bytes.Equal(s.ACKPacket, s.PendingPacket) && !machineNodePairScopedACKWasFenced(s, s.ACKPacket) {
				return errMachineNodePairState
			}
			s.ACKPacket = append([]byte(nil), s.PendingPacket...)
			s.ACKBody = &ack
			if e = saveMachineNodePairScopedState(stateDir, client.identity, s); e != nil {
				return e
			}
		}
		r, receipt, e := sendMachineNodePairScopedPending(ctx, stateDir, client.identity, s, d, httpClient)
		if e != nil {
			if !errors.Is(e, errMachineNodePairPending) || once {
				return e
			}
			if waitMachineNodeBindingPoll(ctx) != nil {
				return ctx.Err()
			}
			continue
		}
		if e = applyMachineNodePairScopedResult(stateDir, client, s, d, r, receipt); e != nil {
			return e
		}
		if s.Stage == wire.NodePairTrustScopedPending && s.PendingOperation == "" {
			if once {
				return errMachineNodePairPending
			}
			if waitMachineNodeBindingPoll(ctx) != nil {
				return ctx.Err()
			}
		}
	}
}
