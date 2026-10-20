package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cicada-ai/cicada/internal/harness"
)

const maxCodexHookInput = 2 << 20

type codexHookInput struct {
	SessionID      string         `json:"session_id"`
	CWD            string         `json:"cwd"`
	TranscriptPath string         `json:"transcript_path"`
	Event          string         `json:"hook_event_name"`
	TurnID         string         `json:"turn_id"`
	ToolName       string         `json:"tool_name"`
	ToolUseID      string         `json:"tool_use_id"`
	ToolInput      map[string]any `json:"tool_input"`
	Prompt         string         `json:"prompt"`
}

type codexOperatorCommand struct{ operation, name, label, slot string }

func decodeCodexHook(input io.Reader) (codexHookInput, error) {
	raw, err := io.ReadAll(io.LimitReader(input, maxCodexHookInput+1))
	if err != nil || len(raw) > maxCodexHookInput {
		return codexHookInput{}, errors.New("CODEX_HOOK_INPUT_INVALID")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var event codexHookInput
	if decoder.Decode(&event) != nil {
		return event, errors.New("CODEX_HOOK_INPUT_INVALID")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return event, errors.New("CODEX_HOOK_INPUT_INVALID")
	}
	return event, nil
}

func codexCicadaToolName(full string) (string, bool) {
	for _, prefix := range []string{"mcp__cicada__", "mcp__plugin_cicada_cicada__"} {
		if strings.HasPrefix(full, prefix) {
			name := strings.TrimPrefix(full, prefix)
			return name, isCicadaMCPTool(name)
		}
	}
	return "", false
}

func codexHookOutput(output io.Writer, value any) error { return json.NewEncoder(output).Encode(value) }

func codexHookBlock(output io.Writer, reason string) error {
	return codexHookOutput(output, map[string]any{"decision": "block", "reason": reason, "systemMessage": reason})
}

func codexHookDeny(output io.Writer) error {
	return codexHookOutput(output, map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "deny",
		"permissionDecisionReason": "Cicada 无法验证此次原生会话调用，未使用先前 Thread 的身份。 / Cicada could not verify this invocation; no previous Thread identity was used."}})
}

// The CLI dispatch supplies stdin/stdout; no caller SID is read from argv/env.
func runCodexHook(args []string, input io.Reader, output io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: cicada codex-hook")
	}
	event, err := decodeCodexHook(input)
	if err != nil {
		return err
	}
	switch event.Event {
	case "PreToolUse":
		return codexPreToolUse(event, output)
	case "UserPromptSubmit":
		return codexUserPrompt(event, output)
	default:
		return codexHookOutput(output, map[string]any{})
	}
}

func codexHookCoordinates(event codexHookInput) (harness.SessionContext, string, error) {
	if !localContextText(event.SessionID, 128) || !filepath.IsAbs(event.CWD) || filepath.Clean(event.CWD) != event.CWD {
		return harness.SessionContext{}, "", errCodexMCPContext
	}
	nodeID, err := configuredCodexNodeID()
	if err != nil {
		return harness.SessionContext{}, "", err
	}
	origin, err := normalizeMCPAPIOrigin(envOr("CICADA_API_URL", "http://127.0.0.1:8787"))
	if err != nil {
		return harness.SessionContext{}, "", err
	}
	return harness.SessionContext{Harness: "codex", NativeSessionID: event.SessionID, MachineID: nodeID, Workspace: event.CWD}, origin, nil
}

func codexPreToolUse(event codexHookInput, output io.Writer) error {
	name, matched := codexCicadaToolName(event.ToolName)
	if !matched {
		return codexHookOutput(output, map[string]any{})
	}
	coordinates, origin, err := codexHookCoordinates(event)
	if err != nil || event.ToolInput == nil {
		return codexHookDeny(output)
	}
	contextInput, ok := event.ToolInput[codexMCPContextArgument].(map[string]any)
	if !ok {
		return codexHookDeny(output)
	}
	nonce, ok := contextInput["connection_nonce"].(string)
	if !ok || !localContextHex(nonce, 64) {
		return codexHookDeny(output)
	}
	business, err := codexBusinessArguments(event.ToolInput)
	if err != nil || validateMCPArguments(name, business) != nil {
		return codexHookDeny(output)
	}
	digest, err := codexArgumentsDigest(business)
	if err != nil {
		return codexHookDeny(output)
	}
	issued, err := requestMachineAgentCodexContextIssue(defaultMCPJoinSocketPath(coordinates), localCodexContextIssue{
		Version: localJoinProtocolVersion, Operation: "codex_context_issue", APIOrigin: origin, Harness: "codex", NativeSessionID: coordinates.NativeSessionID,
		Workspace: coordinates.Workspace, TranscriptPath: event.TranscriptPath, ConnectionNonce: nonce, ToolName: name, ArgumentsDigest: digest, TurnID: event.TurnID, ToolUseID: event.ToolUseID})
	if err != nil || issued == nil || issued.Ticket == "" {
		return codexHookDeny(output)
	}
	// Replace the entire context, including a provider-supplied parent ticket.
	business[codexMCPContextArgument] = map[string]any{"connection_nonce": nonce, "ticket": issued.Ticket}
	return codexHookOutput(output, map[string]any{"hookSpecificOutput": map[string]any{"hookEventName": "PreToolUse", "permissionDecision": "allow", "updatedInput": business}})
}

func unquoteCodexCommandName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
		value = value[1 : len(value)-1]
	} else if strings.HasPrefix(value, "\"") {
		v, err := strconv.Unquote(value)
		if err != nil {
			return "", err
		}
		value = v
	}
	if !localContextText(value, 256) {
		return "", errors.New("invalid Cicada name")
	}
	return value, nil
}

func parseCodexOperatorPrompt(prompt string) (codexOperatorCommand, bool, error) {
	prompt = strings.TrimSpace(prompt)
	fields := strings.Fields(prompt)
	if len(fields) == 0 || fields[0] != "cicada" {
		return codexOperatorCommand{}, false, nil
	}
	if strings.ContainsAny(prompt, "\r\n") {
		return codexOperatorCommand{}, true, errors.New("invalid multiline Cicada command")
	}
	rest := strings.TrimSpace(strings.TrimPrefix(prompt, "cicada"))
	fields = strings.Fields(rest)
	if len(fields) == 0 {
		return codexOperatorCommand{operation: "help"}, true, nil
	}
	verb := fields[0]
	tail := strings.TrimSpace(strings.TrimPrefix(rest, verb))
	command := codexOperatorCommand{}
	switch verb {
	case "help":
		command.operation = "help"
		if tail != "" {
			return command, true, errors.New("invalid Cicada command")
		}
	case "join":
		command.operation = "endpoint_register"
		if tail != "" {
			var err error
			command.name, err = unquoteCodexCommandName(tail)
			if err != nil {
				return command, true, err
			}
		}
	case "leave":
		command.operation = "endpoint_leave"
		if tail != "" {
			return command, true, errors.New("invalid Cicada command")
		}
	case "peers":
		command.operation = "endpoint_directory"
		if tail != "" {
			return command, true, errors.New("invalid Cicada command")
		}
	case "connect":
		if tail == "" {
			command.operation = "native_pair_available"
			break
		}
		parts := strings.Fields(tail)
		if len(parts) < 2 {
			return command, true, errors.New("choose a Pair label and A/B slot")
		}
		command.slot = strings.ToUpper(parts[len(parts)-1])
		if command.slot != "A" && command.slot != "B" {
			return command, true, errors.New("choose an explicit A/B slot")
		}
		var err error
		command.label, err = unquoteCodexCommandName(strings.TrimSpace(strings.TrimSuffix(tail, parts[len(parts)-1])))
		if err != nil {
			return command, true, err
		}
		command.operation = "native_pair_join_named"
	default:
		return command, true, errors.New("unknown Cicada command")
	}
	return command, true, nil
}

const codexOperatorHelp = "Cicada：cicada join 名称 · cicada peers · cicada connect · cicada connect 配对名称 A|B · cicada leave。登记不授予通信权限。\nCicada: join NAME · peers · connect · connect PAIR_LABEL A|B · leave. Registration grants no communication permission."

func codexUserPrompt(event codexHookInput, output io.Writer) error {
	command, matched, err := parseCodexOperatorPrompt(event.Prompt)
	if !matched {
		return codexHookOutput(output, map[string]any{})
	}
	if err != nil || command.operation == "help" {
		return codexHookBlock(output, codexOperatorHelp)
	}
	coordinates, origin, err := codexHookCoordinates(event)
	if err != nil || verifyCodexContextTranscript(event.TranscriptPath, event.SessionID, event.CWD) != nil {
		return codexHookBlock(output, "Cicada 无法验证当前原生记录；未登记、未接入，也未借用其他 Thread。 / Cicada could not verify the current native record; no registration, connection or borrowed identity was used.")
	}
	base, err := mcpSessionStatePath()
	if err != nil || strings.TrimSpace(base) == "" {
		return codexHookBlock(output, "Cicada 原配置位置需要恢复，未创建替代状态。 / The original Cicada state location needs recovery; no replacement was created.")
	}
	base, err = filepath.Abs(base)
	if err != nil {
		return codexHookBlock(output, "Cicada 本地状态位置不可用。 / Cicada local state is unavailable.")
	}
	scope, trusted, err := mcpSessionScope(origin, coordinates)
	if err != nil {
		return codexHookBlock(output, "Cicada 无法验证当前范围。 / Cicada could not verify the current scope.")
	}
	client, err := openCodexOperatorIntent(filepath.Join(filepath.Dir(base), "scopes", scope, "operator-intent.json"))
	if err != nil {
		return codexHookBlock(output, "Cicada 原命令状态不可用；请重试上一条命令。 / Original Cicada command state is unavailable; retry the previous command.")
	}
	q := localEndpointRequest{Version: localJoinProtocolVersion, Operation: command.operation, APIOrigin: origin}
	if command.operation == "endpoint_directory" {
		q.Limit = 64
	} else {
		q.Harness, q.NativeSessionID, q.Workspace = trusted.Harness, trusted.NativeSessionID, trusted.Workspace
	}
	if command.operation == "endpoint_register" {
		q.Name = command.name
		if q.Name == "" {
			q.Name = filepath.Base(event.CWD) + " · Thread"
		}
	}
	q.PairLabel, q.Slot = command.label, command.slot
	result, callErr := client.call(defaultMCPJoinSocketPath(coordinates), q, trusted.NodeID)
	if result == nil || result.State != "COMPLETED" {
		reason := "Cicada 此次命令结果尚未确认；请精确重试，不会以替代身份绕过原命令。 / This Cicada result is unconfirmed; retry the same command without substituting an identity."
		if result != nil && result.State == "REFUSED" {
			reason = "Cicada 已确认此次命令被拒绝，未将其显示为接入或授权成功。 / This Cicada command was refused; no connection or authorization success is claimed."
		}
		if err := codexHookBlock(output, reason); err != nil {
			return err
		}
		if result != nil && result.State == "REFUSED" {
			_ = client.ack(result.RequestID, result.IntentDigest)
		}
		return nil
	}
	if callErr != nil {
		return codexHookBlock(output, "Cicada 原命令结果需要恢复；未确认成功。 / The original Cicada result needs recovery; success is unconfirmed.")
	}
	if result.Join != nil {
		joined := result.Join
		store := newMCPSessionStateStore(base)
		if err := store.save(mcpCachedSession{Scope: scope, APIOrigin: origin, Harness: trusted.Harness, NativeSessionID: trusted.NativeSessionID, NodeID: trusted.NodeID,
			Workspace: trusted.Workspace, GroupID: joined.Endpoint.GroupID, EndpointID: joined.Endpoint.ID, OwnerID: joined.Endpoint.Owner,
			BindingID: joined.BindingID, BindingEpoch: joined.BindingEpoch, LeaseExpiresAt: joined.LeaseExpiresAt, SessionToken: joined.SessionToken}); err != nil {
			return codexHookBlock(output, "Cicada 接入结果尚未安全保存，原命令已保留。请精确重试。 / Cicada connection state is not safely saved; the original command is retained for retry.")
		}
	}
	if err := codexHookBlock(output, formatCodexOperatorResult(command, result)); err != nil {
		return err
	}
	// A failed ack retains the durable result for an idempotent retry. Never
	// turn a successfully written block response into a hook pass-through.
	_ = client.ack(result.RequestID, result.IntentDigest)
	return nil
}

func formatCodexOperatorResult(command codexOperatorCommand, result *localEndpointResult) string {
	var b strings.Builder
	switch {
	case result.Registration != nil:
		if command.operation == "endpoint_leave" {
			b.WriteString("当前 Thread 已离开 Cicada，原生记录和工作区保留。 / This Thread left Cicada; its native record and workspace are retained.\n")
		} else if result.Registration.Presence == "left" {
			b.WriteString("此 Thread 仍为已退出；重复登记未恢复或延长权限。 / This Thread remains left; repeat registration did not restore or renew permission.\n")
		} else {
			b.WriteString("当前 Thread 登记已确认；登记本身不新增或延长通信权限。 / This Thread is registered; registration does not add or renew communication permission.\n")
		}
		b.WriteString(result.Registration.Name + "\n" + result.Registration.Workspace)
	case result.Directory != nil:
		b.WriteString("此 Node 的 Thread 目录快照（不代表当前通信授权） / Node Thread directory snapshot (not communication authorization)\n")
		for _, card := range result.Directory.Endpoints {
			b.WriteString(card.Name + " · " + codexPresenceLabel(card.Presence) + "\n  " + card.Workspace + "\n")
		}
		if len(result.Directory.Endpoints) == 0 {
			b.WriteString("暂无条目。 / No entries.\n")
		}
		if result.Directory.NextCursor != "" {
			b.WriteString("还有后续页，可在 Cicada App 继续读取。 / More pages are available in the Cicada App.")
		}
	case result.Pairs != nil:
		b.WriteString("请选择配对名称及 A/B 槽位 / Choose a Pair label and A/B slot:\n")
		for _, pair := range result.Pairs.Pairs {
			b.WriteString(pair.Label + " · ")
			for i, slot := range pair.Slots {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(slot.Slot)
			}
			b.WriteByte('\n')
		}
		if len(result.Pairs.Pairs) == 0 {
			b.WriteString("暂无可用配对，请在 Cicada App 核对。 / No available Pair; review in the Cicada App.\n")
		}
		if result.Pairs.Truncated {
			b.WriteString("列表未完整展示；不得按首项或最新项猜选。 / The list is incomplete; do not guess the first or newest entry.")
		}
	case result.Join != nil:
		b.WriteString("所选配对的接入结果已保存；通信仍以 App 中两侧 Owner 确认及当前 Hub Guard 为准。 / The selected Pair connection is saved; communication still requires both Owner confirmations and current Hub Guard.\n")
		b.WriteString(result.Join.Endpoint.Name + "\n" + result.Join.Endpoint.Workspace)
	default:
		b.WriteString("Cicada 未确认此结果。 / Cicada has not confirmed this result.")
	}
	return b.String()
}

func codexPresenceLabel(presence string) string {
	switch presence {
	case "left":
		return "已退出 / Left"
	case "offline":
		return "快照时离线 / Offline at snapshot"
	case "LEASE_RECENT":
		return "快照时租约近期有效 / Lease recent at snapshot"
	default:
		return "在线状态未知 / Presence unknown"
	}
}
