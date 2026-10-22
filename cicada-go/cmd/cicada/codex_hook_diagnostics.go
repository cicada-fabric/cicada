package main

import (
	"errors"
	"io"
)

// These are consumer stages, not Hub authorization decisions. Messages contain
// no native IDs, argument values, paths, nonces, tickets or server payloads.
type codexHookFailure string

const (
	codexHookCoordinatesInvalid codexHookFailure = "CODEX_NATIVE_COORDINATES_INVALID"
	codexHookRecordUnverified   codexHookFailure = "CODEX_NATIVE_RECORD_UNVERIFIED"
	codexHookToolInputMissing   codexHookFailure = "CODEX_TOOL_INPUT_MISSING"
	codexHookContextMissing     codexHookFailure = "CODEX_CALL_CONTEXT_MISSING"
	codexHookNonceInvalid       codexHookFailure = "CODEX_CONNECTION_NONCE_INVALID"
	codexHookArgumentsInvalid   codexHookFailure = "CODEX_TOOL_ARGUMENTS_INVALID"
	codexHookDigestInvalid      codexHookFailure = "CODEX_ARGUMENT_DIGEST_UNAVAILABLE"
	codexHookTicketUnavailable  codexHookFailure = "CODEX_NODE_TICKET_UNAVAILABLE"
)

func codexHookFailureText(stage codexHookFailure) string {
	var message string
	switch stage {
	case codexHookCoordinatesInvalid:
		message = "当前会话无法核对；请在 /hooks 启用并审阅 Cicada 后重试。 / Cicada could not verify this Thread; enable and review Cicada in /hooks, then retry."
	case codexHookRecordUnverified:
		message = "当前原生记录未通过检查；请保留此会话并将错误码交给支持人员。 / The current native record failed verification; keep this Thread and share the error code with support."
	case codexHookToolInputMissing:
		message = "此次调用信息不完整；请在原会话重试。 / This call is incomplete; retry in the original Thread."
	case codexHookContextMissing:
		message = "当前插件的调用信息缺失；请确认使用当前 Cicada 插件后重试。 / Plugin call information is missing; confirm the current Cicada plugin is selected, then retry."
	case codexHookNonceInvalid:
		message = "插件连接信息不完整；请在原会话重试。 / Plugin connection information is incomplete; retry in the original Thread."
	case codexHookArgumentsInvalid:
		message = "此次调用参数不符合要求；请在原会话重新提出请求。 / This call has invalid arguments; make the request again in the original Thread."
	case codexHookDigestInvalid:
		message = "此次请求过大或无法读取；请缩短请求后重试。 / This request is too large or unreadable; shorten it and retry."
	case codexHookTicketUnavailable:
		message = "Node 未确认此次调用；请在 App 检查该 Node 状态后重试。 / The Node did not confirm this call; check its status in the App, then retry."
	default:
		return codexHookFailureText(codexHookTicketUnavailable)
	}
	return string(stage) + ": " + message
}

func codexHookDenyFor(output io.Writer, stage codexHookFailure) error {
	return codexHookOutput(output, map[string]any{"hookSpecificOutput": map[string]any{
		"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": codexHookFailureText(stage),
	}})
}

func codexHookRecordFailure(err error) string {
	var diagnostic *LocalCodexContextError
	if !errors.As(err, &diagnostic) || diagnostic == nil {
		return codexHookFailureText(codexHookRecordUnverified)
	}
	var message string
	switch diagnostic.Stage {
	case "ROOT":
		message = "原 Codex 记录位置不可用；请恢复原配置后重试。 / The original Codex record location is unavailable; restore the original configuration and retry."
	case "PATH":
		message = "记录位置不符合当前配置；请恢复原 Codex 配置后重试。 / The record location does not match the current configuration; restore the original Codex configuration and retry."
	case "OWNERSHIP":
		message = "记录不属于当前系统用户；请联系本机维护者核对。 / The record belongs to another OS user; ask this machine's administrator to review it."
	case "PERMISSION":
		message = "原生记录写权限不符合要求；请联系本机维护者处理后重试。 / Native record write permissions do not meet the requirements; ask this machine's administrator to address them, then retry."
	case "INODE":
		message = "记录在核对期间发生变化；请在原会话重试。 / The record changed during verification; retry in the original Thread."
	case "METADATA":
		message = "原生记录内容无法核对；请保留会话并联系支持。 / The native record could not be verified; keep this Thread and contact support."
	case "SOURCE":
		message = "当前原生会话来源尚不支持；请保留会话并联系支持。 / This native session source is unsupported; keep this Thread and contact support."
	case "SESSION":
		message = "记录与当前会话不匹配；请保留原会话并联系支持。 / The record does not match this Thread; keep the original Thread and contact support."
	case "WORKSPACE":
		message = "记录与当前工作区不匹配；请恢复原工作区后重试。 / The record does not match this workspace; restore the original workspace and retry."
	default:
		return codexHookFailureText(codexHookRecordUnverified)
	}
	return "CODEX_NATIVE_RECORD_" + diagnostic.Stage + ": " + message
}
