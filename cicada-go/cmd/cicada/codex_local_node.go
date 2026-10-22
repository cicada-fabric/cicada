package main

import (
	"context"
	"errors"
	"fmt"
)

// Formal plugin launches select an installation explicitly. Legacy callers
// without --user-root keep their existing explicit environment configuration.
// A connection's pin is immutable; a restarted daemon may change its instance.
func newLocalNodeMCPServer(selection LocalNodeSelection) (*mcpServer, error) {
	connection, err := ResolveLocalNodeConnection(context.Background(), selection, nil)
	if err != nil {
		return nil, codexLocalNodeError(err)
	}
	p := connection.Pin
	server := newMCPServerWithPaths(p.APIOrigin, "", p.MCPSessionStateFile, p.MCPOutboxStateFile)
	server.localNode = &connection
	server.outbox.connectionPin = server.localNodePin()
	server.hubStateDir, server.writerRoot = p.StateDir, p.WriterRoot
	if err := server.enableCodexContext(p.NodeID); err != nil {
		return nil, err
	}
	return server, nil
}

func revalidateCodexLocalNode(ctx context.Context, connection *LocalNodeConnection) error {
	if connection == nil {
		return nil
	}
	p := connection.Pin
	_, err := ResolveLocalNodeConnection(ctx, LocalNodeSelection{UserRoot: p.UserRoot, HubID: p.HubID, NodeID: p.NodeID}, &p)
	if err != nil {
		return codexLocalNodeError(err)
	}
	return nil
}

func (m *mcpServer) localNodePin() *LocalNodeConnectionPin {
	if m.localNode == nil {
		return nil
	}
	return &m.localNode.Pin
}

func validateCodexCachedConnection(cached *mcpCachedSession, connection *LocalNodeConnection) error {
	if cached == nil {
		return nil
	}
	if (cached.ConnectionPin == nil) != (connection == nil) {
		return codexLocalNodeError(ErrLocalNodeConfigRequired)
	}
	if connection != nil && *cached.ConnectionPin != connection.Pin {
		return codexLocalNodeError(ErrLocalNodeBindingChanged)
	}
	return nil
}

func codexLocalNodeError(err error) error {
	for _, entry := range []struct {
		kind error
		text string
	}{
		{ErrLocalNodeNotRunning, "此安装位置的 Node 尚未运行，请手动启动原 Node。 / The Node for this installation is not running; start the original Node manually."},
		{ErrLocalNodeNotReady, "Node 尚未就绪，未创建替代身份。 / The Node is not ready; no replacement identity was created."},
		{ErrLocalNodeSelectionAmbiguous, "发现多个 Node，请明确选择 Hub 和 Node。 / Multiple Nodes were found; select an exact Hub and Node."},
		{ErrLocalNodeBindingChanged, "原 Node 绑定或配置已变化；原请求保留，未切换身份。 / The original Node binding or configuration changed; the original request is retained without switching identity."},
		{ErrLocalNodeConfigRequired, "需要恢复原 Node 配置，未读取其他部署的环境配置。 / Restore the original Node configuration; no other deployment's environment configuration was used."},
		{ErrLocalNodeDiscoveryInvalid, "本地 Node 发现材料无法验证。 / Local Node discovery material could not be verified."},
		{ErrLocalNodeDiscoveryUnavailable, "本地 Node 发现暂不可用，请恢复原 Node 后重试。 / Local Node discovery is unavailable; restore the original Node and retry."},
		{ErrLocalNodeDiscoveryLimit, "本地 Node 发现超过限制，未猜选其他 Node。 / Local Node discovery exceeded its limit; no other Node was guessed."},
	} {
		if errors.Is(err, entry.kind) {
			return fmt.Errorf("%w: %s", entry.kind, entry.text)
		}
	}
	return err
}
