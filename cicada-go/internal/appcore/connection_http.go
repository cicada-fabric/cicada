package appcore

// httpClient is shared by every App protocol, including Node, Pair and local
// collaboration. A direct connection owns its dedicated verified transport;
// a missing direct client never falls back to the legacy/system-root client.
func (c *nativeController) httpClient() HTTPDoer {
	if c.directConnection {
		return c.connectionHTTP
	}
	return c.cfg.HTTP
}

func (c *nativeController) closeConnectionHTTP() {
	if client, ok := c.httpClient().(interface{ CloseIdleConnections() }); ok {
		client.CloseIdleConnections()
	}
	c.connectionHTTP = nil
}
