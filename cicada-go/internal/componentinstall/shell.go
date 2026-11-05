package componentinstall

type shellIntegrationResult struct {
	State      string `json:"state"`
	Entry      string `json:"entry,omitempty"`
	Bashrc     string `json:"bashrc,omitempty"`
	Activation string `json:"activation,omitempty"`
}

type shellIntegrationChange interface {
	apply(remaining bool) error
	close()
	status() shellIntegrationResult
}

func shellPathUpdate(bin string) string {
	quoted := codexShellQuote(bin)
	return "case \":${PATH-}:\" in\n  *:" + quoted + ":*) ;;\n  *) if [ -n \"${PATH-}\" ]; then export PATH=\"$PATH\":" + quoted + "; else export PATH=" + quoted + "; fi ;;\nesac\n"
}
