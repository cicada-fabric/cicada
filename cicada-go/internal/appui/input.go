package appui

import "github.com/cicada-ai/cicada/internal/hubaccountwire"

// ActivationCodeInputLimit is the protocol's maximum canonical local claim
// code length. Keeping the native editor at this bound prevents valid codes
// from being silently truncated before appcore performs its strict parse.
func ActivationCodeInputLimit() int { return max(hubaccountwire.MaxAppClaimCodeBytes, 32*1024) }
