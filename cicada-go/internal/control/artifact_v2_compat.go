package control

import "github.com/cicada-ai/cicada/internal/store"

func (c *Control) HasScopedArtifactRefs() (bool, error) {
	return c.store.HasScopedArtifactRefs()
}

func (c *Control) ListArtifactsIfNoScopedRefs(goalID string) ([]store.Artifact, error) {
	return c.store.ListArtifactsIfNoScopedRefs(goalID)
}

func (c *Control) CreateArtifactIfNoScopedRefs(artifact store.Artifact) (*store.Artifact, error) {
	return c.store.CreateArtifactIfNoScopedRefs(artifact)
}
