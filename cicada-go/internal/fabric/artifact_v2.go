package fabric

// Artifact v2 is the data-plane authorization boundary for immutable result
// references.  HTTP and MCP adapters call these methods; neither adapter gets
// a filesystem path or a second authorization implementation.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

const ArtifactV2MaxReadBytes int64 = 16 << 20

var (
	ErrArtifactV2PathTraversal = errors.New("artifact path traversal denied")
	ErrArtifactV2SymlinkEscape = errors.New("artifact symlink escape denied")
	ErrArtifactV2NoContent     = errors.New("artifact content is unavailable")
	ErrArtifactV2NotRegular    = errors.New("artifact content is not a regular file")
)

type ArtifactRefReadInput struct {
	ArtifactRefID string   `json:"artifact_ref_id"`
	Scopes        []string `json:"scopes,omitempty"`
}

type ArtifactRefGrantInput struct {
	ArtifactRefID      string   `json:"artifact_ref_id"`
	GranteeGroupID     string   `json:"grantee_group_id,omitempty"`
	GranteePrincipalID string   `json:"grantee_principal_id,omitempty"`
	Scopes             []string `json:"scopes"`
	ExpiresAt          string   `json:"expires_at,omitempty"`
}

// CreateArtifactRefV2 publishes one immutable version of an existing legacy
// Artifact.  The caller may supply a summary and digest, but never a source
// path.  RelativePath is accepted only as a workspace-relative locator and is
// checked before it reaches the store.
func (s *Service) CreateArtifactRefV2(actor Actor, input store.ArtifactRefV2Input) (*store.ArtifactRefV2, error) {
	if err := s.Authorize(actor, "artifact.publish"); err != nil {
		return nil, err
	}
	input.GroupID = strings.TrimSpace(input.GroupID)
	if input.GroupID != "" && input.GroupID != actor.GroupID {
		return nil, ErrPermissionDenied
	}
	input.GroupID = actor.GroupID
	if input.RelativePath != "" {
		if _, err := artifactRelativePath(input.RelativePath); err != nil {
			return nil, err
		}
	}
	input.ProducerPrincipalID = actor.PrincipalID
	input.ProducerEndpointID = actor.EndpointID
	if err := s.store.InitializeArtifactV2Schema(); err != nil {
		return nil, err
	}
	ref, err := s.store.CreateArtifactRefV2ForActor(nativeActorScope(actor), input)
	if err != nil {
		return nil, mapRelayError(err)
	}
	// A supplied relative locator is checked against the persisted workspace
	// root before the ref can be used for content reads.  Metadata publication
	// remains useful for old rows whose path was never workspace-scoped.
	if _, relative, pathErr := s.store.ArtifactRefV2Path(ref.ID); pathErr != nil {
		return nil, pathErr
	} else if relative != "" {
		if _, err := artifactRelativePath(relative); err != nil {
			return nil, err
		}
	}
	return ref, nil
}

// PublishArtifactRefV2 is a compatibility spelling used by adapters.
func (s *Service) PublishArtifactRefV2(actor Actor, input store.ArtifactRefV2Input) (*store.ArtifactRefV2, error) {
	return s.CreateArtifactRefV2(actor, input)
}

func (s *Service) GrantArtifactRefV2(actor Actor, input ArtifactRefGrantInput) (*store.ArtifactRefV2Grant, error) {
	if err := s.Authorize(actor, "artifact.share"); err != nil {
		return nil, err
	}
	grant := store.ArtifactRefV2GrantInput{
		ArtifactRefID: input.ArtifactRefID, GranteeGroupID: strings.TrimSpace(input.GranteeGroupID),
		GranteePrincipalID: strings.TrimSpace(input.GranteePrincipalID), GrantorPrincipalID: actor.PrincipalID,
		Scopes: input.Scopes, ExpiresAt: input.ExpiresAt,
	}
	result, err := s.store.CreateArtifactRefV2GrantForActor(nativeActorScope(actor), grant)
	return result, mapRelayError(err)
}

func (s *Service) RevokeArtifactRefV2Grant(actor Actor, grantID, reason string) (*store.ArtifactRefV2Grant, error) {
	if err := s.Authorize(actor, "artifact.share"); err != nil {
		return nil, err
	}
	result, err := s.store.RevokeArtifactRefV2GrantForActor(nativeActorScope(actor), grantID, reason)
	return result, mapRelayError(err)
}

func (s *Service) RevokeArtifactRefV2(actor Actor, refID, reason string) (*store.ArtifactRefV2, error) {
	if err := s.Authorize(actor, "artifact.share"); err != nil {
		return nil, err
	}
	result, err := s.store.RevokeArtifactRefV2ForActor(nativeActorScope(actor), refID, reason)
	return result, mapRelayError(err)
}

// AuthorizeArtifactRefV2 is intentionally small and side-effect free.  All
// callers use it before metadata, summary, digest, or content is returned.
func (s *Service) AuthorizeArtifactRefV2(actor Actor, input ArtifactRefReadInput) (*store.ArtifactRefV2, error) {
	if err := s.Authorize(actor, "artifact.read"); err != nil {
		return nil, err
	}
	return s.store.AuthorizeArtifactRefV2ForActor(nativeActorScope(actor),
		input.ArtifactRefID, input.Scopes, s.now().UTC())
}

// ReadArtifactRefV2 performs the guard twice for content.  The second check
// closes the common revoke-while-reading window and makes stale membership or
// grants fail closed before bytes are returned.
func (s *Service) ReadArtifactRefV2(actor Actor, input ArtifactRefReadInput) (*store.ArtifactRefV2Authorized, error) {
	if err := s.Authorize(actor, "artifact.read"); err != nil {
		return nil, err
	}
	ref, err := s.AuthorizeArtifactRefV2(actor, input)
	if err != nil {
		return nil, err
	}
	scopes, err := artifactScopes(input.Scopes)
	if err != nil {
		return nil, err
	}
	projected := projectArtifactRefV2Read(*ref, scopes)
	result := &store.ArtifactRefV2Authorized{Ref: projected, Scopes: scopes}
	if containsArtifactScope(scopes, store.ArtifactRefV2ScopeContent) {
		content, err := s.readArtifactContent(ref)
		if err != nil {
			return nil, err
		}
		result.Content = content
		if _, err := s.AuthorizeArtifactRefV2(actor, ArtifactRefReadInput{ArtifactRefID: input.ArtifactRefID, Scopes: scopes}); err != nil {
			return nil, err
		}
		if err := s.Authorize(actor, "artifact.read"); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// ReadArtifactV2 is a compatibility spelling retained for clients migrating
// from an Artifact ID to an opaque versioned reference ID.
func (s *Service) ReadArtifactV2(actor Actor, input ArtifactRefReadInput) (*store.ArtifactRefV2Authorized, error) {
	return s.ReadArtifactRefV2(actor, input)
}

func (s *Service) ResolveArtifactRefsV2(actor Actor, refIDs, scopes []string) ([]store.ArtifactRefV2, error) {
	if err := s.Authorize(actor, "artifact.read"); err != nil {
		return nil, err
	}
	if len(refIDs) == 0 {
		return []store.ArtifactRefV2{}, nil
	}
	projectedScopes, err := artifactScopes(scopes)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(refIDs))
	result := make([]store.ArtifactRefV2, 0, len(refIDs))
	for _, refID := range refIDs {
		refID = strings.TrimSpace(refID)
		if refID == "" {
			return nil, store.ErrArtifactRefV2Denied
		}
		if _, ok := seen[refID]; ok {
			continue
		}
		seen[refID] = struct{}{}
		ref, err := s.store.AuthorizeArtifactRefV2ForActor(nativeActorScope(actor), refID, scopes, s.now().UTC())
		if err != nil {
			return nil, err
		}
		result = append(result, projectArtifactRefV2Read(*ref, projectedScopes))
	}
	return result, nil
}

func (s *Service) ListArtifactRefsV2(actor Actor, limit int) ([]store.ArtifactRefV2, error) {
	if err := s.Authorize(actor, "artifact.read"); err != nil {
		return nil, err
	}
	return s.store.ListArtifactRefsV2ForActor(nativeActorScope(actor), limit)
}

func projectArtifactRefV2Read(ref store.ArtifactRefV2, scopes []string) store.ArtifactRefV2 {
	ref.Scopes = append([]string(nil), scopes...)
	if !containsArtifactScope(scopes, store.ArtifactRefV2ScopeMetadata) {
		ref.WorkspaceID = ""
		ref.ProducerPrincipalID = ""
		ref.ProducerEndpointID = ""
		ref.Name = ""
		ref.Kind = ""
		ref.Size = 0
		ref.MIMEType = ""
	}
	if !containsArtifactScope(scopes, store.ArtifactRefV2ScopeSummary) {
		ref.Summary = ""
	}
	if !containsArtifactScope(scopes, store.ArtifactRefV2ScopeDigest) {
		ref.Digest = ""
	}
	return ref
}

// ValidateGatewayArtifactRefs checks the source actor's current membership,
// the exact source refs, and a concrete group grant for the target.  A string
// in Gateway.ArtifactRefs therefore never upgrades to workspace access.
func (s *Service) ValidateGatewayArtifactRefs(actor Actor, targetGroupID string, refIDs, scopes []string) error {
	if err := s.Authorize(actor, "artifact.share"); err != nil {
		return err
	}
	targetGroupID = strings.TrimSpace(targetGroupID)
	if targetGroupID == "" {
		return store.ErrArtifactRefV2Denied
	}
	for _, refID := range refIDs {
		ref, err := s.store.AuthorizeArtifactRefV2ForActor(nativeActorScope(actor), refID, scopes, s.now().UTC())
		if err != nil {
			return err
		}
		if ref.GroupID == targetGroupID {
			continue
		}
		if err := s.store.RequireArtifactRefV2GroupGrant(ref.ID, targetGroupID, scopes, s.now().UTC()); err != nil {
			return err
		}
	}
	return nil
}

func artifactScopes(scopes []string) ([]string, error) {
	seen := make(map[string]struct{}, len(scopes))
	result := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if scope == "" {
			continue
		}
		switch scope {
		case store.ArtifactRefV2ScopeMetadata, store.ArtifactRefV2ScopeSummary,
			store.ArtifactRefV2ScopeDigest, store.ArtifactRefV2ScopeContent:
		default:
			return nil, fmt.Errorf("%w: unknown scope %q", store.ErrArtifactRefV2ScopeDenied, scope)
		}
		if _, ok := seen[scope]; !ok {
			seen[scope] = struct{}{}
			result = append(result, scope)
		}
	}
	if len(result) == 0 {
		result = []string{store.ArtifactRefV2ScopeMetadata, store.ArtifactRefV2ScopeSummary, store.ArtifactRefV2ScopeDigest}
	}
	return result, nil
}

func containsArtifactScope(scopes []string, wanted string) bool {
	for _, scope := range scopes {
		if scope == wanted {
			return true
		}
	}
	return false
}

func artifactRelativePath(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.IndexByte(value, 0) >= 0 || filepath.IsAbs(value) || strings.HasPrefix(value, `\\`) {
		return "", fmt.Errorf("%w: absolute path", ErrArtifactV2PathTraversal)
	}
	// Treat Windows separators as separators even on Linux so a reference
	// created on one platform cannot become a traversal on another.
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == '/' || r == '\\' })
	for _, part := range parts {
		if part == ".." {
			return "", fmt.Errorf("%w: parent component", ErrArtifactV2PathTraversal)
		}
	}
	clean := filepath.Clean(filepath.FromSlash(strings.ReplaceAll(value, `\`, "/")))
	if clean == "." || clean == "" {
		return "", fmt.Errorf("%w: empty path", store.ErrArtifactRefV2UnsafePath)
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "", fmt.Errorf("%w: cleaned path escapes workspace", ErrArtifactV2PathTraversal)
	}
	return clean, nil
}

func secureArtifactPath(root, relative string) (string, error) {
	relative, err := artifactRelativePath(relative)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(root) == "" || relative == "" {
		return "", store.ErrArtifactRefV2UnsafePath
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", fmt.Errorf("%w: workspace root: %v", ErrArtifactV2SymlinkEscape, err)
	}
	candidate := filepath.Join(rootResolved, relative)
	candidateResolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrArtifactV2SymlinkEscape, err)
	}
	rel, err := filepath.Rel(rootResolved, candidateResolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", ErrArtifactV2SymlinkEscape
	}
	info, err := os.Lstat(candidate)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", ErrArtifactV2SymlinkEscape
	}
	return candidateResolved, nil
}

func (s *Service) readArtifactContent(ref *store.ArtifactRefV2) ([]byte, error) {
	root, relative, err := s.store.ArtifactRefV2Path(ref.ID)
	if err != nil {
		return nil, err
	}
	path, err := secureArtifactPath(root, relative)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, ErrArtifactV2NotRegular
	}
	if info.Size() > ArtifactV2MaxReadBytes {
		return nil, fmt.Errorf("artifact exceeds read limit")
	}
	content, err := io.ReadAll(io.LimitReader(file, ArtifactV2MaxReadBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > ArtifactV2MaxReadBytes {
		return nil, fmt.Errorf("artifact exceeds read limit")
	}
	if ref.Size > 0 && int64(len(content)) != ref.Size {
		return nil, fmt.Errorf("%w: size changed", store.ErrArtifactRefV2DigestMismatch)
	}
	sum := sha256.Sum256(content)
	if hex.EncodeToString(sum[:]) != strings.TrimPrefix(strings.ToLower(strings.TrimSpace(ref.Digest)), "sha256:") {
		return nil, store.ErrArtifactRefV2DigestMismatch
	}
	return content, nil
}
