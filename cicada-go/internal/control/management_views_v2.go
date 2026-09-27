package control

import (
	"sort"
	"strings"

	"github.com/cicada-ai/cicada/internal/store"
)

// SharedTaskResults returns task submissions for one management-visible
// Group. Candidate results remain visible with their Authority so the client
// does not mistake submitted evidence for accepted work.
func (c *Control) SharedTaskResults(groupID string, limit int) ([]store.SharedTaskResult, error) {
	groupID = strings.TrimSpace(groupID)
	if _, err := c.store.GetGroup(groupID); err != nil {
		return nil, err
	}
	return c.store.ListSharedTaskResults(groupID, limit)
}

// FederationRequestsForGroup returns requests on either side of a Group's
// representative boundary. The two filtered queries avoid loading unrelated
// private Group requests into the management response.
func (c *Control) FederationRequestsForGroup(groupID string, limit int) ([]store.FederationRequest, error) {
	groupID = strings.TrimSpace(groupID)
	if _, err := c.store.GetGroup(groupID); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	outgoing, err := c.store.ListFederationRequests(store.FederationRequestFilter{SourceGroupID: groupID, Limit: limit})
	if err != nil {
		return nil, err
	}
	incoming, err := c.store.ListFederationRequests(store.FederationRequestFilter{TargetGroupID: groupID, Limit: limit})
	if err != nil {
		return nil, err
	}
	byID := make(map[string]store.FederationRequest, len(outgoing)+len(incoming))
	for _, request := range outgoing {
		byID[request.ID] = request
	}
	for _, request := range incoming {
		byID[request.ID] = request
	}
	requests := make([]store.FederationRequest, 0, len(byID))
	for _, request := range byID {
		requests = append(requests, request)
	}
	sort.Slice(requests, func(i, j int) bool {
		if requests[i].UpdatedAt == requests[j].UpdatedAt {
			return requests[i].ID > requests[j].ID
		}
		return requests[i].UpdatedAt > requests[j].UpdatedAt
	})
	if len(requests) > limit {
		requests = requests[:limit]
	}
	return requests, nil
}
