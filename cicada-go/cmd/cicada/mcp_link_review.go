package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func (m *mcpServer) communicationLinkReviewTool(name string, arguments map[string]any) (any, error) {
	switch name {
	case "cicada_link_review_list":
		limit := int64(16)
		if raw, ok := arguments["limit"]; ok {
			parsed, valid := strictMCPInteger(raw)
			if !valid || parsed < 1 || parsed > 100 {
				return nil, errors.New("link review limit must be an integer from 1 through 100")
			}
			limit = parsed
		}
		query := url.Values{}
		if cursor := stringArgument(arguments, "cursor"); cursor != "" {
			query.Set("cursor", cursor)
		}
		query.Set("limit", strconv.FormatInt(limit, 10))
		return m.api(http.MethodGet, "/v2/fabric/link-reviews?"+query.Encode(), nil)
	case "cicada_link_review_get":
		messageID := strings.TrimSpace(stringArgument(arguments, "message_id"))
		if messageID == "" {
			return nil, errors.New("message_id is required")
		}
		return m.api(http.MethodGet, "/v2/fabric/link-reviews/"+url.PathEscape(messageID), nil)
	case "cicada_link_review_claim_next":
		messageID := strings.TrimSpace(stringArgument(arguments, "message_id"))
		version, validVersion := strictMCPInteger(arguments["expected_version"])
		epoch, validEpoch := strictMCPInteger(arguments["expected_owner_epoch"])
		if messageID == "" || !validVersion || version <= 0 || !validEpoch || epoch <= 0 {
			return nil, errors.New("link review claim requires message_id and positive integer expected_version/expected_owner_epoch")
		}
		return m.api(http.MethodPost, "/v2/fabric/link-reviews/"+url.PathEscape(messageID)+"/claim-next", map[string]any{
			"message_id": messageID, "expected_version": version, "expected_owner_epoch": epoch,
		})
	case "cicada_link_review_decide":
		messageID := strings.TrimSpace(stringArgument(arguments, "message_id"))
		version, validVersion := strictMCPInteger(arguments["expected_version"])
		epoch, validEpoch := strictMCPInteger(arguments["expected_owner_epoch"])
		decision := stringArgument(arguments, "decision")
		if messageID == "" || !validVersion || version <= 0 || !validEpoch || epoch <= 0 ||
			(decision != "APPROVED" && decision != "REJECTED") {
			return nil, errors.New("link review decision requires positive integer version/epoch and APPROVED or REJECTED")
		}
		return m.api(http.MethodPost, "/v2/fabric/link-reviews/"+url.PathEscape(messageID)+"/decision", map[string]any{
			"message_id": messageID, "expected_version": version,
			"expected_owner_epoch": epoch, "decision": decision,
		})
	default:
		return nil, fmt.Errorf("unknown communication Link review tool: %s", name)
	}
}
