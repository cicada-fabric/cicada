package telegram

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9:_-]{1,256}$`)

type Client struct {
	BaseURL    string
	Token      string
	HTTPClient *http.Client
	PollWait   time.Duration
}

func NewClient(baseURL, token string, client *http.Client) (*Client, error) {
	token = strings.TrimSpace(token)
	if !tokenPattern.MatchString(token) {
		return nil, errors.New("telegram bot token has an invalid format")
	}
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || parsed.User != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return nil, errors.New("telegram API URL must be an absolute http or https URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 35 * time.Second}
	}
	return &Client{BaseURL: strings.TrimRight(parsed.String(), "/"), Token: token, HTTPClient: client, PollWait: 25 * time.Second}, nil
}

func (c *Client) GetUpdates(ctx context.Context, offset int64) ([]json.RawMessage, error) {
	if c == nil || c.HTTPClient == nil {
		return nil, errors.New("telegram client is not initialized")
	}
	wait := int64(c.PollWait / time.Second)
	if wait < 0 {
		wait = 0
	}
	if wait > 50 {
		wait = 50
	}
	endpoint := c.BaseURL + "/bot" + c.Token + "/getUpdates?offset=" + strconv.FormatInt(offset, 10) + "&limit=100&timeout=" + strconv.FormatInt(wait, 10)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	response, err := c.HTTPClient.Do(request)
	if err != nil {
		// net/http errors can include the complete request URL. Telegram embeds
		// the bot token in that URL, so never propagate the transport text.
		return nil, errors.New("telegram API request failed")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxUpdateBytes*4+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxUpdateBytes*4 {
		return nil, errors.New("telegram API response is too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("telegram API returned %s", response.Status)
	}
	var envelope struct {
		OK     bool              `json:"ok"`
		Result []json.RawMessage `json:"result"`
		Error  string            `json:"description"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, errors.New("telegram API returned invalid JSON")
	}
	if !envelope.OK {
		if envelope.Error == "" {
			envelope.Error = "request rejected"
		}
		return nil, fmt.Errorf("telegram API request failed: %s", envelope.Error)
	}
	return envelope.Result, nil
}
