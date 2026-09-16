// Package telegram normalizes Telegram Bot API updates without retaining the
// provider token or forwarding provider-specific envelopes to Workers.
package telegram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const MaxUpdateBytes = 1 << 20

type Update struct {
	UpdateID      int64    `json:"update_id"`
	Message       *Message `json:"message,omitempty"`
	EditedMessage *Message `json:"edited_message,omitempty"`
	ChannelPost   *Message `json:"channel_post,omitempty"`
}

type Message struct {
	MessageID      int64    `json:"message_id"`
	From           *User    `json:"from,omitempty"`
	Chat           Chat     `json:"chat"`
	Date           int64    `json:"date"`
	Text           string   `json:"text,omitempty"`
	Caption        string   `json:"caption,omitempty"`
	ReplyToMessage *Message `json:"reply_to_message,omitempty"`
}

type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username,omitempty"`
	FirstName string `json:"first_name,omitempty"`
}

type Chat struct {
	ID       int64  `json:"id"`
	Type     string `json:"type"`
	Title    string `json:"title,omitempty"`
	Username string `json:"username,omitempty"`
}

func UpdateID(raw []byte) (int64, error) {
	var value struct {
		UpdateID int64 `json:"update_id"`
	}
	if len(raw) == 0 || !json.Valid(raw) {
		return 0, errors.New("telegram update must be valid JSON")
	}
	if err := json.Unmarshal(raw, &value); err != nil || value.UpdateID < 0 {
		return 0, errors.New("telegram update_id must be non-negative")
	}
	return value.UpdateID, nil
}

// Normalize returns a stable event key, event type, and JSON payload. The
// update_id is the idempotency key used by Control's connector store.
func Normalize(raw []byte) (externalID, eventType string, payload []byte, err error) {
	if len(raw) == 0 || len(raw) > MaxUpdateBytes || !json.Valid(raw) {
		return "", "", nil, errors.New("telegram update must be valid JSON and at most 1 MiB")
	}
	var update Update
	if err := json.Unmarshal(raw, &update); err != nil {
		return "", "", nil, err
	}
	if update.UpdateID < 0 {
		return "", "", nil, errors.New("telegram update_id must be non-negative")
	}
	message, eventType := selectMessage(update)
	if message == nil {
		return "", "", nil, errors.New("telegram update has no supported message")
	}
	text := strings.TrimSpace(message.Text)
	if text == "" {
		text = strings.TrimSpace(message.Caption)
	}
	value := map[string]any{
		"provider": "telegram", "update_id": update.UpdateID,
		"message_id": message.MessageID, "chat_id": message.Chat.ID,
		"chat_type": message.Chat.Type, "date": message.Date, "text": text,
	}
	if message.Chat.Title != "" {
		value["chat_title"] = message.Chat.Title
	}
	if message.Chat.Username != "" {
		value["chat_username"] = message.Chat.Username
	}
	if message.From != nil {
		value["from_id"] = message.From.ID
		if message.From.Username != "" {
			value["from_username"] = message.From.Username
		}
	}
	if message.ReplyToMessage != nil {
		value["reply_to_message_id"] = message.ReplyToMessage.MessageID
	}
	payload, err = json.Marshal(value)
	if err != nil {
		return "", "", nil, err
	}
	return fmt.Sprintf("update:%d", update.UpdateID), eventType, payload, nil
}

func selectMessage(update Update) (*Message, string) {
	if update.Message != nil {
		return update.Message, "message.created"
	}
	if update.EditedMessage != nil {
		return update.EditedMessage, "message.edited"
	}
	if update.ChannelPost != nil {
		return update.ChannelPost, "channel_post.created"
	}
	return nil, ""
}

// Signature is the HMAC-SHA256 header value expected by Control's webhook
// ingress. The secret is read by the connector process, never by Control's
// event payload or a Worker.
func Signature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
