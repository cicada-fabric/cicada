package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/cicada-ai/cicada/internal/e2ee"
	"github.com/cicada-ai/cicada/internal/store"
)

const maxClientEnrollmentBytes = 48 * 1024

func (h *Handler) clientV2(response http.ResponseWriter, request *http.Request) {
	if h.control == nil {
		writeError(response, http.StatusServiceUnavailable, errors.New("Client management is unavailable"))
		return
	}
	switch request.URL.Path {
	case "/v2/client/identity":
		if request.Method != http.MethodGet {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		hubID, err := h.control.ClientHubID()
		if err != nil {
			writeError(response, http.StatusServiceUnavailable, err)
			return
		}
		writeJSON(response, http.StatusOK, map[string]any{
			"contract": "android-hub-v1", "hub_id": hubID,
			"control_public_identity": h.control.ClientControlPublicIdentity(),
			"control_key_version":     1,
			"suite":                   "ML-KEM-768+ML-DSA-65+AES-256-GCM",
		})
	case "/v2/client/devices/enroll":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		var input struct {
			OwnerID          string              `json:"owner_id"`
			OwnerKeyID       string              `json:"owner_key_id"`
			DeviceID         string              `json:"device_id"`
			DevicePublic     e2ee.PublicIdentity `json:"device_public_identity"`
			OwnerDeviceGrant []byte              `json:"owner_device_grant"`
		}
		if err := decodeStrictClientJSON(request.Body, maxClientEnrollmentBytes, &input); err != nil {
			writeError(response, http.StatusBadRequest, err)
			return
		}
		device, err := h.control.RegisterClientDevice(store.RegisterClientDeviceInput{
			OwnerID: input.OwnerID, OwnerKeyID: input.OwnerKeyID,
			DeviceID: input.DeviceID, DevicePublic: input.DevicePublic,
			OwnerDeviceGrant: input.OwnerDeviceGrant,
		})
		if err != nil {
			// A management bearer is deliberately irrelevant on this route. A
			// registered, active owner key must sign the exact device binding.
			writeError(response, http.StatusForbidden, errors.New("owner-authorized device enrollment failed"))
			return
		}
		writeJSON(response, http.StatusCreated, map[string]any{
			"owner_id": device.OwnerID, "device_id": device.DeviceID,
			"session_epoch":      device.SessionEpoch,
			"device_key_version": device.KeyVersion,
			"state":              device.State,
		})
	case "/v2/client/rpc":
		if request.Method != http.MethodPost {
			writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		h.clientRPC(response, request)
	default:
		writeError(response, http.StatusNotFound, errors.New("Client route not found"))
	}
}

func decodeStrictClientJSON(reader io.Reader, limit int64, value any) error {
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > limit {
		return errors.New("Client request exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Client request contains trailing data")
	}
	return nil
}
