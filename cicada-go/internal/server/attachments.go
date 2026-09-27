package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/cicada-ai/cicada/internal/control"
)

func (h *Handler) attachments(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	var input control.AttachmentInput
	if err := readAttachmentJSON(request, &input); err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	attachment, err := h.control.CreateAttachment(input)
	if err != nil {
		writeError(response, http.StatusBadRequest, err)
		return
	}
	writeJSON(response, http.StatusCreated, attachment)
}

func readAttachmentJSON(request *http.Request, target any) error {
	body, err := readBody(request, 12<<20)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request body must contain one JSON value")
	}
	return nil
}

func (h *Handler) attachment(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/v1/attachments/")
	if id == "" || strings.Contains(id, "/") {
		writeError(response, http.StatusNotFound, errors.New("attachment not found"))
		return
	}
	attachment, err := h.control.Attachment(id)
	if err != nil {
		writeError(response, http.StatusInternalServerError, err)
		return
	}
	if attachment == nil {
		writeError(response, http.StatusNotFound, os.ErrNotExist)
		return
	}
	writeJSON(response, http.StatusOK, attachment)
}
