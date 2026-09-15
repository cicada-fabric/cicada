package server

import (
	_ "embed"
	"errors"
	"net/http"
)

//go:embed ui/index.html
var clientHTML []byte

func serveClient(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.Path != "/" {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.Header().Set("Cache-Control", "no-store")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(clientHTML)
}
