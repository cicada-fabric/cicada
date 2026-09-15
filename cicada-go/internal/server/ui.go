package server

import (
	"embed"
	"errors"
	"net/http"
)

//go:embed ui/index.html ui/app.css ui/app.js
var clientFiles embed.FS

func isPublicClientPath(path string) bool {
	return path == "/" || path == "/assets/app.css" || path == "/assets/app.js"
}

func serveClient(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !isPublicClientPath(request.URL.Path) {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	path := "ui/index.html"
	contentType := "text/html; charset=utf-8"
	if request.URL.Path == "/assets/app.css" {
		path = "ui/app.css"
		contentType = "text/css; charset=utf-8"
	} else if request.URL.Path == "/assets/app.js" {
		path = "ui/app.js"
		contentType = "text/javascript; charset=utf-8"
	}
	data, err := clientFiles.ReadFile(path)
	if err != nil {
		writeError(response, http.StatusNotFound, errors.New("client asset not found"))
		return
	}
	response.Header().Set("Content-Type", contentType)
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(data)
}
