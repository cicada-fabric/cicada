package server

import (
	"embed"
	"errors"
	"net/http"
)

//go:embed ui/index.html ui/app.css ui/app.js ui/goal-detail.js ui/attachments.js ui/voice.js ui/push.js ui/events.js ui/manifest.webmanifest ui/sw.js ui/icon.svg
var clientFiles embed.FS

func isPublicClientPath(path string) bool {
	return path == "/" || path == "/assets/app.css" || path == "/assets/app.js" || path == "/assets/goal-detail.js" || path == "/assets/attachments.js" || path == "/assets/voice.js" || path == "/assets/push.js" || path == "/assets/events.js" || path == "/manifest.webmanifest" || path == "/sw.js" || path == "/icon.svg"
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
	} else if request.URL.Path == "/assets/goal-detail.js" {
		path = "ui/goal-detail.js"
		contentType = "text/javascript; charset=utf-8"
	} else if request.URL.Path == "/assets/attachments.js" {
		path = "ui/attachments.js"
		contentType = "text/javascript; charset=utf-8"
	} else if request.URL.Path == "/assets/voice.js" {
		path = "ui/voice.js"
		contentType = "text/javascript; charset=utf-8"
	} else if request.URL.Path == "/assets/push.js" {
		path = "ui/push.js"
		contentType = "text/javascript; charset=utf-8"
	} else if request.URL.Path == "/assets/events.js" {
		path = "ui/events.js"
		contentType = "text/javascript; charset=utf-8"
	} else if request.URL.Path == "/manifest.webmanifest" {
		path = "ui/manifest.webmanifest"
		contentType = "application/manifest+json; charset=utf-8"
	} else if request.URL.Path == "/sw.js" {
		path = "ui/sw.js"
		contentType = "text/javascript; charset=utf-8"
	} else if request.URL.Path == "/icon.svg" {
		path = "ui/icon.svg"
		contentType = "image/svg+xml; charset=utf-8"
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
