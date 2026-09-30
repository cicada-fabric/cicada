package server

import (
	"embed"
	"errors"
	"net/http"
)

//go:embed all:ui
var clientFiles embed.FS

var clientAssets = map[string]struct {
	file     string
	typeName string
	encoding string
}{
	"/":                                {"ui/index.html", "text/html; charset=utf-8", ""},
	"/assets/panel.css":                {"ui/panel.css", "text/css; charset=utf-8", ""},
	"/assets/panel.js":                 {"ui/panel.js", "text/javascript; charset=utf-8", ""},
	"/assets/panel-bootstrap.js":       {"ui/panel-bootstrap.js", "text/javascript; charset=utf-8", ""},
	"/assets/panel-client.js":          {"ui/panel-client.js", "text/javascript; charset=utf-8", ""},
	"/assets/panel-model.js":           {"ui/panel-model.js", "text/javascript; charset=utf-8", ""},
	"/assets/panel-canvas.js":          {"ui/panel-canvas.js", "text/javascript; charset=utf-8", ""},
	"/assets/panel-canvas-controls.js": {"ui/panel-canvas-controls.js", "text/javascript; charset=utf-8", ""},
	"/assets/panel-dom.js":             {"ui/panel-dom.js", "text/javascript; charset=utf-8", ""},
	"/assets/panel.manifest.json":      {"ui/generated/panel.manifest.json", "application/json; charset=utf-8", ""},
	"/assets/wasm_exec.js":             {"ui/generated/wasm_exec.js", "text/javascript; charset=utf-8", ""},
	"/assets/cicada-webcrypto.wasm":    {"ui/generated/cicada-webcrypto.wasm.gz", "application/wasm", "gzip"},
	"/icon.svg":                        {"ui/icon.svg", "image/svg+xml", ""},
}

func isPublicClientPath(path string) bool {
	_, ok := clientAssets[path]
	return ok
}

func serveClient(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		writeError(response, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}
	asset, ok := clientAssets[request.URL.Path]
	if !ok {
		writeError(response, http.StatusNotFound, errors.New("route not found"))
		return
	}
	data, err := clientFiles.ReadFile(asset.file)
	if err != nil {
		if request.URL.Path == "/" || request.URL.Path == "/assets/panel.js" ||
			request.URL.Path == "/assets/panel-bootstrap.js" || request.URL.Path == "/assets/panel-client.js" || request.URL.Path == "/assets/panel-model.js" ||
			request.URL.Path == "/assets/panel-canvas.js" || request.URL.Path == "/assets/panel-canvas-controls.js" ||
			request.URL.Path == "/assets/panel-dom.js" || request.URL.Path == "/assets/panel.css" || request.URL.Path == "/icon.svg" {
			writeError(response, http.StatusNotFound, errors.New("Hub panel asset is unavailable"))
			return
		}
		writeError(response, http.StatusServiceUnavailable, errors.New("Hub WebCrypto assets were not built; run scripts/build-web-panel.sh and rebuild the Hub"))
		return
	}
	response.Header().Set("Content-Type", asset.typeName)
	if asset.encoding != "" {
		response.Header().Set("Content-Encoding", asset.encoding)
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src 'self'; img-src 'self' data:; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(data)
}
