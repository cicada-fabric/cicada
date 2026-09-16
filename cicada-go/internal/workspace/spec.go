package workspace

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// Source describes a reproducible, credential-free workspace origin.
type Source struct {
	Kind     string `json:"kind"`
	URL      string `json:"url"`
	Revision string `json:"revision"`
}

func (s Source) Hostname() string {
	target, err := url.Parse(s.URL)
	if err != nil {
		return ""
	}
	return strings.ToLower(target.Hostname())
}

// SourceFromResources parses resources.workspace_source. A missing source is
// valid and keeps the existing empty/pre-provisioned workspace behavior.
func SourceFromResources(resources map[string]any) (*Source, error) {
	if resources == nil || resources["workspace_source"] == nil {
		return nil, nil
	}
	values, ok := resources["workspace_source"].(map[string]any)
	if !ok {
		if typed, typedOK := resources["workspace_source"].(map[string]string); typedOK {
			values = make(map[string]any, len(typed))
			for key, value := range typed {
				values[key] = value
			}
		} else {
			return nil, errors.New("resources.workspace_source must be an object")
		}
	}
	source := &Source{
		Kind: stringValue(values["kind"]), URL: stringValue(values["url"]),
		Revision: stringValue(values["revision"]),
	}
	if source.Kind == "" {
		source.Kind = "git"
	}
	if source.Revision == "" {
		source.Revision = "HEAD"
	}
	if err := source.Validate(); err != nil {
		return nil, err
	}
	return source, nil
}

func (s Source) Validate() error {
	if strings.ToLower(strings.TrimSpace(s.Kind)) != "git" {
		return fmt.Errorf("unsupported workspace source kind: %s", s.Kind)
	}
	if len(s.URL) == 0 || len(s.URL) > 2048 {
		return errors.New("workspace Git URL must contain 1-2048 characters")
	}
	target, err := url.Parse(s.URL)
	if err != nil || target == nil || target.Scheme != "https" || target.Hostname() == "" {
		return errors.New("workspace Git URL must be an absolute https URL")
	}
	if target.User != nil || target.RawQuery != "" || target.Fragment != "" || target.Port() != "" {
		return errors.New("workspace Git URL cannot contain credentials, a port, query, or fragment")
	}
	if target.Path == "" || target.Path == "/" {
		return errors.New("workspace Git URL must include a repository path")
	}
	if len(s.Revision) == 0 || len(s.Revision) > 256 || strings.HasPrefix(s.Revision, "-") ||
		strings.ContainsAny(s.Revision, "\x00\r\n") {
		return errors.New("workspace Git revision must be 1-256 safe characters")
	}
	for _, character := range target.Hostname() {
		if character > 127 {
			return errors.New("workspace Git hostname must use ASCII")
		}
	}
	return nil
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}
