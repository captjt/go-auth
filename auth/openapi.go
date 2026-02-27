package auth

import (
	"encoding/json"
	"sort"
	"strings"
)

type routeDoc struct {
	Method      string
	Path        string
	Summary     string
	Description string
	Tags        []string
}

type openAPISpec struct {
	OpenAPI string                 `json:"openapi"`
	Info    openAPIInfo            `json:"info"`
	Paths   map[string]openAPIPath `json:"paths"`
}

type openAPIInfo struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

type openAPIPath map[string]openAPIOperation

type openAPIOperation struct {
	Summary     string                     `json:"summary,omitempty"`
	Description string                     `json:"description,omitempty"`
	Tags        []string                   `json:"tags,omitempty"`
	Responses   map[string]openAPIResponse `json:"responses"`
}

type openAPIResponse struct {
	Description string `json:"description"`
}

func buildOpenAPISpec(appName string, docs []routeDoc) ([]byte, error) {
	sort.Slice(docs, func(i, j int) bool {
		if docs[i].Path == docs[j].Path {
			return docs[i].Method < docs[j].Method
		}
		return docs[i].Path < docs[j].Path
	})

	spec := openAPISpec{
		OpenAPI: "3.0.3",
		Info: openAPIInfo{
			Title:   appName + " API",
			Version: "0.1.0",
		},
		Paths: map[string]openAPIPath{},
	}

	for _, d := range docs {
		if _, ok := spec.Paths[d.Path]; !ok {
			spec.Paths[d.Path] = openAPIPath{}
		}
		spec.Paths[d.Path][strings.ToLower(d.Method)] = openAPIOperation{
			Summary:     d.Summary,
			Description: d.Description,
			Tags:        d.Tags,
			Responses: map[string]openAPIResponse{
				"200": {Description: "Success"},
				"400": {Description: "Bad request"},
				"401": {Description: "Unauthorized"},
				"404": {Description: "Not found"},
				"429": {Description: "Too many requests"},
			},
		}
	}

	return json.MarshalIndent(spec, "", "  ")
}
