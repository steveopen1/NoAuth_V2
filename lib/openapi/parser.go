package openapi

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"noauth/lib/types"
)

type OpenAPISpec struct {
	OpenAPI    string                 `json:"openapi"`
	Swagger    string                 `json:"swagger"`
	Info       OpenAPIInfo            `json:"info"`
	Paths      map[string]OpenAPIPath `json:"paths"`
	Servers    []OpenAPIServer        `json:"servers"`
	Components OpenAPIComponents      `json:"components"`
}

type OpenAPIInfo struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Version     string `json:"version"`
}

type OpenAPIPath struct {
	Get     *OpenAPIOperation `json:"get,omitempty"`
	Post    *OpenAPIOperation `json:"post,omitempty"`
	Put     *OpenAPIOperation `json:"put,omitempty"`
	Delete  *OpenAPIOperation `json:"delete,omitempty"`
	Patch   *OpenAPIOperation `json:"patch,omitempty"`
	Head    *OpenAPIOperation `json:"head,omitempty"`
	Options *OpenAPIOperation `json:"options,omitempty"`
}

type OpenAPIOperation struct {
	Summary     string                     `json:"summary"`
	Description string                     `json:"description"`
	OperationID string                     `json:"operationId"`
	Parameters  []OpenAPIParameter         `json:"parameters"`
	RequestBody *OpenAPIRequestBody        `json:"requestBody"`
	Responses   map[string]OpenAPIResponse `json:"responses"`
	Tags        []string                   `json:"tags"`
}

type OpenAPIParameter struct {
	Name        string                 `json:"name"`
	In          string                 `json:"in"`
	Description string                 `json:"description"`
	Required    bool                   `json:"required"`
	Schema      map[string]interface{} `json:"schema"`
}

type OpenAPIRequestBody struct {
	Description string                      `json:"description"`
	Required    bool                        `json:"required"`
	Content     map[string]OpenAPIMediaType `json:"content"`
}

type OpenAPIMediaType struct {
	Schema *OpenAPISchema `json:"schema"`
}

type OpenAPISchema struct {
	Type        string                    `json:"type"`
	Properties  map[string]*OpenAPISchema `json:"properties"`
	Items       *OpenAPISchema            `json:"items"`
	Format      string                    `json:"format"`
	Description string                    `json:"description"`
}

type OpenAPIResponse struct {
	Description string                      `json:"description"`
	Content     map[string]OpenAPIMediaType `json:"content"`
}

type OpenAPIServer struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

type OpenAPIComponents struct {
	Schemas map[string]*OpenAPISchema `json:"schemas"`
}

func ParseOpenAPI(filePath string) ([]*types.ParsedRequest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenAPI file: %w", err)
	}

	return ParseOpenAPISpec(data)
}

func ParseOpenAPISpec(data []byte) ([]*types.ParsedRequest, error) {
	var spec OpenAPISpec
	if err := json.Unmarshal(data, &spec); err != nil {
		var legacySpec map[string]interface{}
		if err2 := json.Unmarshal(data, &legacySpec); err2 != nil {
			return nil, fmt.Errorf("failed to parse OpenAPI JSON: %w", err)
		}
		if swagger, ok := legacySpec["swagger"].(string); ok && strings.HasPrefix(swagger, "2.") {
			return parseSwagger2Spec(data)
		}
		return nil, fmt.Errorf("failed to parse OpenAPI JSON: %w", err)
	}

	return convertOpenAPIToRequests(spec)
}

func parseSwagger2Spec(data []byte) ([]*types.ParsedRequest, error) {
	var swagger struct {
		Host     string   `json:"host"`
		BasePath string   `json:"basePath"`
		Schemes  []string `json:"schemes"`
		Paths    map[string]struct {
			GET    interface{} `json:"get"`
			POST   interface{} `json:"post"`
			PUT    interface{} `json:"put"`
			DELETE interface{} `json:"delete"`
			PATCH  interface{} `json:"patch"`
		} `json:"paths"`
	}

	if err := json.Unmarshal(data, &swagger); err != nil {
		return nil, fmt.Errorf("failed to parse Swagger 2.0: %w", err)
	}

	var requests []*types.ParsedRequest
	baseURL := ""
	if len(swagger.Schemes) > 0 {
		baseURL = swagger.Schemes[0] + "://" + swagger.Host + swagger.BasePath
	}

	for path, pathItem := range swagger.Paths {
		fullPath := baseURL + path

		methods := []interface{}{pathItem.GET, pathItem.POST, pathItem.PUT, pathItem.DELETE, pathItem.PATCH}
		methodNames := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}

		for i, method := range methods {
			if method != nil {
				req := &types.ParsedRequest{
					Method:  methodNames[i],
					URL:     fullPath,
					Headers: make(map[string]string),
				}
				requests = append(requests, req)
			}
		}
	}

	return requests, nil
}

func convertOpenAPIToRequests(spec OpenAPISpec) ([]*types.ParsedRequest, error) {
	var requests []*types.ParsedRequest
	baseURL := ""
	if len(spec.Servers) > 0 {
		baseURL = spec.Servers[0].URL
	}

	for path, pathItem := range spec.Paths {
		fullPath := baseURL + path

		operations := []struct {
			method string
			op     *OpenAPIOperation
		}{
			{"GET", pathItem.Get},
			{"POST", pathItem.Post},
			{"PUT", pathItem.Put},
			{"DELETE", pathItem.Delete},
			{"PATCH", pathItem.Patch},
			{"HEAD", pathItem.Head},
			{"OPTIONS", pathItem.Options},
		}

		for _, op := range operations {
			if op.op == nil {
				continue
			}

			req := &types.ParsedRequest{
				Method:  op.method,
				URL:     fullPath,
				Headers: make(map[string]string),
			}

			for _, param := range op.op.Parameters {
				if param.In == "header" {
					req.Headers[param.Name] = ""
				}
			}

			if op.op.RequestBody != nil {
				if ct, ok := op.op.RequestBody.Content["application/json"]; ok {
					if ct.Schema != nil {
						req.Body = generateSampleJSON(ct.Schema)
						req.ContentType = "application/json"
					}
				} else if ct, ok := op.op.RequestBody.Content["application/x-www-form-urlencoded"]; ok {
					if ct.Schema != nil {
						req.Body = generateFormData(ct.Schema)
						req.ContentType = "application/x-www-form-urlencoded"
					}
				}
			}

			requests = append(requests, req)
		}
	}

	return requests, nil
}

func generateSampleJSON(schema *OpenAPISchema) string {
	if schema == nil {
		return "{}"
	}

	if schema.Type == "object" && schema.Properties != nil {
		var parts []string
		for key, prop := range schema.Properties {
			parts = append(parts, fmt.Sprintf(`"%s": %s`, key, generateSampleJSON(prop)))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}

	if schema.Type == "array" && schema.Items != nil {
		return "[" + generateSampleJSON(schema.Items) + "]"
	}

	switch schema.Type {
	case "string":
		if schema.Format == "date" {
			return `"2024-01-01"`
		}
		if schema.Format == "date-time" {
			return `"2024-01-01T00:00:00Z"`
		}
		if schema.Format == "email" {
			return `"user@example.com"`
		}
		if schema.Format == "uuid" {
			return `"550e8400-e29b-41d4-a716-446655440000"`
		}
		return `"string"`
	case "integer", "number":
		return "0"
	case "boolean":
		return "true"
	default:
		return "null"
	}
}

func generateFormData(schema *OpenAPISchema) string {
	if schema == nil || schema.Properties == nil {
		return ""
	}

	var parts []string
	for key, prop := range schema.Properties {
		parts = append(parts, fmt.Sprintf("%s=%s", key, generateSampleJSON(prop)))
	}
	return strings.Join(parts, "&")
}
