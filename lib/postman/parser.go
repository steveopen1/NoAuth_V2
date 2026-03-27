package postman

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"noauth/lib/types"
)

type PostmanCollection struct {
	Info     PostmanInfo       `json:"info"`
	Item     []PostmanItem     `json:"item"`
	Event    []PostmanEvent    `json:"event"`
	Variable []PostmanVariable `json:"variable"`
}

type PostmanInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Schema      string `json:"schema"`
}

type PostmanItem struct {
	Name    string          `json:"name"`
	Item    []PostmanItem   `json:"item,omitempty"`
	Request *PostmanRequest `json:"request,omitempty"`
	Event   []PostmanEvent  `json:"event,omitempty"`
}

type PostmanRequest struct {
	Method string          `json:"method"`
	Header []PostmanHeader `json:"header"`
	URL    interface{}     `json:"url"`
	Body   *PostmanBody    `json:"body"`
	Auth   *PostmanAuth    `json:"auth"`
}

type PostmanHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type PostmanBody struct {
	Mode       string              `json:"mode"`
	Raw        string              `json:"raw,omitempty"`
	Formdata   []PostmanFormData   `json:"formdata,omitempty"`
	Urlencoded []PostmanUrlencoded `json:"urlencoded,omitempty"`
}

type PostmanFormData struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type"`
}

type PostmanUrlencoded struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type PostmanAuth struct {
	Type   string             `json:"type"`
	Bearer []PostmanAuthParam `json:"bearer,omitempty"`
	Basic  []PostmanAuthParam `json:"basic,omitempty"`
	ApiKey []PostmanAuthParam `json:"apikey,omitempty"`
}

type PostmanAuthParam struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type PostmanEvent struct {
	Listen string         `json:"listen"`
	Script *PostmanScript `json:"script,omitempty"`
}

type PostmanScript struct {
	Type string   `json:"type"`
	Exec []string `json:"exec,omitempty"`
}

type PostmanVariable struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func ParsePostmanCollection(filePath string) ([]*types.ParsedRequest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Postman file: %w", err)
	}

	return ParsePostman(data)
}

func ParsePostman(data []byte) ([]*types.ParsedRequest, error) {
	var collection PostmanCollection
	if err := json.Unmarshal(data, &collection); err != nil {
		return nil, fmt.Errorf("failed to parse Postman JSON: %w", err)
	}

	var requests []*types.ParsedRequest
	flattenItems(collection.Item, &requests)

	return requests, nil
}

func flattenItems(items []PostmanItem, requests *[]*types.ParsedRequest) {
	for _, item := range items {
		if item.Request != nil {
			req := convertPostmanRequestToRequest(*item.Request)
			if req != nil {
				*requests = append(*requests, req)
			}
		}
		if len(item.Item) > 0 {
			flattenItems(item.Item, requests)
		}
	}
}

func convertPostmanRequestToRequest(postmanReq PostmanRequest) *types.ParsedRequest {
	req := &types.ParsedRequest{
		Method:  postmanReq.Method,
		Headers: make(map[string]string),
	}

	if req.Method == "" {
		req.Method = "GET"
	}

	switch v := postmanReq.URL.(type) {
	case string:
		req.URL = v
	case map[string]interface{}:
		if raw, ok := v["raw"].(string); ok {
			req.URL = raw
		} else if rawArr, ok := v["raw"].([]interface{}); ok && len(rawArr) > 0 {
			if s, ok := rawArr[0].(string); ok {
				req.URL = s
			}
		}
	}

	for _, header := range postmanReq.Header {
		req.Headers[header.Key] = header.Value
	}

	if postmanReq.Body != nil {
		switch postmanReq.Body.Mode {
		case "raw":
			req.Body = postmanReq.Body.Raw
			if req.ContentType == "" {
				req.ContentType = "text/plain"
			}
		case "formdata":
			var formParts []string
			for _, fd := range postmanReq.Body.Formdata {
				formParts = append(formParts, fmt.Sprintf("%s=%s", url.QueryEscape(fd.Key), url.QueryEscape(fd.Value)))
			}
			req.Body = strings.Join(formParts, "&")
			req.ContentType = "application/x-www-form-urlencoded"
		case "urlencoded":
			var urlEncParts []string
			for _, ue := range postmanReq.Body.Urlencoded {
				urlEncParts = append(urlEncParts, fmt.Sprintf("%s=%s", url.QueryEscape(ue.Key), url.QueryEscape(ue.Value)))
			}
			req.Body = strings.Join(urlEncParts, "&")
			req.ContentType = "application/x-www-form-urlencoded"
		}
	}

	if req.URL != "" {
		if u, err := url.Parse(req.URL); err == nil {
			req.Headers["Host"] = u.Host
		}
	}

	return req
}
