package zap

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"noauth/lib/types"
)

type ZAPResponse struct {
	Requests []ZAPRequest `json:"requests"`
}

type ZAPRequest struct {
	URI     string            `json:"uri"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

func ParseZAPJSON(filePath string) ([]*types.ParsedRequest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ZAP file: %w", err)
	}

	return ParseZAP(data)
}

func ParseZAP(data []byte) ([]*types.ParsedRequest, error) {
	var zapResp ZAPResponse
	if err := json.Unmarshal(data, &zapResp); err != nil {
		var zapArray []ZAPRequest
		if err2 := json.Unmarshal(data, &zapArray); err2 != nil {
			return nil, fmt.Errorf("failed to parse ZAP JSON: %w", err)
		}
		zapResp.Requests = zapArray
	}

	var requests []*types.ParsedRequest
	for _, zapReq := range zapResp.Requests {
		req, err := convertZAPRequestToRequest(zapReq)
		if err != nil {
			continue
		}
		requests = append(requests, req)
	}

	return requests, nil
}

func convertZAPRequestToRequest(zapReq ZAPRequest) (*types.ParsedRequest, error) {
	req := &types.ParsedRequest{
		Method:  zapReq.Method,
		URL:     zapReq.URI,
		Headers: make(map[string]string),
		Body:    zapReq.Body,
	}

	for k, v := range zapReq.Headers {
		req.Headers[k] = v
	}

	if req.Method == "" {
		req.Method = "GET"
	}

	if req.URL != "" {
		if u, err := url.Parse(req.URL); err == nil {
			req.Headers["Host"] = u.Host
		}
	}

	if req.Body != "" && req.ContentType == "" {
		req.ContentType = "application/x-www-form-urlencoded"
	}

	return req, nil
}

func detectContentType(body string) string {
	if strings.Contains(body, "{") && strings.Contains(body, "}") {
		return "application/json"
	}
	if strings.Contains(body, "=") && strings.Contains(body, "&") {
		return "application/x-www-form-urlencoded"
	}
	return "text/plain"
}
