package burp

import (
	"encoding/xml"
	"fmt"
	"net/url"
	"os"
	"strings"

	"noauth/lib/types"
)

type BurpItems struct {
	XMLName xml.Name   `xml:"items"`
	Items   []BurpItem `xml:"item"`
}

type BurpItem struct {
	Time           string       `xml:"time,attr"`
	URL            string       `xml:"url"`
	Host           string       `xml:"host"`
	Port           int          `xml:"port"`
	Protocol       string       `xml:"protocol"`
	Method         string       `xml:"method"`
	Path           string       `xml:"path"`
	Extension      string       `xml:"extension"`
	Request        BurpRequest  `xml:"request"`
	Response       BurpResponse `xml:"response"`
	Status         int          `xml:"status"`
	ResponseLength int          `xml:"responselength"`
	MimeType       string       `xml:"mimetype"`
}

type BurpRequest struct {
	Base64 bool   `xml:"base64,attr"`
	Text   string `xml:",chardata"`
}

type BurpResponse struct {
	Base64 bool   `xml:"base64,attr"`
	Text   string `xml:",chardata"`
}

func ParseBurpXML(filePath string) ([]*types.ParsedRequest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Burp file: %w", err)
	}

	return ParseBurp(data)
}

func ParseBurp(data []byte) ([]*types.ParsedRequest, error) {
	var items BurpItems
	if err := xml.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("failed to parse Burp XML: %w", err)
	}

	var requests []*types.ParsedRequest
	for _, item := range items.Items {
		req, err := convertBurpItemToRequest(item)
		if err != nil {
			continue
		}
		requests = append(requests, req)
	}

	return requests, nil
}

func convertBurpItemToRequest(item BurpItem) (*types.ParsedRequest, error) {
	fullURL := item.URL
	if fullURL == "" {
		protocol := "https"
		if item.Protocol == "http" {
			protocol = "http"
		}
		fullURL = fmt.Sprintf("%s://%s:%d%s", protocol, item.Host, item.Port, item.Path)
	}

	req := &types.ParsedRequest{
		Method:  item.Method,
		URL:     fullURL,
		Headers: make(map[string]string),
		Raw:     item.Request.Text,
	}

	req.Headers["Host"] = fmt.Sprintf("%s:%d", item.Host, item.Port)

	if item.Request.Text != "" {
		headers, body := parseRequestHeadersAndBody(item.Request.Text)
		for k, v := range headers {
			if strings.ToLower(k) != "host" {
				req.Headers[k] = v
			}
		}
		req.Body = body

		if ct, ok := headers["Content-Type"]; ok {
			req.ContentType = ct
		} else if ct, ok := headers["content-type"]; ok {
			req.ContentType = ct
		}
	}

	if u, err := url.Parse(fullURL); err == nil {
		req.Headers["Host"] = u.Host
	}

	return req, nil
}

func parseRequestHeadersAndBody(raw string) (map[string]string, string) {
	headers := make(map[string]string)
	lines := strings.Split(raw, "\r\n")

	bodyStart := 0
	for i, line := range lines {
		if line == "" {
			bodyStart = i + 1
			break
		}

		if strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				headers[key] = value
			}
		}
	}

	body := strings.Join(lines[bodyStart:], "\r\n")
	return headers, body
}

func decodeBase64(s string) ([]byte, error) {
	return []byte(s), nil
}
