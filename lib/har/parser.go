package har

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"noauth/lib/types"
)

type HARFile struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Entries []HAREntry `json:"entries"`
}

type HAREntry struct {
	Request  HARRequest  `json:"request"`
	Response HARResponse `json:"response"`
}

type HARRequest struct {
	Method      string          `json:"method"`
	URL         string          `json:"url"`
	HTTPVersion string          `json:"httpVersion"`
	Headers     []HARHeader     `json:"headers"`
	QueryString []HARQueryParam `json:"queryString"`
	PostData    *HARPostData    `json:"postData"`
	Cookies     []HARCookie     `json:"cookies"`
}

type HARResponse struct {
	Status      int         `json:"status"`
	StatusText  string      `json:"statusText"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []HARHeader `json:"headers"`
	Content     HARContent  `json:"content"`
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARQueryParam struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

type HARCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARContent struct {
	Size        int    `json:"size"`
	MimeType    string `json:"mimeType"`
	Compression int    `json:"compression"`
	Text        string `json:"text"`
}

func ParseHARFile(filePath string) ([]*types.ParsedRequest, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read HAR file: %w", err)
	}

	return ParseHAR(data)
}

func ParseHAR(data []byte) ([]*types.ParsedRequest, error) {
	var harFile HARFile
	if err := json.Unmarshal(data, &harFile); err != nil {
		return nil, fmt.Errorf("failed to parse HAR JSON: %w", err)
	}

	var requests []*types.ParsedRequest
	for _, entry := range harFile.Log.Entries {
		req, err := convertHAREntryToRequest(entry)
		if err != nil {
			continue
		}
		requests = append(requests, req)
	}

	return requests, nil
}

func convertHAREntryToRequest(entry HAREntry) (*types.ParsedRequest, error) {
	req := &types.ParsedRequest{
		Method:  entry.Request.Method,
		URL:     entry.Request.URL,
		Headers: make(map[string]string),
		Raw:     fmt.Sprintf("%s %s HTTP/1.1", entry.Request.Method, entry.Request.URL),
	}

	for _, header := range entry.Request.Headers {
		req.Headers[header.Name] = header.Value
	}

	if entry.Request.URL != "" {
		if u, err := url.Parse(entry.Request.URL); err == nil {
			req.Headers["Host"] = u.Host
		}
	}

	var body string
	if entry.Request.PostData != nil {
		body = entry.Request.PostData.Text
		req.ContentType = entry.Request.PostData.MimeType
	}

	if req.ContentType == "" && len(entry.Request.QueryString) > 0 {
		var queryParts []string
		for _, q := range entry.Request.QueryString {
			queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(q.Name), url.QueryEscape(q.Value)))
		}
		if len(queryParts) > 0 {
			if strings.Contains(req.URL, "?") {
				req.URL = req.URL + "&" + strings.Join(queryParts, "&")
			} else {
				req.URL = req.URL + "?" + strings.Join(queryParts, "&")
			}
		}
	}

	req.Body = body

	return req, nil
}

func parseResponseBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return body, nil
		}
		defer reader.Close()
		return io.ReadAll(reader)
	}

	return body, nil
}
