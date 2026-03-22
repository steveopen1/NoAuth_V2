package lib

import (
	"bufio"
	"bytes"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

type ParsedRequest struct {
	Method      string
	URL         string
	Headers     map[string]string
	Body        string
	ContentType string
	Raw         string
}

func ParseRequest(filePath string) (*ParsedRequest, error) {
	data, err := readFile(filePath)
	if err != nil {
		return nil, err
	}

	content := strings.TrimSpace(string(data))
	if strings.HasPrefix(content, "curl ") {
		return parseCurlCommand(content)
	}
	return parseRawRequest(content)
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func parseRawRequest(raw string) (*ParsedRequest, error) {
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return nil, fmt.Errorf("empty request")
	}

	req := &ParsedRequest{
		Headers: make(map[string]string),
		Raw:     raw,
	}

	reader := bufio.NewReader(bytes.NewBufferString(raw))
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read request line: %w", err)
	}
	requestLine = strings.TrimSpace(requestLine)
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid request line: %s", requestLine)
	}
	req.Method = parts[0]
	pathWithQuery := parts[1]
	if len(parts) >= 3 {
		req.Headers["HTTP-Version"] = parts[2]
	}

	var bodyLines []string
	inBody := false
	var detectedHost string

	for {
		line, err := reader.ReadString('\n')
		if err != nil && len(line) == 0 {
			break
		}
		line = strings.TrimSpace(line)

		if line == "" {
			if !inBody {
				inBody = true
				continue
			}
		}

		if inBody {
			bodyLines = append(bodyLines, line)
		} else if strings.Contains(line, ":") {
			colonIdx := strings.Index(line, ":")
			key := strings.TrimSpace(line[:colonIdx])
			value := strings.TrimSpace(line[colonIdx+1:])
			keyLower := strings.ToLower(key)
			if keyLower == "host" {
				detectedHost = value
				if !strings.Contains(req.URL, "://") {
					req.URL = "http://" + value + pathWithQuery
				}
			} else {
				req.Headers[key] = value
			}
		}
	}

	if bodyLines != nil {
		req.Body = strings.Join(bodyLines, "\n")
	}

	if !strings.Contains(req.URL, "://") {
		if strings.HasPrefix(pathWithQuery, "http://") || strings.HasPrefix(pathWithQuery, "https://") {
			req.URL = pathWithQuery
		} else if detectedHost != "" {
			if !strings.HasPrefix(pathWithQuery, "/") {
				pathWithQuery = "/" + pathWithQuery
			}
			req.URL = "http://" + detectedHost + pathWithQuery
		} else {
			if !strings.HasPrefix(pathWithQuery, "/") {
				pathWithQuery = "/" + pathWithQuery
			}
			req.URL = pathWithQuery
		}
	}

	if ct, ok := req.Headers["Content-Type"]; ok {
		req.ContentType = ct
	} else if ct, ok := req.Headers["content-type"]; ok {
		req.ContentType = ct
	}

	return req, nil
}

func parseCurlCommand(curlStr string) (*ParsedRequest, error) {
	req := &ParsedRequest{
		Headers: make(map[string]string),
		Raw:     curlStr,
	}

	urlRegex := regexp.MustCompile(`'([^']+)'|"([^"]+)"|(https?://\S+)`)
	urlMatches := urlRegex.FindAllStringSubmatch(curlStr, -1)

	var targetURL string
	for _, match := range urlMatches {
		for _, g := range match[1:] {
			if g != "" {
				if strings.HasPrefix(g, "http://") || strings.HasPrefix(g, "https://") {
					targetURL = g
					break
				}
			}
		}
		if targetURL != "" {
			break
		}
	}

	if targetURL == "" {
		return nil, fmt.Errorf("failed to parse URL from curl command")
	}
	req.URL = targetURL

	parsedURL, err := url.Parse(targetURL)
	if err == nil {
		req.Headers["Host"] = parsedURL.Host
	}

	methodRegex := regexp.MustCompile(`-X\s+(\S+)`)
	if m := methodRegex.FindStringSubmatch(curlStr); len(m) > 1 {
		req.Method = m[1]
	} else if strings.Contains(curlStr, "--request") {
		reqRegex := regexp.MustCompile(`--request\s+(\S+)`)
		if m := reqRegex.FindStringSubmatch(curlStr); len(m) > 1 {
			req.Method = m[1]
		}
	} else {
		req.Method = "GET"
	}

	headerRegex := regexp.MustCompile(`-H\s+['"]([^'"]+)['"]`)
	headers := headerRegex.FindAllStringSubmatch(curlStr, -1)
	for _, h := range headers {
		if len(h) > 1 {
			parts := strings.SplitN(h[1], ":", 2)
			if len(parts) == 2 {
				req.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	dataRegex := regexp.MustCompile(`--data(-raw)?\s+`)
	dataIdx := dataRegex.FindStringIndex(curlStr)

	dRegex := regexp.MustCompile(`-d\s+`)
	dIdx := dRegex.FindStringIndex(curlStr)

	var bodyStr string
	searchIdx := -1

	if dataIdx != nil && (dIdx == nil || dataIdx[0] < dIdx[0]) {
		searchIdx = dataIdx[1]
	} else if dIdx != nil {
		searchIdx = dIdx[1]
	}

	if searchIdx >= 0 {
		afterD := strings.TrimSpace(curlStr[searchIdx:])
		if len(afterD) > 0 {
			var quote byte
			if afterD[0] == '\'' || afterD[0] == '"' {
				quote = afterD[0]
				afterD = afterD[1:]
			}

			if quote > 0 {
				if endIdx := strings.Index(afterD, string(quote)); endIdx != -1 {
					bodyStr = afterD[:endIdx]
				}
			} else {
				parts := strings.Fields(afterD)
				if len(parts) > 0 {
					bodyStr = parts[0]
				}
			}

			if bodyStr != "" {
				req.Body = bodyStr
				if req.Method == "GET" {
					req.Method = "POST"
				}
			}
		}
	}

	if ct, ok := req.Headers["Content-Type"]; ok {
		req.ContentType = ct
	} else if ct, ok := req.Headers["content-type"]; ok {
		req.ContentType = ct
	} else if req.Body != "" {
		if strings.HasPrefix(req.Body, "{") || strings.HasPrefix(req.Body, "[") {
			req.ContentType = "application/json"
		} else {
			req.ContentType = "application/x-www-form-urlencoded"
		}
	}

	return req, nil
}

func isJSONFormat(body string) bool {
	trimmed := strings.TrimSpace(body)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func isFormFormat(body string) bool {
	trimmed := strings.TrimSpace(body)
	return strings.Contains(trimmed, "=") && !strings.Contains(trimmed, "{")
}
