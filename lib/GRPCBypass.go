package lib

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type GRPCBypassCase struct {
	method      string
	url         string
	headers     map[string]string
	body        string
	contentType string
	protocol    string
	desc        string
}

func BuildGRPCBypassCases(baseURL string) []GRPCBypassCase {
	var cases []GRPCBypassCase

	grpcEndpoints := []string{
		"/grpc/",
		"/grpc.api/",
		"/api/grpc/",
		"/h2c/",
		"/h2c.api/",
		"/grpc.v1/",
		"/api/v1/grpc/",
		"/h2",
		"/grpc-web/",
	}

	for _, endpoint := range grpcEndpoints {
		fullURL := strings.TrimSuffix(baseURL, "/") + endpoint

		contentTypes := []string{
			"application/grpc",
			"application/grpc+json",
			"application/grpc+proto",
			"application/proto",
			"application/octet-stream",
		}
		for _, ct := range contentTypes {
			cases = append(cases, GRPCBypassCase{
				method:   "POST",
				url:      fullURL,
				headers:  map[string]string{"Content-Type": ct},
				body:     "",
				protocol: "h2c",
				desc:     fmt.Sprintf("gRPC[Content-Type: %s]", ct),
			})
		}

		methods := []string{"POST", "GET", "PUT", "DELETE", "PATCH", "PRI"}
		for _, method := range methods {
			cases = append(cases, GRPCBypassCase{
				method:   method,
				url:      fullURL,
				headers:  map[string]string{"Content-Type": "application/grpc"},
				body:     "",
				protocol: "h2c",
				desc:     fmt.Sprintf("gRPC[method: %s]", method),
			})
		}

		cases = append(cases, GRPCBypassCase{
			method:   "PRI",
			url:      fullURL,
			headers:  map[string]string{},
			body:     "",
			protocol: "h2c",
			desc:     "gRPC[PRI method HTTP/2]",
		})
	}

	protocolUpgrade := []string{
		"h2c",
		"h2",
		"HTTP/2",
		"HTTP/2.0",
	}
	for _, upgrade := range protocolUpgrade {
		cases = append(cases, GRPCBypassCase{
			method:   "GET",
			url:      baseURL,
			headers:  map[string]string{"Upgrade": upgrade},
			body:     "",
			protocol: "http/1.1",
			desc:     fmt.Sprintf("HTTP2[Upgrade: %s]", upgrade),
		})
	}

	http2SettingsValues := []string{
		"AAMAAABkAARAAAAAAAIAAAAA==",
		"AAUAAABkAARAAAAAAAIAAAAA==",
		"AAMAAABkAARAAAAAAAGAAAAAQ==",
		"",
	}
	for i, settings := range http2SettingsValues {
		headers := map[string]string{}
		if settings != "" {
			headers["HTTP2-Settings"] = settings
		}
		cases = append(cases, GRPCBypassCase{
			method:   "GET",
			url:      baseURL,
			headers:  headers,
			body:     "",
			protocol: "http/1.1",
			desc:     fmt.Sprintf("HTTP2[HTTP2-Settings %d]", i+1),
		})
	}

	teHeaderValues := []string{"trailers", "trailers, deflate", "trailers, gzip", "deflate, trailers"}
	for _, te := range teHeaderValues {
		cases = append(cases, GRPCBypassCase{
			method:   "POST",
			url:      baseURL,
			headers:  map[string]string{"TE": te, "Content-Type": "application/grpc"},
			body:     "",
			protocol: "h2c",
			desc:     fmt.Sprintf("gRPC[TE: %s]", te),
		})
	}

	cases = append(cases, GRPCBypassCase{
		method:   "GET",
		url:      baseURL,
		headers:  map[string]string{"Upgrade": "h2c", "HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA=="},
		body:     "",
		protocol: "http/1.1",
		desc:     "HTTP2[Upgrade + HTTP2-Settings combo]",
	})

	cases = append(cases, buildHTTP2伪装Cases(baseURL)...)

	return cases
}

func buildHTTP2伪装Cases(baseURL string) []GRPCBypassCase {
	var cases []GRPCBypassCase

	http2PriorKnowledge := []struct {
		method      string
		url         string
		headers     map[string]string
		body        string
		contentType string
		desc        string
	}{
		{
			method: "GET",
			url:    baseURL + "/",
			headers: map[string]string{
				":method":              "GET",
				":scheme":              "https",
				":authority":           "localhost",
				":path":                "/",
				"user-agent":           "grpc-go/1.0.0",
				"grpc-accept-encoding": "gzip",
			},
			desc: "HTTP2[PRI * HTTP/2 with PRI method]",
		},
		{
			method: "POST",
			url:    baseURL + "/api.Service/ListUsers",
			headers: map[string]string{
				":method":      "POST",
				":scheme":      "https",
				":authority":   "localhost",
				":path":        "/api.Service/ListUsers",
				"content-type": "application/grpc",
				"te":           "trailers",
			},
			body: "",
			desc: "gRPC[ListUsers via HTTP2 PRI]",
		},
		{
			method: "POST",
			url:    baseURL + "/api.Service/GetUser",
			headers: map[string]string{
				":method":      "POST",
				":scheme":      "https",
				":authority":   "localhost",
				":path":        "/api.Service/GetUser",
				"content-type": "application/grpc",
				"te":           "trailers",
			},
			body: createGrpcRequestPayload("/api.Service/GetUser", `{"user_id": "1"}`),
			desc: "gRPC[GetUser with payload]",
		},
	}

	for _, tc := range http2PriorKnowledge {
		cases = append(cases, GRPCBypassCase{
			method:      tc.method,
			url:         tc.url,
			headers:     tc.headers,
			body:        tc.body,
			contentType: tc.contentType,
			protocol:    "h2",
			desc:        tc.desc,
		})
	}

	return cases
}

func createGrpcRequestPayload(service, message string) string {
	serviceBytes := []byte(service)
	messageBytes := []byte(message)

	grpcFrame := new(bytes.Buffer)

	length := uint32(len(messageBytes))
	grpcFrame.Write([]byte{
		byte(length >> 24),
		byte(length >> 16),
		byte(length >> 8),
		byte(length),
	})

	grpcFrame.Write(serviceBytes)

	compressed, _ := gzipCompress(messageBytes)
	grpcFrame.Write(compressed)

	return base64.StdEncoding.EncodeToString(grpcFrame.Bytes())
}

func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return data, err
	}
	writer.Write(data)
	writer.Close()
	return buf.Bytes(), nil
}

type GRPCSecurityTest struct {
	targetService string
}

func NewGRPCSecurityTest(serviceName string) *GRPCSecurityTest {
	return &GRPCSecurityTest{targetService: serviceName}
}

func (g *GRPCSecurityTest) TestUnaryCall(endpoint, method, payload string) (int, string, error) {
	url := endpoint + "/" + g.targetService + "." + method

	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		return 0, "", err
	}

	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("te", "trailers")
	req.Header.Set("user-agent", "grpc-go-security-test/1.0")

	resp, err := HttpClient.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}

	return resp.StatusCode, string(body), nil
}

func (g *GRPCSecurityTest) TestServerReflection(endpoint string) (bool, []string) {
	var methods []string

	reflectionQuery := `{"jsonrpc":"2.0","method":"ServerReflection.ServerReflectionInfo","id":1}`
	statusCode, response, err := g.TestUnaryCall(endpoint, "grpc.reflection.v1.ServerReflection/ServerReflectionInfo", reflectionQuery)

	if err != nil || statusCode != 200 {
		return false, methods
	}

	if strings.Contains(response, "ListServices") || strings.Contains(response, "file_descriptor") {
		return true, []string{"ServerReflection", "ListServices", "file_descriptor"}
	}

	return false, methods
}

func DetectGRPCService(url string) bool {
	grpcTest := NewGRPCSecurityTest("test")

	endpoints := []string{
		"/",
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
		"/grpc.reflection.v1alpha.ServerReflection",
	}

	for _, endpoint := range endpoints {
		_, _, err := grpcTest.TestUnaryCall(url, endpoint, "{}")
		if err == nil {
			return true
		}
	}

	resp, err := http.NewRequest("PRI", url, nil)
	if err != nil {
		return false
	}
	grpcResp, err := HttpClient.Do(resp)
	if err == nil {
		grpcResp.Body.Close()
		if grpcResp.StatusCode != 405 {
			return true
		}
	}

	return false
}

type H2CBypassCase struct {
	method  string
	url     string
	headers map[string]string
	body    []byte
	desc    string
}

func BuildH2CBypassCases(baseURL string) []H2CBypassCase {
	var cases []H2CBypassCase

	h2cPaths := []string{
		"/h2c",
		"/h2c_push",
		"/h2c_stream",
	}

	for _, path := range h2cPaths {
		cases = append(cases, H2CBypassCase{
			method: "GET",
			url:    baseURL + path,
			headers: map[string]string{
				"Upgrade":        "h2c",
				"HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA==",
			},
			desc: fmt.Sprintf("H2C[Upgrade via %s]", path),
		})
	}

	cases = append(cases, H2CBypassCase{
		method: "POST",
		url:    baseURL,
		headers: map[string]string{
			"Upgrade":        "h2c",
			"HTTP2-Settings": "AAMAAABkAARAAAAAAAIAAAAA==",
			"Content-Type":   "application/json",
		},
		body: []byte(`{"test": "h2c_post"}`),
		desc: "H2C[POST with h2c upgrade]",
	})

	cases = append(cases, H2CBypassCase{
		method: "PRI",
		url:    baseURL,
		headers: map[string]string{
			":method":    "GET",
			":scheme":    "https",
			":authority": "localhost",
			":path":      "/",
		},
		desc: "H2C[PRI method HTTP/2 prior knowledge]",
	})

	return cases
}
