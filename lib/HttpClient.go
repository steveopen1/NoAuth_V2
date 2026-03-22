package lib

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HttpClient 全局共享的 HTTP 客户端配置
var HttpClient *http.Client

// maxRetries 瞬态错误的最大重试次数
const maxRetries = 2

// InitHTTPClient 初始化共享 HTTP 客户端
// - 支持代理
// - 跳过 TLS 证书验证（安全测试场景常见自签名证书）
// - 设置超时
// - 禁止自动跟随重定向（302 本身是有意义的鉴权信号）
func InitHTTPClient(proxyURL string, timeout int) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     30 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	// 设置代理
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxy)
		}
	}

	HttpClient = &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
		// 禁止自动跟随重定向，返回原始响应
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// DoWithRetry 执行 HTTP 请求，对瞬态错误自动重试
// 瞬态错误: 超时、连接重置、连接拒绝、429 (Too Many Requests)
// 重试策略: 最多 2 次重试，退避 500ms → 1500ms
func DoWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// 指数退避: 500ms, 1500ms
			backoff := time.Duration(500*(1<<(attempt-1))) * time.Millisecond
			time.Sleep(backoff)

			// 需要重置 Body（如果有的话）
			if req.GetBody != nil {
				body, err := req.GetBody()
				if err == nil {
					req.Body = body
				}
			}
		}

		resp, err := HttpClient.Do(req)
		if err == nil {
			// 429 Too Many Requests: 服务端限速，重试
			if resp.StatusCode == 429 && attempt < maxRetries {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				lastErr = fmt.Errorf("HTTP 429 Too Many Requests")
				continue
			}
			return resp, nil
		}

		// 判断是否为瞬态错误
		if !isTransientError(err) {
			return nil, err
		}
		lastErr = err
	}
	return nil, fmt.Errorf("重试 %d 次后仍然失败: %w", maxRetries, lastErr)
}

// isTransientError 判断错误是否为可重试的瞬态错误
func isTransientError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	transientPatterns := []string{
		"timeout",
		"connection reset",
		"connection refused",
		"broken pipe",
		"eof",
		"tls handshake timeout",
		"no such host", // DNS 临时失败
	}
	for _, pattern := range transientPatterns {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}
	// net.Error 接口的 Timeout() 判断
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		return true
	}
	return false
}

// maxResponseBody 响应体最大读取限制 (10MB)
const maxResponseBody = 10 * 1024 * 1024

// LimitedReadAll 有限制地读取响应体，防止大响应撑爆内存
func LimitedReadAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxResponseBody))
}
