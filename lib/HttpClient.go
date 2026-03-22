package lib

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
)

// HttpClient 全局共享的 HTTP 客户端配置
var HttpClient *http.Client

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
