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

func RequestFuzzStart(reqFile string, thread int, debug int, targetIDs []string) SheetData {
	result := SheetData{
		Name:    "Request Fuzz 测试",
		Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"},
	}

	fmt.Println(Blue("[+] Request Fuzz 开始测试"))

	parsedReq, err := ParseRequest(reqFile)
	if err != nil {
		fmt.Printf(Red("[-] 解析请求文件失败: %s\n"), err)
		return result
	}

	fmt.Printf(Green("[+] 成功解析请求: %s %s\n"), parsedReq.Method, parsedReq.URL)
	if parsedReq.Body != "" {
		fmt.Printf(Blue("[+] 请求 Body: %s\n"), truncateStr(parsedReq.Body, 100))
	}

	variants := GenerateAllVariants(parsedReq)
	if len(variants) == 0 {
		fmt.Println(Yellow("[!] 未生成任何变异 payload，请检查请求格式是否支持"))
		return result
	}

	fmt.Printf(Blue("[+] 共生成 %d 个变异 payload\n"), len(variants))

	resp, err := sendOriginalRequest(parsedReq)
	if err != nil {
		fmt.Printf(Red("[-] 发送原始请求失败: %s\n"), err)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf(Red("[-] 读取原始响应失败: %s\n"), err)
		return result
	}

	origCode := resp.StatusCode
	origLen := len(body)

	fmt.Printf(Green("[+] 原始请求响应: code=%d len=%d\n"), origCode, origLen)

	baseline := Baseline{Code: origCode, Len: origLen}
	ctx := ClassifyContext{
		Auth:   baseline,
		NoAuth: Baseline{},
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)
	mu := &sync.Mutex{}
	var exportData [][]string
	seen := make(map[string]bool)
	var completed int64

	for _, variant := range variants {
		wg.Add(1)
		go func(variant Variant) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			mutatedURL, headers, body := BuildMutatedRequest(parsedReq, &variant)

			var req *http.Request
			var err error

			if body != "" && body != parsedReq.Body {
				req, err = http.NewRequest(parsedReq.Method, mutatedURL, bytes.NewBufferString(body))
			} else {
				req, err = http.NewRequest(parsedReq.Method, mutatedURL, nil)
			}

			if err != nil {
				mu.Lock()
				fmt.Printf(Yellow("[!] %s 创建请求失败: %s\n"), variant.Name, err)
				mu.Unlock()
				return
			}

			for k, v := range headers {
				req.Header.Set(k, v)
			}

			if host, ok := headers["Host"]; ok {
				req.Host = host
			}

			resp, err := DoWithRetry(req)
			current := atomic.AddInt64(&completed, 1)
			if err != nil {
				if debug == 1 {
					mu.Lock()
					fmt.Printf(Yellow("[!] %s 请求失败 [%d/%d]: %s\n"), variant.Name, current, len(variants), err)
					mu.Unlock()
				}
				return
			}
			defer resp.Body.Close()

			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			newCode := resp.StatusCode
			newLen := len(respBody)

			meta := ExtractResponseMeta(resp, respBody)
			classification := ClassifyResult(ctx, newCode, newLen, meta)

			isDiff := (newLen != origLen || newCode != origCode) && newCode != 404

			mu.Lock()
			defer mu.Unlock()

			if current%50 == 0 || int(current) == len(variants) {
				fmt.Printf(Blue("[*] Request Fuzz 进度: [%d/%d]\n"), current, len(variants))
			}

			curlCmd := buildFuzzCurl(parsedReq, &variant, mutatedURL, headers, body)

			if debug == 1 {
				fmt.Printf(Green("[+] %s: code=%d len=%d → %s\n"), variant.Name, newCode, newLen, classification)
				key := fmt.Sprintf("%s|%d|%d", variant.Name, newLen, newCode)
				if !seen[key] {
					seen[key] = true
					exportData = append(exportData, []string{
						variant.Name,
						mutatedURL,
						fmt.Sprintf("%d", newLen),
						fmt.Sprintf("%d", newCode),
						classification,
						curlCmd,
					})
				}
			} else if isDiff {
				fmt.Printf(Green("[+] %s: code=%d len=%d → %s\n"), variant.Name, newCode, newLen, classification)
				key := fmt.Sprintf("%s|%d|%d", variant.Name, newLen, newCode)
				if !seen[key] {
					seen[key] = true
					exportData = append(exportData, []string{
						variant.Name,
						mutatedURL,
						fmt.Sprintf("%d", newLen),
						fmt.Sprintf("%d", newCode),
						classification,
						curlCmd,
					})
				}
			}
		}(variant)
	}

	wg.Wait()

	result.Data = exportData
	result.TotalPayloads = len(variants)

	fmt.Printf(Blue("[+] Request Fuzz 阶段完成: %d 个 payload 中 %d 个有响应差异\n"), len(variants), len(exportData))

	return result
}

func sendOriginalRequest(req *ParsedRequest) (*http.Response, error) {
	var body io.Reader
	if req.Body != "" {
		body = bytes.NewBufferString(req.Body)
	}

	httpReq, err := http.NewRequest(req.Method, req.URL, body)
	if err != nil {
		return nil, err
	}

	for k, v := range req.Headers {
		if k != "Host" {
			httpReq.Header.Set(k, v)
		} else {
			httpReq.Host = v
		}
	}

	if req.ContentType != "" {
		if _, ok := req.Headers["Content-Type"]; !ok {
			httpReq.Header.Set("Content-Type", req.ContentType)
		}
	}

	return DoWithRetry(httpReq)
}

func buildFuzzCurl(orig *ParsedRequest, variant *Variant, mutatedURL string, headers map[string]string, body string) string {
	var parts []string
	parts = append(parts, "curl -k -v")

	if orig.Method != "GET" {
		parts = append(parts, fmt.Sprintf("-X %s", orig.Method))
	}

	for k, v := range headers {
		if k == "Host" {
			continue
		}
		parts = append(parts, fmt.Sprintf("-H \"%s: %s\"", k, v))
	}

	if body != "" && body != orig.Body {
		parts = append(parts, fmt.Sprintf("-d '%s'", body))
	}

	parts = append(parts, fmt.Sprintf("\"%s\"", mutatedURL))

	return strings.Join(parts, " ")
}
