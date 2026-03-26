package lib

import (
	"fmt"
	"io"
	"net/http"
	"noauth/poc"
	"strings"
	"sync"
	"sync/atomic"
)

func GetStart(url, noauth, auth string, thread int, debug int, noauthBaseline Baseline) (SheetData, int, int, []string) {

	result := SheetData{
		Name:    "GET 测试",
		Headers: []string{"URL", "响应长度", "状态码", "判定", "复现命令"},
	}

	fmt.Println(Blue("[+] GET poc 开始测试"))

	if strings.HasSuffix(url, "/") {
		url = strings.TrimSuffix(url, "/")
	}

	resp, err := HttpClient.Get(url + auth)
	if err != nil {
		fmt.Printf(Red("[-] 请求原始鉴权接口失败: %s\n"), err)
		return result, 0, 0, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf(Red("[-] 读取响应体失败: %s\n"), err)
		return result, 0, 0, nil
	}

	len1 := len(body)
	origCode := resp.StatusCode
	fmt.Printf(Green("[+] 原始鉴权接口 %s 的响应长度: len=%d code=%d\n"), url+auth, len1, origCode)

	authMeta := ExtractResponseMeta(resp, body)

	// 构建双基线判定上下文
	ctx := ClassifyContext{
		Auth:           Baseline{Code: origCode, Len: len1, Body: sampleBody(body, 8192), Meta: authMeta},
		NoAuth:         noauthBaseline,
		BaselineTimeMs: authMeta.ResponseTimeMs,
	}

	list := poc.Summary(noauth, auth)
	total := len(list)
	fmt.Printf(Blue("[+] 共生成 %d 个 GET payload\n"), total)

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)
	mu := &sync.Mutex{}

	// 用于收集导出数据
	var exportData [][]string
	// 用于去重
	seen := make(map[string]bool)
	// 进度计数器
	var completed int64
	// 收集命中的 payload 路径（供 POST 阶段复用）
	hitPayloadSet := make(map[string]bool)

	for _, value := range list {
		wg.Add(1)
		go func(value string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			req, err := http.NewRequest("GET", url+value, nil)
			if err != nil {
				return
			}
			resp, err := DoWithRetry(req)
			current := atomic.AddInt64(&completed, 1)
			if err != nil {
				if debug == 1 {
					mu.Lock()
					fmt.Printf(Yellow("[!] GET 请求失败 [%d/%d] %s: %s\n"), current, total, url+value, err)
					mu.Unlock()
				}
				return
			}
			defer resp.Body.Close()

			body, err := LimitedReadAll(resp.Body)
			if err != nil {
				return
			}

			meta := ExtractResponseMeta(resp, body)

			if strings.Contains(meta.ContentType, "text/html") {
				if strings.Contains(string(body), url+value) {
					body = []byte(strings.Replace(string(body), url+value, "", 1))
				}
			}

			len2 := len(body)
			code := resp.StatusCode
			classification, color := ClassifyResultWithColor(ctx, code, len2, meta)

			isHit := (len2 != len1 || code != origCode) && code != 404

			mu.Lock()
			// 记录命中的 payload（无论 debug 模式）
			if isHit {
				hitPayloadSet[value] = true
			}

			// 进度显示（每 50 个或最后一个时打印）
			if current%50 == 0 || int(current) == total {
				fmt.Printf(Blue("[*] GET 进度: [%d/%d]\n"), current, total)
			}

			// 根据置信度级别使用不同颜色输出
			hitPrefix := Green
			if color == "red" {
				hitPrefix = Red
			} else if color == "yellow" {
				hitPrefix = Yellow
			} else if color == "cyan" {
				hitPrefix = Cyan
			}

			if debug == 1 {
				fmt.Printf(hitPrefix("[+] GET: %s len=%d code=%d → %s\n"), url+value, len2, code, classification)
				key := fmt.Sprintf("GET|%s|%d|%d", url+value, len2, code)
				if !seen[key] {
					seen[key] = true
					curl := fmt.Sprintf("curl -k -v \"%s\"", url+value)
					exportData = append(exportData, []string{
						url + value,
						fmt.Sprintf("%d", len2),
						fmt.Sprintf("%d", code),
						classification,
						curl,
					})
				}
			} else if isHit {
				fmt.Printf(hitPrefix("[+] GET: 响应差异 %s len=%d code=%d → %s\n"), url+value, len2, code, classification)
				key := fmt.Sprintf("GET|%s|%d|%d", url+value, len2, code)
				if !seen[key] {
					seen[key] = true
					curl := fmt.Sprintf("curl -k -v \"%s\"", url+value)
					exportData = append(exportData, []string{
						url + value,
						fmt.Sprintf("%d", len2),
						fmt.Sprintf("%d", code),
						classification,
						curl,
					})
				}
			}
			mu.Unlock()
		}(value)
	}

	wg.Wait()

	// 提取命中的 payload 列表
	var hitPayloads []string
	for v := range hitPayloadSet {
		hitPayloads = append(hitPayloads, v)
	}

	fmt.Printf(Blue("[+] GET 阶段完成: %d 个 payload 中 %d 个命中\n"), total, len(hitPayloads))

	result.Data = exportData
	result.TotalPayloads = total
	return result, origCode, len1, hitPayloads
}
