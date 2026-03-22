package lib

import (
	"fmt"
	"io"
	"noauth/poc"
	"strings"
	"sync"
	"sync/atomic"
)

func GetStart(url, noauth, auth string, thread int, debug int) (SheetData, int, int) {

	result := SheetData{
		Name:    "GET 测试",
		Headers: []string{"URL", "响应长度", "状态码", "判定"},
	}

	fmt.Println(Blue("[+] GET poc 开始测试"))

	if strings.HasSuffix(url, "/") {
		url = strings.TrimSuffix(url, "/")
	}

	resp, err := HttpClient.Get(url + auth)
	if err != nil {
		fmt.Printf(Red("[-] 请求原始鉴权接口失败: %s\n"), err)
		return result, 0, 0
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf(Red("[-] 读取响应体失败: %s\n"), err)
		return result, 0, 0
	}

	if strings.Contains(string(body), url+auth) {
		body = []byte(strings.Replace(string(body), url+auth, "", 1))
	}

	len1 := len(body)
	origCode := resp.StatusCode
	fmt.Printf(Green("[+] 原始鉴权接口 %s 的响应长度: len=%d code=%d\n"), url+auth, len1, origCode)

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

	for _, value := range list {
		wg.Add(1)
		go func(value string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			resp, err := HttpClient.Get(url + value)
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

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			if strings.Contains(string(body), url+value) {
				body = []byte(strings.Replace(string(body), url+value, "", 1))
			}

			len2 := len(body)
			code := resp.StatusCode

			mu.Lock()
			defer mu.Unlock()

			// 进度显示（每 50 个或最后一个时打印）
			if current%50 == 0 || int(current) == total {
				fmt.Printf(Blue("[*] GET 进度: [%d/%d]\n"), current, total)
			}

			if debug == 1 {
				fmt.Printf(Green("[+] GET: %s len=%d code=%d\n"), url+value, len2, code)
				key := fmt.Sprintf("GET|%s|%d|%d", url+value, len2, code)
				if !seen[key] {
					seen[key] = true
					exportData = append(exportData, []string{
						url + value,
						fmt.Sprintf("%d", len2),
						fmt.Sprintf("%d", code),
						classifyResult(len1, len2, origCode, code),
					})
				}
			} else if len2 != len1 && code != 404 {
				fmt.Printf(Green("[+] GET: 响应长度不一致 %s len=%d code=%d\n"), url+value, len2, code)
				key := fmt.Sprintf("GET|%s|%d|%d", url+value, len2, code)
				if !seen[key] {
					seen[key] = true
					exportData = append(exportData, []string{
						url + value,
						fmt.Sprintf("%d", len2),
						fmt.Sprintf("%d", code),
						classifyResult(len1, len2, origCode, code),
					})
				}
			}
		}(value)
	}

	wg.Wait()

	result.Data = exportData
	result.TotalPayloads = total
	return result, origCode, len1
}

// classifyResult 根据响应长度和状态码差异对结果进行初步分类
func classifyResult(origLen, newLen, origCode, newCode int) string {
	// 状态码为 200 且长度与原始不同，可能存在绕过
	if newCode == 200 && origCode != 200 {
		return "可能绕过"
	}
	// 状态码为 302/301 重定向
	if newCode == 302 || newCode == 301 {
		return "重定向"
	}
	// 状态码为 403
	if newCode == 403 {
		return "拒绝访问"
	}
	// 状态码为 200 且长度差异较大
	if newCode == 200 && origCode == 200 {
		diff := newLen - origLen
		if diff < 0 {
			diff = -diff
		}
		if diff > 100 {
			return "长度差异大"
		}
		return "长度差异小"
	}
	return fmt.Sprintf("状态码=%d", newCode)
}
