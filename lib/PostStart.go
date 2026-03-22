package lib

import (
	"bytes"
	"fmt"
	"io"
	"noauth/poc"
	"strings"
	"sync"
	"sync/atomic"
)

func PostStart(url, noauth, auth string, thread int, debug int, noauthBaseline Baseline) SheetData {

	result := SheetData{
		Name:    "POST 测试",
		Headers: []string{"URL", "响应长度", "状态码", "请求类型", "判定"},
	}

	fmt.Println(Blue("[+] POST(Form-data 和 Json) poc 开始测试"))

	if strings.HasSuffix(url, "/") {
		url = strings.TrimSuffix(url, "/")
	}

	resp, err := HttpClient.Post(url+auth, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte{}))
	respjson, errjson := HttpClient.Post(url+auth, "application/json", bytes.NewBuffer([]byte("{}")))

	if errjson != nil {
		fmt.Printf(Red("[-] POST-Json 请求原始鉴权接口失败: %s\n"), errjson)
		return result
	}

	if err != nil {
		fmt.Printf(Red("[-] POST 请求原始鉴权接口失败: %s\n"), err)
		return result
	}
	defer resp.Body.Close()
	defer respjson.Body.Close()

	body, err := io.ReadAll(resp.Body)
	bodyjson, errjson := io.ReadAll(respjson.Body)
	if errjson != nil {
		fmt.Printf(Red("[-] 读取 Json 响应体失败: %s\n"), errjson)
		return result
	}

	if err != nil {
		fmt.Printf(Red("[-] 读取响应体失败: %s\n"), err)
		return result
	}

	if strings.Contains(string(body), url+auth) {
		body = []byte(strings.Replace(string(body), url+auth, "", 1))
	}
	if strings.Contains(string(bodyjson), url+auth) {
		bodyjson = []byte(strings.Replace(string(bodyjson), url+auth, "", 1))
	}

	len1 := len(body)
	origCode := resp.StatusCode
	fmt.Printf(Green("[+] 原始鉴权接口(POST-Form) %s 的响应长度: len=%d code=%d\n"), url+auth, len1, origCode)

	lenjson := len(bodyjson)
	origCodeJson := respjson.StatusCode
	fmt.Printf(Green("[+] 原始鉴权接口(POST-Json) %s 的响应长度: len=%d code=%d\n"), url+auth, lenjson, origCodeJson)

	// 构建双基线判定上下文（Form 和 Json 各自有独立的 Auth 基线）
	ctxForm := ClassifyContext{
		Auth:   Baseline{Code: origCode, Len: len1},
		NoAuth: noauthBaseline,
	}
	ctxJson := ClassifyContext{
		Auth:   Baseline{Code: origCodeJson, Len: lenjson},
		NoAuth: noauthBaseline,
	}

	list := poc.Summary(noauth, auth)
	total := len(list)
	fmt.Printf(Blue("[+] 共生成 %d 个 POST payload\n"), total)

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

			resp, err := HttpClient.Post(url+value, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte{}))
			respjson, errjson := HttpClient.Post(url+value, "application/json", bytes.NewBuffer([]byte("{}")))

			current := atomic.AddInt64(&completed, 1)

			if err != nil {
				if debug == 1 {
					mu.Lock()
					fmt.Printf(Yellow("[!] POST 请求失败 [%d/%d] %s: %s\n"), current, total, url+value, err)
					mu.Unlock()
				}
				return
			}
			if errjson != nil {
				if debug == 1 {
					mu.Lock()
					fmt.Printf(Yellow("[!] POST-Json 请求失败 [%d/%d] %s: %s\n"), current, total, url+value, errjson)
					mu.Unlock()
				}
				return
			}
			defer respjson.Body.Close()
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			bodyjson, errjson := io.ReadAll(respjson.Body)

			if err != nil {
				return
			}

			if errjson != nil {
				return
			}

			// 提取响应元数据
			formSnippet := truncateBody(body, 4096)
			formLocation := resp.Header.Get("Location")
			jsonSnippet := truncateBody(bodyjson, 4096)
			jsonLocation := respjson.Header.Get("Location")

			if strings.Contains(string(body), url+value) {
				body = []byte(strings.Replace(string(body), url+value, "", 1))
			}

			len2 := len(body)
			code := resp.StatusCode
			formClassify := ClassifyResult(ctxForm, code, len2, formSnippet, formLocation)

			if strings.Contains(string(bodyjson), url+value) {
				bodyjson = []byte(strings.Replace(string(bodyjson), url+value, "", 1))
			}

			len2json := len(bodyjson)
			codeJson := respjson.StatusCode
			jsonClassify := ClassifyResult(ctxJson, codeJson, len2json, jsonSnippet, jsonLocation)

			mu.Lock()
			defer mu.Unlock()

			// 进度显示
			if current%50 == 0 || int(current) == total {
				fmt.Printf(Blue("[*] POST 进度: [%d/%d]\n"), current, total)
			}

			if debug == 1 {
				fmt.Printf(Green("[+] POST-Form: %s len=%d code=%d → %s\n"), url+value, len2, code, formClassify)
				key := fmt.Sprintf("POST-Form|%s|%d|%d", url+value, len2, code)
				if !seen[key] {
					seen[key] = true
					exportData = append(exportData, []string{
						url + value,
						fmt.Sprintf("%d", len2),
						fmt.Sprintf("%d", code),
						"POST-Form",
						formClassify,
					})
				}
				if len2json != len2 {
					fmt.Printf(Green("[+] POST-Json: %s len=%d code=%d → %s\n"), url+value, len2json, codeJson, jsonClassify)
					keyJson := fmt.Sprintf("POST-Json|%s|%d|%d", url+value, len2json, codeJson)
					if !seen[keyJson] {
						seen[keyJson] = true
						exportData = append(exportData, []string{
							url + value,
							fmt.Sprintf("%d", len2json),
							fmt.Sprintf("%d", codeJson),
							"POST-Json",
							jsonClassify,
						})
					}
				}
			} else {
				if (len2 != len1 || code != origCode) && code != 404 {
					fmt.Printf(Green("[+] POST-Form: 响应差异 %s len=%d code=%d → %s\n"), url+value, len2, code, formClassify)
					key := fmt.Sprintf("POST-Form|%s|%d|%d", url+value, len2, code)
					if !seen[key] {
						seen[key] = true
						exportData = append(exportData, []string{
							url + value,
							fmt.Sprintf("%d", len2),
							fmt.Sprintf("%d", code),
							"POST-Form",
							formClassify,
						})
					}
				}

				if (len2json != lenjson || codeJson != origCodeJson) && len2json != len2 && codeJson != 404 {
					fmt.Printf(Green("[+] POST-Json: 响应差异 %s len=%d code=%d → %s\n"), url+value, len2json, codeJson, jsonClassify)
					keyJson := fmt.Sprintf("POST-Json|%s|%d|%d", url+value, len2json, codeJson)
					if !seen[keyJson] {
						seen[keyJson] = true
						exportData = append(exportData, []string{
							url + value,
							fmt.Sprintf("%d", len2json),
							fmt.Sprintf("%d", codeJson),
							"POST-Json",
							jsonClassify,
						})
					}
				}
			}
		}(value)
	}

	wg.Wait()

	result.Data = exportData
	result.TotalPayloads = total
	return result
}
