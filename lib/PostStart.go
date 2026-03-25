package lib

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"noauth/poc"
	"strings"
	"sync"
	"sync/atomic"
)

// postProbeCount POST 探针数量（用于检测 POST 是否与 GET 行为一致）
const postProbeCount = 5

func PostStart(url, noauth, auth string, thread int, debug int, noauthBaseline Baseline, getHitPayloads []string) SheetData {

	result := SheetData{
		Name:    "POST 测试",
		Headers: []string{"URL", "响应长度", "状态码", "请求类型", "判定", "复现命令"},
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

	// 确定 POST 测试的 payload 列表
	allPayloads := poc.Summary(noauth, auth)
	testList := selectPostPayloads(url, allPayloads, getHitPayloads, len1, origCode, lenjson, origCodeJson, thread, debug)

	total := len(testList)
	if total == 0 {
		fmt.Println(Blue("[*] POST 阶段: 无需测试的 payload，跳过"))
		result.TotalPayloads = 0
		return result
	}

	fmt.Printf(Blue("[+] POST 将测试 %d 个 payload（全量 %d 个）\n"), total, len(allPayloads))

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)
	mu := &sync.Mutex{}

	// 用于收集导出数据
	var exportData [][]string
	// 用于去重
	seen := make(map[string]bool)
	// 进度计数器
	var completed int64

	for _, value := range testList {
		wg.Add(1)
		go func(value string) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			reqForm, err := http.NewRequest("POST", url+value, bytes.NewBuffer([]byte{}))
			if err != nil {
				return
			}
			reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			reqForm.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewBuffer([]byte{})), nil
			}

			reqJson, err := http.NewRequest("POST", url+value, bytes.NewBuffer([]byte("{}")))
			if err != nil {
				return
			}
			reqJson.Header.Set("Content-Type", "application/json")
			reqJson.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(bytes.NewBuffer([]byte("{}"))), nil
			}

			resp, err := DoWithRetry(reqForm)
			respjson, errjson := DoWithRetry(reqJson)

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
				if resp != nil {
					resp.Body.Close()
				}
				return
			}
			defer respjson.Body.Close()
			defer resp.Body.Close()

			body, err := LimitedReadAll(resp.Body)
			bodyjson, errjson := LimitedReadAll(respjson.Body)

			if err != nil {
				return
			}

			if errjson != nil {
				return
			}

			// 提取响应元数据
			formMeta := ExtractResponseMeta(resp, body)
			jsonMeta := ExtractResponseMeta(respjson, bodyjson)

			if strings.Contains(formMeta.ContentType, "text/html") {
				if strings.Contains(string(body), url+value) {
					body = []byte(strings.Replace(string(body), url+value, "", 1))
				}
			}

			len2 := len(body)
			code := resp.StatusCode
			formClassify := ClassifyResult(ctxForm, code, len2, formMeta)

			if strings.Contains(jsonMeta.ContentType, "text/html") {
				if strings.Contains(string(bodyjson), url+value) {
					bodyjson = []byte(strings.Replace(string(bodyjson), url+value, "", 1))
				}
			}

			len2json := len(bodyjson)
			codeJson := respjson.StatusCode
			jsonClassify := ClassifyResult(ctxJson, codeJson, len2json, jsonMeta)

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
					curlForm := fmt.Sprintf("curl -k -v -X POST -H \"Content-Type: application/x-www-form-urlencoded\" \"%s\"", url+value)
					exportData = append(exportData, []string{
						url + value,
						fmt.Sprintf("%d", len2),
						fmt.Sprintf("%d", code),
						"POST-Form",
						formClassify,
						curlForm,
					})
				}
				if len2json != len2 {
					fmt.Printf(Green("[+] POST-Json: %s len=%d code=%d → %s\n"), url+value, len2json, codeJson, jsonClassify)
					keyJson := fmt.Sprintf("POST-Json|%s|%d|%d", url+value, len2json, codeJson)
					if !seen[keyJson] {
						seen[keyJson] = true
						curlJson := fmt.Sprintf("curl -k -v -X POST -H \"Content-Type: application/json\" -d '{}' \"%s\"", url+value)
						exportData = append(exportData, []string{
							url + value,
							fmt.Sprintf("%d", len2json),
							fmt.Sprintf("%d", codeJson),
							"POST-Json",
							jsonClassify,
							curlJson,
						})
					}
				}
			} else {
				if (len2 != len1 || code != origCode) && code != 404 {
					fmt.Printf(Green("[+] POST-Form: 响应差异 %s len=%d code=%d → %s\n"), url+value, len2, code, formClassify)
					key := fmt.Sprintf("POST-Form|%s|%d|%d", url+value, len2, code)
					if !seen[key] {
						seen[key] = true
						curlForm := fmt.Sprintf("curl -k -v -X POST -H \"Content-Type: application/x-www-form-urlencoded\" \"%s\"", url+value)
						exportData = append(exportData, []string{
							url + value,
							fmt.Sprintf("%d", len2),
							fmt.Sprintf("%d", code),
							"POST-Form",
							formClassify,
							curlForm,
						})
					}
				}

				if (len2json != lenjson || codeJson != origCodeJson) && len2json != len2 && codeJson != 404 {
					fmt.Printf(Green("[+] POST-Json: 响应差异 %s len=%d code=%d → %s\n"), url+value, len2json, codeJson, jsonClassify)
					keyJson := fmt.Sprintf("POST-Json|%s|%d|%d", url+value, len2json, codeJson)
					if !seen[keyJson] {
						seen[keyJson] = true
						curlJson := fmt.Sprintf("curl -k -v -X POST -H \"Content-Type: application/json\" -d '{}' \"%s\"", url+value)
						exportData = append(exportData, []string{
							url + value,
							fmt.Sprintf("%d", len2json),
							fmt.Sprintf("%d", codeJson),
							"POST-Json",
							jsonClassify,
							curlJson,
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

// selectPostPayloads 智能选择 POST 阶段需要测试的 payload
//
// 策略:
//   - debug 模式: 测试全部 payload（保持完整输出）
//   - GET 有命中: 只测试 GET 命中的 payload（路径绕过已在 GET 阶段验证，POST 仅做方法确认）
//   - GET 无命中: 发送少量探针检测 POST 是否与 GET 行为不同
//     -- 探针全部匹配基线 → POST 行为一致，跳过全量测试
//     -- 探针有差异 → POST 有独立 ACL，回退到全量测试
func selectPostPayloads(url string, allPayloads, getHitPayloads []string,
	formBaseLen, formBaseCode, jsonBaseLen, jsonBaseCode, thread, debug int) []string {

	// debug 模式: 全量
	if debug == 1 {
		fmt.Println(Blue("[*] POST debug 模式: 测试全部 payload"))
		return allPayloads
	}

	// GET 有命中: 只测试命中的 payload
	if len(getHitPayloads) > 0 {
		fmt.Printf(Blue("[+] POST 智能优化: GET 阶段 %d 个 payload 命中，仅对这些进行 POST 验证\n"), len(getHitPayloads))
		return getHitPayloads
	}

	// GET 无命中: 发送探针检测 POST 是否有独立行为
	fmt.Printf(Blue("[+] POST 智能优化: GET 阶段无命中，发送 %d 个 POST 探针检测...\n"), postProbeCount)

	probeCount := postProbeCount
	if probeCount > len(allPayloads) {
		probeCount = len(allPayloads)
	}

	// 从不同位置取样（首部、中间、尾部），提高探针代表性
	probeIndices := spreadSample(len(allPayloads), probeCount)
	probeHit := false

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)
	mu := &sync.Mutex{}

	for _, idx := range probeIndices {
		wg.Add(1)
		go func(value string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			resp, err := HttpClient.Post(url+value, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte{}))
			if err != nil {
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

			newLen := len(body)
			newCode := resp.StatusCode

			// 与 POST-Form 基线比较
			if (newLen != formBaseLen || newCode != formBaseCode) && newCode != 404 {
				mu.Lock()
				probeHit = true
				mu.Unlock()
			}
		}(allPayloads[idx])
	}
	wg.Wait()

	if probeHit {
		// POST 有独立行为，回退到全量
		fmt.Println(Yellow("[!] POST 探针检测到差异响应，回退到全量 POST 测试"))
		return allPayloads
	}

	// POST 行为与 GET 一致，跳过
	fmt.Println(Blue("[*] POST 探针无差异: POST 行为与 GET 一致，跳过全量测试（节省 " +
		fmt.Sprintf("%d", len(allPayloads)*2) + " 个请求）"))
	return nil
}

// spreadSample 从 [0, total) 中均匀取 count 个索引
func spreadSample(total, count int) []int {
	if count >= total {
		indices := make([]int, total)
		for i := range indices {
			indices[i] = i
		}
		return indices
	}
	indices := make([]int, count)
	step := float64(total-1) / float64(count-1)
	for i := 0; i < count; i++ {
		indices[i] = int(float64(i) * step)
	}
	return indices
}
