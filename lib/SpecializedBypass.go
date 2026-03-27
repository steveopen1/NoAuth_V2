package lib

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type SpecializedBypassStartResult struct {
	JWTSheet     SheetData
	GraphQLSheet SheetData
	OAuthSheet   SheetData
	SAMLSheet    SheetData
	GRPCSheet    SheetData
	SessionSheet SheetData
}

func SpecializedBypassStart(url, noauth, auth string, thread int, debug int, noauthBaseline Baseline) SpecializedBypassStartResult {
	result := SpecializedBypassStartResult{
		JWTSheet:     SheetData{Name: "JWT 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}},
		GraphQLSheet: SheetData{Name: "GraphQL 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}},
		OAuthSheet:   SheetData{Name: "OAuth2 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}},
		SAMLSheet:    SheetData{Name: "SAML 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}},
		GRPCSheet:    SheetData{Name: "gRPC/h2c 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}},
		SessionSheet: SheetData{Name: "Session 安全测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}},
	}

	url = strings.TrimSuffix(url, "/")

	startTime := time.Now()
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
	responseTimeMs := time.Since(startTime).Milliseconds()

	authMeta := ExtractResponseMeta(resp, body, responseTimeMs)
	ctx := ClassifyContext{
		Auth:           Baseline{Code: origCode, Len: origLen, Body: sampleBody(body, 8192), Meta: authMeta},
		NoAuth:         noauthBaseline,
		BaselineTimeMs: authMeta.ResponseTimeMs,
	}

	var wg sync.WaitGroup
	wg.Add(6)

	go func() {
		defer wg.Done()
		result.JWTSheet = testJWTTampering(url, auth, ctx, thread, debug)
	}()

	go func() {
		defer wg.Done()
		result.GraphQLSheet = testGraphQLBypass(url, auth, ctx, thread, debug)
	}()

	go func() {
		defer wg.Done()
		result.OAuthSheet = testOAuth2Bypass(url, auth, ctx, thread, debug)
	}()

	go func() {
		defer wg.Done()
		result.SAMLSheet = testSAMLBypass(url, auth, ctx, thread, debug)
	}()

	go func() {
		defer wg.Done()
		result.GRPCSheet = testGRPCBypass(url, auth, ctx, thread, debug)
	}()

	go func() {
		defer wg.Done()
		result.SessionSheet = testSessionFixation(url, auth, ctx, thread, debug)
	}()

	wg.Wait()

	return result
}

func testJWTTampering(url, auth string, ctx ClassifyContext, thread, debug int) SheetData {
	result := SheetData{Name: "JWT 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}}

	resp, err := HttpClient.Get(url + auth)
	if err != nil {
		return result
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	token := ExtractJWTFromResponse(body)

	if token == "" {
		resp2, _ := HttpClient.Get(url + "/login")
		if resp2 != nil {
			defer resp2.Body.Close()
			body2, _ := io.ReadAll(io.LimitReader(resp2.Body, 1024*1024))
			token = ExtractJWTFromResponse(body2)
		}
	}

	if token == "" {
		token = extractTokenFromAuthHeader(resp)
	}

	if token == "" {
		fmt.Println(Yellow("[*] 未在响应中找到 JWT Token，跳过 JWT 绕过测试"))
		return result
	}

	fmt.Printf(Blue("[+] 发现 JWT Token: %s...\n"), truncateStr(token, 30))

	jwtCases := BuildJWTBypassCases(url, auth, token)

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)

	for _, tc := range jwtCases {
		wg.Add(1)
		go func(tc JWTBypassCase) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			req, err := http.NewRequest(tc.method, tc.url, nil)
			if err != nil {
				return
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			resp, err := HttpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
			newLen := len(respBody)
			newCode := resp.StatusCode

			meta := ExtractResponseMeta(resp, respBody, 0)
			classification := ClassifyResult(ctx, newCode, newLen, meta)

			curlCmd := fmt.Sprintf("curl -k -v -H \"Authorization: Bearer %s\" \"%s\"", token, tc.url)

			mu.Lock()
			result.Data = append(result.Data, []string{
				tc.desc,
				tc.url,
				fmt.Sprintf("%d", newLen),
				fmt.Sprintf("%d", newCode),
				classification,
				curlCmd,
			})
			mu.Unlock()

			if debug == 1 && strings.Contains(classification, "绕过") {
				fmt.Printf(Green("[+] JWT 绕过: %s len=%d code=%d → %s\n"), tc.desc, newLen, newCode, classification)
			}
		}(tc)
	}
	wg.Wait()

	return result
}

func extractTokenFromAuthHeader(resp *http.Response) string {
	auth := resp.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func testGraphQLBypass(url, auth string, ctx ClassifyContext, thread, debug int) SheetData {
	result := SheetData{Name: "GraphQL 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}}

	graphqlCases := BuildGraphQLBypassCases(url)

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)

	for _, tc := range graphqlCases {
		wg.Add(1)
		go func(tc GraphQLBypassCase) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var resp *http.Response
			var err error

			if tc.method == "POST" {
				resp, err = HttpClient.Post(tc.url, tc.contentType, bytes.NewBufferString(tc.body))
			} else {
				resp, err = HttpClient.Get(tc.url)
			}

			if err != nil {
				return
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
			newLen := len(respBody)
			newCode := resp.StatusCode

			meta := ExtractResponseMeta(resp, respBody, 0)
			classification := ClassifyResult(ctx, newCode, newLen, meta)

			mu.Lock()
			result.Data = append(result.Data, []string{
				tc.desc,
				tc.url,
				fmt.Sprintf("%d", newLen),
				fmt.Sprintf("%d", newCode),
				classification,
				fmt.Sprintf("curl -k -X %s -d '%s' -H 'Content-Type: %s' \"%s\"", tc.method, tc.body, tc.contentType, tc.url),
			})
			mu.Unlock()

			if debug == 1 && strings.Contains(classification, "绕过") {
				fmt.Printf(Green("[+] GraphQL 绕过: %s len=%d code=%d → %s\n"), tc.desc, newLen, newCode, classification)
			}
		}(tc)
	}
	wg.Wait()

	return result
}

func testOAuth2Bypass(url, auth string, ctx ClassifyContext, thread, debug int) SheetData {
	result := SheetData{Name: "OAuth2 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}}

	oauthCases := BuildOAuth2BypassCases(url)

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)

	for _, tc := range oauthCases {
		wg.Add(1)
		go func(tc OAuth2BypassCase) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var resp *http.Response
			var err error

			if tc.method == "POST" {
				bodyData := strings.NewReader(tc.body)
				req, _ := http.NewRequest("POST", tc.url, bodyData)
				for k, v := range tc.headers {
					req.Header.Set(k, v)
				}
				resp, err = HttpClient.Do(req)
			} else {
				resp, err = HttpClient.Get(tc.url)
			}

			if err != nil {
				return
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
			newLen := len(respBody)
			newCode := resp.StatusCode

			meta := ExtractResponseMeta(resp, respBody, 0)
			classification := ClassifyResult(ctx, newCode, newLen, meta)

			mu.Lock()
			result.Data = append(result.Data, []string{
				tc.desc,
				tc.url,
				fmt.Sprintf("%d", newLen),
				fmt.Sprintf("%d", newCode),
				classification,
				tc.url,
			})
			mu.Unlock()

			if debug == 1 && strings.Contains(classification, "绕过") {
				fmt.Printf(Green("[+] OAuth2 绕过: %s len=%d code=%d → %s\n"), tc.desc, newLen, newCode, classification)
			}
		}(tc)
	}
	wg.Wait()

	return result
}

func testSAMLBypass(url, auth string, ctx ClassifyContext, thread, debug int) SheetData {
	result := SheetData{Name: "SAML 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}}

	samlCases := BuildSAMLBypassCases(url + "/saml/acs")

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)

	for _, tc := range samlCases {
		wg.Add(1)
		go func(tc SAMLBypassCase) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			req, _ := http.NewRequest(tc.method, tc.url, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			resp, err := HttpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
			newLen := len(respBody)
			newCode := resp.StatusCode

			meta := ExtractResponseMeta(resp, respBody, 0)
			classification := ClassifyResult(ctx, newCode, newLen, meta)

			mu.Lock()
			result.Data = append(result.Data, []string{
				tc.desc,
				tc.url,
				fmt.Sprintf("%d", newLen),
				fmt.Sprintf("%d", newCode),
				classification,
				tc.desc,
			})
			mu.Unlock()

			if debug == 1 && strings.Contains(classification, "绕过") {
				fmt.Printf(Green("[+] SAML 绕过: %s len=%d code=%d → %s\n"), tc.desc, newLen, newCode, classification)
			}
		}(tc)
	}
	wg.Wait()

	return result
}

func testGRPCBypass(url, auth string, ctx ClassifyContext, thread, debug int) SheetData {
	result := SheetData{Name: "gRPC/h2c 绕过测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}}

	grpcCases := BuildGRPCBypassCases(url)

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)

	for _, tc := range grpcCases {
		wg.Add(1)
		go func(tc GRPCBypassCase) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			req, _ := http.NewRequest(tc.method, tc.url, nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			resp, err := HttpClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
			newLen := len(respBody)
			newCode := resp.StatusCode

			meta := ExtractResponseMeta(resp, respBody, 0)
			classification := ClassifyResult(ctx, newCode, newLen, meta)

			mu.Lock()
			result.Data = append(result.Data, []string{
				tc.desc,
				tc.url,
				fmt.Sprintf("%d", newLen),
				fmt.Sprintf("%d", newCode),
				classification,
				tc.desc,
			})
			mu.Unlock()

			if debug == 1 && strings.Contains(classification, "绕过") {
				fmt.Printf(Green("[+] gRPC 绕过: %s len=%d code=%d → %s\n"), tc.desc, newLen, newCode, classification)
			}
		}(tc)
	}
	wg.Wait()

	return result
}

func testSessionFixation(url, auth string, ctx ClassifyContext, thread, debug int) SheetData {
	result := SheetData{Name: "Session 安全测试", Headers: []string{"绕过技术", "URL", "响应长度", "状态码", "判定", "复现命令"}}

	sessionCases := BuildSessionFixationCases(url)

	var mu sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, thread)

	for _, tc := range sessionCases {
		wg.Add(1)
		go func(tc SessionFixationCase) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var resp *http.Response
			var err error

			if tc.method == "POST" {
				resp, err = HttpClient.Post(tc.url, "application/x-www-form-urlencoded", strings.NewReader("username=test&password=test"))
			} else {
				resp, err = HttpClient.Get(tc.url)
			}

			if err != nil {
				return
			}
			defer resp.Body.Close()

			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
			newLen := len(respBody)
			newCode := resp.StatusCode

			meta := ExtractResponseMeta(resp, respBody, 0)
			classification := ClassifyResult(ctx, newCode, newLen, meta)

			mu.Lock()
			result.Data = append(result.Data, []string{
				tc.desc,
				tc.url,
				fmt.Sprintf("%d", newLen),
				fmt.Sprintf("%d", newCode),
				classification,
				tc.desc,
			})
			mu.Unlock()

			if debug == 1 && strings.Contains(classification, "绕过") {
				fmt.Printf(Green("[+] Session 安全: %s len=%d code=%d → %s\n"), tc.desc, newLen, newCode, classification)
			}
		}(tc)
	}
	wg.Wait()

	return result
}
