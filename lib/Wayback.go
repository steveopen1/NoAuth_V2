package lib

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type WaybackResponse struct {
	URL         string `json:"url"`
	Timestamp   string `json:"timestamp"`
	Status      string `json:"status"`
	RequestUUID string `json:"request_uuid"`
}

type WaybackStatusResponse struct {
	ArchivedSnapshots struct {
		Closest struct {
			Available bool   `json:"available"`
			URL       string `json:"url"`
			Timestamp string `json:"timestamp"`
			Status    string `json:"status"`
		} `json:"closest"`
	} `json:"archived_snapshots"`
}

type WaybackSearchResult struct {
	URL         string `json:"url"`
	Timestamp   string `json:"timestamp"`
	Original    string `json:"original"`
	Mimetype    string `json:"mimetype"`
	Status      string `json:"status"`
	Length      int    `json:"length"`
	Digest      string `json:"digest"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

type WaybackCDXResponse []struct {
	Original    string `json:"original"`
	Timestamp   string `json:"timestamp"`
	Mimetype    string `json:"mimetype"`
	Status      string `json:"status"`
	Length      int    `json:"length"`
	Digest      string `json:"digest"`
	RedirectURL string `json:"redirect_url,omitempty"`
}

var waybackClient = &http.Client{
	Timeout: 10 * time.Second,
}

func QueryWaybackAvailable(targetURL string) (bool, string, string) {
	fmt.Printf(Blue("[+] 正在查询 Wayback Machine: %s\n"), targetURL)

	apiURL := fmt.Sprintf("https://archive.org/wayback/available?url=%s", targetURL)

	resp, err := waybackClient.Get(apiURL)
	if err != nil {
		fmt.Printf(Yellow("[!] Wayback查询失败: %s\n"), err)
		return false, "", ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf(Yellow("[!] 读取Wayback响应失败: %s\n"), err)
		return false, "", ""
	}

	var result WaybackStatusResponse
	if err := json.Unmarshal(body, &result); err != nil {
		fmt.Printf(Yellow("[!] 解析Wayback响应失败: %s\n"), err)
		return false, "", ""
	}

	if result.ArchivedSnapshots.Closest.Available {
		fmt.Printf(Green("[+] Wayback发现历史快照: %s (时间: %s)\n"),
			result.ArchivedSnapshots.Closest.URL,
			result.ArchivedSnapshots.Closest.Timestamp)
		return true, result.ArchivedSnapshots.Closest.URL, result.ArchivedSnapshots.Closest.Timestamp
	}

	fmt.Printf(Yellow("[*] Wayback未找到 %s 的历史记录\n"), targetURL)
	return false, "", ""
}

func SearchWaybackCDX(targetURL string) []WaybackSearchResult {
	fmt.Printf(Blue("[+] 正在搜索 Wayback CDX 索引: %s\n"), targetURL)

	apiURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=original,timestamp,mimetype,status,length,digest&filter=statuscode:200&limit=20", targetURL)

	resp, err := waybackClient.Get(apiURL)
	if err != nil {
		fmt.Printf(Yellow("[!] CDX搜索失败: %s\n"), err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf(Yellow("[!] 读取CDX响应失败: %s\n"), err)
		return nil
	}

	if len(body) < 2 {
		fmt.Printf(Yellow("[*] CDX未找到 %s 的历史记录\n"), targetURL)
		return nil
	}

	var rawResult WaybackCDXResponse
	if err := json.Unmarshal(body, &rawResult); err != nil {
		fmt.Printf(Yellow("[!] 解析CDX响应失败: %s\n"), err)
		return nil
	}

	var results []WaybackSearchResult
	for _, item := range rawResult {
		results = append(results, WaybackSearchResult{
			Original:  item.Original,
			Timestamp: item.Timestamp,
			Mimetype:  item.Mimetype,
			Status:    item.Status,
			Length:    item.Length,
			Digest:    item.Digest,
		})
	}

	if len(results) > 0 {
		fmt.Printf(Green("[+] CDX找到 %d 条历史记录\n"), len(results))
	} else {
		fmt.Printf(Yellow("[*] CDX未找到 %s 的历史记录\n"), targetURL)
	}

	return results
}

func GenerateWaybackPayloads(targetURL string, authPath string) []string {
	var payloads []string

	domain := extractDomain(targetURL)
	if domain == "" {
		return payloads
	}

	available, waybackURL, ts := QueryWaybackAvailable(domain + authPath)
	_ = available
	if waybackURL != "" {
		payloads = append(payloads, waybackURL)
		fmt.Printf("  [+] Wayback发现: %s (时间: %s)\n", waybackURL, ts)
	}

	cdxResults := SearchWaybackCDX(domain + "/*")
	for _, result := range cdxResults {
		if result.Original != "" {
			payloads = append(payloads, "https://web.archive.org/web/"+result.Timestamp+"/"+result.Original)
		}
	}

	return payloads
}

func extractWaybackDomain(rawURL string) string {
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		rawURL = strings.TrimPrefix(rawURL, "http://")
		rawURL = strings.TrimPrefix(rawURL, "https://")
	}
	if idx := strings.Index(rawURL, "/"); idx > 0 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

type WayBackInfo struct {
	HasHistory bool
	HistoryURL string
	Timestamp  string
	CDXCount   int
}

func GetWaybackInfo(targetURL string) WayBackInfo {
	info := WayBackInfo{}

	domain := extractWaybackDomain(targetURL)
	if domain == "" {
		return info
	}

	if available, waybackURL, timestamp := QueryWaybackAvailable(domain); available {
		info.HasHistory = true
		info.HistoryURL = waybackURL
		info.Timestamp = timestamp
	}

	cdxResults := SearchWaybackCDX(domain + "/*")
	info.CDXCount = len(cdxResults)

	return info
}

func PrintWaybackReport(targetURL string) {
	fmt.Println()
	fmt.Println(CyanStyle("┌──────────────────────────────────────────────────────────────────────┐"))
	fmt.Println(CyanStyle("│] Wayback Machine 信息收集报告                                          │"))
	fmt.Println(CyanStyle("└──────────────────────────────────────────────────────────────────────┘"))
	fmt.Println()

	domain := extractWaybackDomain(targetURL)
	if domain == "" {
		fmt.Printf(YellowStyle("[*] 无法从 %s 提取域名\n"), targetURL)
		return
	}

	fmt.Printf("  目标域名: %s\n\n", domain)

	available, waybackURL, timestamp := QueryWaybackAvailable(domain)
	if available {
		fmt.Printf("  %s[+] 历史快照可用%s\n", GreenStyle(""), ResetStyle())
		fmt.Printf("    URL: %s\n", waybackURL)
		fmt.Printf("    时间戳: %s\n", timestamp)
	} else {
		fmt.Printf("  %s[*] 未找到历史快照%s\n", YellowStyle(""), ResetStyle())
	}

	fmt.Println()
	cdxResults := SearchWaybackCDX(domain + "/*")
	if len(cdxResults) > 0 {
		fmt.Printf("  %s[+] CDX索引找到 %d 条记录 (显示前10条)%s\n", GreenStyle(""), len(cdxResults), ResetStyle())
		for i := 0; i < len(cdxResults) && i < 10; i++ {
			r := cdxResults[i]
			fmt.Printf("    [%s] %s (%s, %d bytes)\n",
				r.Timestamp,
				truncateStrFix(r.Original, 60),
				r.Mimetype,
				r.Length)
		}
		if len(cdxResults) > 10 {
			fmt.Printf("    ... 还有 %d 条记录\n", len(cdxResults)-10)
		}
	} else {
		fmt.Printf("  %s[*] CDX索引未找到记录%s\n", YellowStyle(""), ResetStyle())
	}

	fmt.Println()
	fmt.Println(CyanStyle("└──────────────────────────────────────────────────────────────────────┘"))
}

func truncateStrFix(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func CyanStyle(s string) string {
	return fmt.Sprintf("\033[36m%s\033[0m", s)
}

func GreenStyle(s string) string {
	return fmt.Sprintf("\033[32m%s\033[0m", s)
}

func YellowStyle(s string) string {
	return fmt.Sprintf("\033[33m%s\033[0m", s)
}

func RedStyle(s string) string {
	return fmt.Sprintf("\033[31m%s\033[0m", s)
}

func ResetStyle() string {
	return "\033[0m"
}

func BlueStyle(s string) string {
	return fmt.Sprintf("\033[34m%s\033[0m", s)
}
