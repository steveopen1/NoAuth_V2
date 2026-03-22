package lib

import (
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Baseline 表示一个接口的响应基准特征
type Baseline struct {
	Code int
	Len  int
	Body []byte // 用于关键词检测
}

// ClassifyContext 双基线判定上下文
// Auth: 鉴权接口的原始响应（预期被拦截）
// NoAuth: 无鉴权接口的响应（预期正常可访问，作为正向基准）
type ClassifyContext struct {
	Auth   Baseline
	NoAuth Baseline
}

// ResponseMeta 响应元数据（扩展到 Header 分析）
type ResponseMeta struct {
	Body        []byte // 关键词检测用（首尾采样）
	Location    string // Location 头
	SetCookie   string // Set-Cookie 头（新 session 信号）
	ContentType string // Content-Type 头（响应结构变化信号）
	WWWAuth     string // WWW-Authenticate 头（认证域变化）
}

// ExtractResponseMeta 从 HTTP 响应中提取完整元数据
func ExtractResponseMeta(resp *http.Response, body []byte) ResponseMeta {
	return ResponseMeta{
		Body:        sampleBody(body, 8192),
		Location:    resp.Header.Get("Location"),
		SetCookie:   resp.Header.Get("Set-Cookie"),
		ContentType: resp.Header.Get("Content-Type"),
		WWWAuth:     resp.Header.Get("WWW-Authenticate"),
	}
}

// sampleBody 采样响应体用于关键词检测
// 策略: 前 6KB + 后 2KB，覆盖大部分关键信息位置
func sampleBody(body []byte, maxLen int) []byte {
	if len(body) <= maxLen {
		return body
	}
	// 前 6KB
	headSize := maxLen * 3 / 4
	tailSize := maxLen - headSize
	head := body[:headSize]
	tail := body[len(body)-tailSize:]
	result := make([]byte, 0, maxLen)
	result = append(result, head...)
	result = append(result, tail...)
	return result
}

// FetchBaseline 请求目标 URL 并构建 Baseline
func FetchBaseline(targetURL string) (Baseline, error) {
	resp, err := HttpClient.Get(targetURL)
	if err != nil {
		return Baseline{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Baseline{Code: resp.StatusCode}, err
	}

	return Baseline{
		Code: resp.StatusCode,
		Len:  len(body),
		Body: sampleBody(body, 8192),
	}, nil
}

// ClassifyResult 智能判定引擎 v3
//
// v3 改进:
//  1. 登录检测升级: 区分「登录页面」和「含登录关键词的 API 响应」
//  2. 小响应体自适应阈值: 最低阈值按响应体大小动态调整
//  3. 重定向目标扩充: 增加业务路径识别
//  4. Header 信号: Set-Cookie/Content-Type 变化作为辅助判据
//  5. 响应采样扩大: 首尾采样 8KB，覆盖更多关键词位置
func ClassifyResult(ctx ClassifyContext, newCode, newLen int, meta ResponseMeta) string {
	origCode := ctx.Auth.Code
	origLen := ctx.Auth.Len
	noauthCode := ctx.NoAuth.Code
	noauthLen := ctx.NoAuth.Len

	isLoginPage := detectLoginPage(meta.Body)
	hasNewSession := meta.SetCookie != "" && !strings.Contains(meta.SetCookie, "deleted")
	// Header 辅助信号
	headerSignals := buildHeaderSignals(meta)

	// ═══════════════════════════════════════════════════
	// 规则 1: 状态码从拦截变为 200（最强绕过信号）
	// ═══════════════════════════════════════════════════
	if newCode == 200 && isBlockedCode(origCode) {
		// 与无鉴权接口做相似度比较
		if noauthCode == 200 && noauthLen > 0 {
			sim := lengthSimilarity(newLen, noauthLen)
			if sim > 0.9 && !isLoginPage {
				suffix := headerSignals
				return "可能绕过(高)" + suffix
			}
			if sim > 0.7 && !isLoginPage {
				return "可能绕过(中)" + headerSignals
			}
		}
		// 没有 noauth 基线或不够相似
		if isLoginPage {
			return "可能绕过(低)"
		}
		// 有新 session cookie 是强信号
		if hasNewSession {
			return "可能绕过(中)" + headerSignals
		}
		return "可能绕过(中)" + headerSignals
	}

	// ═══════════════════════════════════════════════════
	// 规则 2: 重定向分析（区分登录跳转 vs 业务跳转）
	// ═══════════════════════════════════════════════════
	if newCode == 302 || newCode == 301 {
		if meta.Location != "" {
			lower := strings.ToLower(meta.Location)
			if !isLoginRedirectTarget(lower) {
				target := truncateStr(meta.Location, 60)
				return fmt.Sprintf("重定向(需关注→%s)", target)
			}
		}
		return "重定向"
	}

	// ═══════════════════════════════════════════════════
	// 规则 3: 明确拒绝（细分 401 和 403）
	// ═══════════════════════════════════════════════════
	if newCode == 403 {
		return "拒绝访问(403)"
	}
	if newCode == 401 {
		return "拒绝访问(401)"
	}

	// ═══════════════════════════════════════════════════
	// 规则 4: 同为 200，按比例比较长度差异（自适应阈值）
	// ═══════════════════════════════════════════════════
	if newCode == 200 && origCode == 200 {
		diff := absInt(newLen - origLen)
		// 自适应阈值：
		//   大响应(>500B): 原始长度的 20%
		//   中响应(100-500B): 原始长度的 30%，最小 30 字节
		//   小响应(<100B): 固定 15 字节（避免 10 字节阈值吞掉细微绕过）
		threshold := adaptiveThreshold(origLen)

		if diff > threshold {
			// 进一步: 是否更接近 noauth 页面
			if noauthLen > 0 && noauthCode == 200 {
				diffToNoAuth := absInt(newLen - noauthLen)
				simToNoAuth := lengthSimilarity(newLen, noauthLen)
				if diffToNoAuth < diff && simToNoAuth > 0.7 {
					return "长度差异大(高)" + headerSignals
				}
			}
			return "长度差异大(中)" + headerSignals
		}

		// 长度差异小，但检查 noauth 相似度（交叉验证）
		if noauthLen > 0 && noauthCode == 200 {
			simToNoAuth := lengthSimilarity(newLen, noauthLen)
			simToAuth := lengthSimilarity(newLen, origLen)
			// 如果响应更接近 noauth 而不是 auth，即使长度差异小也标记
			if simToNoAuth > 0.9 && simToAuth < 0.8 && !isLoginPage {
				return "长度差异大(高)" + headerSignals
			}
		}
		return "长度差异小"
	}

	// ═══════════════════════════════════════════════════
	// 规则 5: 其他状态码变化
	// ═══════════════════════════════════════════════════
	if newCode != origCode {
		return fmt.Sprintf("状态码变化(%d→%d)", origCode, newCode)
	}

	return fmt.Sprintf("状态码=%d", newCode)
}

// adaptiveThreshold 根据响应体大小计算自适应阈值
func adaptiveThreshold(origLen int) int {
	switch {
	case origLen >= 500:
		return maxInt(origLen/5, 50) // 20%，最小 50B
	case origLen >= 100:
		return maxInt(origLen*3/10, 30) // 30%，最小 30B
	default:
		return 15 // 小响应固定 15B
	}
}

// buildHeaderSignals 从响应头构建辅助信号标记
func buildHeaderSignals(meta ResponseMeta) string {
	var signals []string
	if meta.SetCookie != "" {
		signals = append(signals, "NewCookie")
	}
	if meta.ContentType != "" && strings.Contains(meta.ContentType, "json") {
		// Content-Type 是 JSON 而非 HTML → 可能是 API 真实响应
		signals = append(signals, "JSON")
	}
	if len(signals) > 0 {
		return " [" + strings.Join(signals, ",") + "]"
	}
	return ""
}

// detectLoginPage 智能检测响应是否为登录页面
// 改进: 区分「HTML 登录页面」和「API 错误响应中含登录关键词」
func detectLoginPage(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body))

	// ── 判断响应类型 ──
	isHTML := strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") ||
		strings.Contains(lower, "<form") || strings.Contains(lower, "<body")
	isJSON := (len(body) > 0 && (body[0] == '{' || body[0] == '['))

	// ── JSON 响应: 仅检查强拒绝信号，不检查弱关键词 ──
	if isJSON {
		// JSON API 中出现 "password" 不算登录页（可能是错误消息）
		// 只检查明确的拒绝语义
		jsonDenyKeywords := []string{
			"\"unauthorized\"", "\"access denied\"", "\"forbidden\"",
			"\"not authorized\"", "\"permission denied\"",
			"\"认证失败\"", "\"无权访问\"", "\"拒绝访问\"", "\"权限不足\"",
			"\"token expired\"", "\"token invalid\"", "\"invalid token\"",
		}
		matchCount := 0
		for _, kw := range jsonDenyKeywords {
			if strings.Contains(lower, kw) {
				matchCount++
			}
		}
		// JSON 中至少要有拒绝语义才判定
		return matchCount > 0
	}

	// ── HTML 响应: 检查登录表单特征（需要 2+ 个信号） ──
	if isHTML {
		score := 0
		// 强信号: 登录表单
		formKeywords := []string{
			"type=\"password\"", "type='password'",
			"name=\"password\"", "name='password'",
			"id=\"password\"", "id='password'",
		}
		for _, kw := range formKeywords {
			if strings.Contains(lower, kw) {
				score += 2
				break
			}
		}
		// 中等信号: 登录页面语义
		loginKeywords := []string{
			"login", "sign in", "signin", "log in",
			"登录", "登陆",
		}
		for _, kw := range loginKeywords {
			if strings.Contains(lower, kw) {
				score++
				break
			}
		}
		// 弱信号
		if strings.Contains(lower, "username") || strings.Contains(lower, "用户名") {
			score++
		}
		// 需要 2+ 分才认定为登录页（单个关键词不够）
		return score >= 2
	}

	// ── 未知类型: 使用宽松检测 ──
	keywords := []string{
		"unauthorized", "access denied", "forbidden",
		"not authorized", "permission denied",
		"认证失败", "无权访问", "拒绝访问", "权限不足",
	}
	for _, kw := range keywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isLoginRedirectTarget 判断重定向目标是否为登录/认证路径
func isLoginRedirectTarget(lower string) bool {
	loginPaths := []string{
		// 认证相关
		"login", "signin", "sign-in", "sign_in",
		"auth", "sso", "cas", "oauth", "saml",
		"account", "passport",
		// 注册相关
		"register", "signup",
	}
	for _, kw := range loginPaths {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// isBlockedCode 判断状态码是否为典型的鉴权拦截码
func isBlockedCode(code int) bool {
	return code == 401 || code == 403 || code == 302 || code == 301 || code == 405
}

// lengthSimilarity 计算两个长度的相似度 (0.0 ~ 1.0)
func lengthSimilarity(a, b int) float64 {
	if a == 0 && b == 0 {
		return 1.0
	}
	bigger := float64(maxInt(a, b))
	if bigger == 0 {
		return 0
	}
	diff := float64(absInt(a - b))
	return 1.0 - diff/bigger
}

func absInt(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func truncateBody(body []byte, maxLen int) []byte {
	if len(body) <= maxLen {
		return body
	}
	return body[:maxLen]
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// IsHighRisk 判断分类标签是否为高风险（用于 Excel 高亮和报告筛选）
func IsHighRisk(classification string) bool {
	return strings.Contains(classification, "可能绕过") ||
		strings.Contains(classification, "长度差异大") ||
		strings.Contains(classification, "重定向(需关注")
}

// ExtractConfidence 从分类标签中提取置信度
func ExtractConfidence(classification string) string {
	if strings.Contains(classification, "(高)") {
		return "高"
	}
	if strings.Contains(classification, "(中)") {
		return "中"
	}
	if strings.Contains(classification, "(低)") {
		return "低"
	}
	return ""
}

// ExtractBaseLabel 从带置信度的标签中提取基础标签
func ExtractBaseLabel(classification string) string {
	if strings.HasPrefix(classification, "可能绕过") {
		return "可能绕过"
	}
	if strings.HasPrefix(classification, "长度差异大") {
		return "长度差异大"
	}
	if strings.HasPrefix(classification, "重定向(需关注") {
		return "重定向(需关注)"
	}
	return classification
}
