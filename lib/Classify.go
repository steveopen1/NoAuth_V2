package lib

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// ClassifyResultWithColor 返回判定结果和对应的高亮颜色
// confidence: 高(red)/中(yellow)/低(green)
func ClassifyResultWithColor(ctx ClassifyContext, newCode, newLen int, meta ResponseMeta) (string, string) {
	result := ClassifyResult(ctx, newCode, newLen, meta)

	switch {
	case strings.Contains(result, "可能绕过(高)"):
		return result, "red"
	case strings.Contains(result, "可能绕过(中)"):
		return result, "yellow"
	case strings.Contains(result, "重定向(需关注"):
		return result, "yellow"
	case strings.Contains(result, "可能绕过(低)"):
		return result, "green"
	case strings.Contains(result, "长度差异大"):
		return result, "cyan"
	case strings.Contains(result, "内容拦截"):
		return result, "red"
	default:
		return result, ""
	}
}

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
	Body          []byte // 关键词检测用（首尾采样）
	Location      string // Location 头
	SetCookie     string // Set-Cookie 头（新 session 信号）
	ContentType   string // Content-Type 头（响应结构变化信号）
	WWWAuth       string // WWW-Authenticate 头（认证域变化）
	CacheControl  string // Cache-Control 头（缓存控制变化）
	Authorization string // Authorization 头（认证信息残留检测）
	Cookie        string // Cookie 头（Cookie 安全属性检测）
	Server        string // Server 头（服务端标识）
	XPoweredBy    string // X-Powered-By 头（技术栈信息）
	// 增强字段
	ETag          string // ETag 头（资源标识变化）
	Expires       string // Expires 头（缓存过期变化）
	ContentLength int    // Content-Length 头（与实际body长度对比）
	Vary          string // Vary 头（缓存键变化）
	// CORS 头
	AccessControlAllowOrigin      string // Access-Control-Allow-Origin
	AccessControlAllowMethods     string // Access-Control-Allow-Methods
	AccessControlAllowHeaders     string // Access-Control-Allow-Headers
	AccessControlExposeHeaders    string // Access-Control-Expose-Headers
	AccessControlAllowCredentials bool   // Access-Control-Allow-Credentials
	// 安全相关头
	ContentSecurityPolicy   string // CSP 头
	XFrameOptions           string // 点击劫持防护
	XContentTypeOptions     string // MIME 类型 sniffing 防护
	StrictTransportSecurity string // HSTS 头
	// 响应时间（毫秒）
	ResponseTimeMs int64
}

// ExtractResponseMeta 从 HTTP 响应中提取完整元数据
func ExtractResponseMeta(resp *http.Response, body []byte) ResponseMeta {
	return ResponseMeta{
		Body:                          sampleBody(body, 8192),
		Location:                      resp.Header.Get("Location"),
		SetCookie:                     resp.Header.Get("Set-Cookie"),
		ContentType:                   resp.Header.Get("Content-Type"),
		WWWAuth:                       resp.Header.Get("WWW-Authenticate"),
		CacheControl:                  resp.Header.Get("Cache-Control"),
		Authorization:                 resp.Header.Get("Authorization"),
		Cookie:                        resp.Header.Get("Cookie"),
		Server:                        resp.Header.Get("Server"),
		XPoweredBy:                    resp.Header.Get("X-Powered-By"),
		ETag:                          resp.Header.Get("ETag"),
		Expires:                       resp.Header.Get("Expires"),
		ContentLength:                 len(body),
		Vary:                          resp.Header.Get("Vary"),
		AccessControlAllowOrigin:      resp.Header.Get("Access-Control-Allow-Origin"),
		AccessControlAllowMethods:     resp.Header.Get("Access-Control-Allow-Methods"),
		AccessControlAllowHeaders:     resp.Header.Get("Access-Control-Allow-Headers"),
		AccessControlExposeHeaders:    resp.Header.Get("Access-Control-Expose-Headers"),
		AccessControlAllowCredentials: resp.Header.Get("Access-Control-Allow-Credentials") == "true",
		ContentSecurityPolicy:         resp.Header.Get("Content-Security-Policy"),
		XFrameOptions:                 resp.Header.Get("X-Frame-Options"),
		XContentTypeOptions:           resp.Header.Get("X-Content-Type-Options"),
		StrictTransportSecurity:       resp.Header.Get("Strict-Transport-Security"),
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
	hasNewSession := meta.SetCookie != "" && !strings.Contains(strings.ToLower(meta.SetCookie), "deleted")
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
	if newCode == 302 || newCode == 301 || newCode == 307 || newCode == 308 {
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
		// 首先检查：内容是否包含鉴权拦截关键词（即使长度相似也可能是绕过）
		blockedContent := detectBlockedContent(meta.Body)
		if blockedContent != "" {
			return "内容拦截(疑似绕过→" + blockedContent + ")"
		}

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

	// ═══════════════════════════════════════════
	// 规则 5: 其他状态码变化
	// ═══════════════════════════════════════════
	if newCode != origCode {
		// 优先检测高风险状态码
		switch newCode {
		case 429:
			return "限流(429)"
		case 500:
			return "服务器错误(500)"
		case 502:
			return "网关错误(502)"
		case 503:
			return "服务不可用(503)"
		case 504:
			return "网关超时(504)"
		case 400:
			if origCode == 200 {
				return "请求格式异常(400)"
			}
		case 422:
			return "格式错误(422)"
		case 405:
			return "方法不允许(405)"
		case 407:
			return "代理认证失败(407)"
		case 408:
			return "请求超时(408)"
		}
		return fmt.Sprintf("状态码变化(%d→%d)", origCode, newCode)
	}

	return fmt.Sprintf("状态码=%d", newCode)
}

// adaptiveThreshold 根据响应体大小计算自适应阈值
func adaptiveThreshold(origLen int) int {
	if origLen <= 0 {
		return 0 // 空响应，任何变化都应检测
	}
	switch {
	case origLen >= 500:
		return maxInt(origLen/5, 50) // 20%，最小 50B
	case origLen >= 100:
		return maxInt(origLen*3/10, 30) // 30%，最小 30B
	case origLen >= 20:
		return maxInt(origLen/2, 10) // 50%，最小 10B
	default:
		return maxInt(origLen*3/5, 5) // 60%，最小 5B（更敏感）
	}
}

// buildHeaderSignals 从响应头构建辅助信号标记
func buildHeaderSignals(meta ResponseMeta) string {
	var signals []string
	if meta.SetCookie != "" {
		signals = append(signals, "NewCookie")
	}
	if meta.Authorization != "" && meta.SetCookie == "" {
		signals = append(signals, "Auth残留")
	}
	if meta.Server != "" {
		signals = append(signals, "Server:"+meta.Server)
	}
	if meta.XPoweredBy != "" {
		signals = append(signals, meta.XPoweredBy)
	}
	if meta.WWWAuth != "" && strings.Contains(strings.ToLower(meta.WWWAuth), "bearer") {
		signals = append(signals, "Bearer认证")
	}
	if meta.ContentType != "" {
		if strings.Contains(meta.ContentType, "json") {
			signals = append(signals, "JSON")
		} else if strings.Contains(meta.ContentType, "html") {
			signals = append(signals, "HTML")
		} else if strings.Contains(meta.ContentType, "xml") {
			signals = append(signals, "XML")
		}
	}
	if len(signals) > 0 {
		return " [" + strings.Join(signals, ",") + "]"
	}
	return ""
}

// detectBlockedContent 检测响应内容是否包含鉴权拦截关键词
// 返回拦截关键词内容（空字符串表示未检测到）
func detectBlockedContent(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	trimmed := trimBody(body)
	if len(trimmed) == 0 {
		return ""
	}
	lower := strings.ToLower(string(trimmed))

	// JSON 格式检测
	if trimmed[0] == '{' || trimmed[0] == '[' {
		blockedKeywords := []string{
			`"code":401`, `"code":403`,
			`"status":401`, `"status":403`,
			`"error":"unauthorized`, `"error":"forbidden`,
			`"error":"access denied`, `"error":"permission denied`,
			`"message":"unauthorized`, `"message":"forbidden`,
			`"msg":"unauthorized`, `"msg":"forbidden`,
			`"error_code":401`, `"error_code":403`,
			`"result":401`, `"result":403`,
			`"ret":401`, `"ret":403`,
			// 字符串错误码
			`"code":"error"`, `"code":"fail"`, `"code":"failed"`,
			`"status":"error"`, `"status":"fail"`, `"status":"failed"`,
			`"success":false`, `"success":0`,
			// 数字错误码（常见企业 API）
			`"code":10001`, `"code":10002`, `"code":10003`,
			`"code":20001`, `"code":20002`, `"code":40101`,
			`"code":50001`, `"code":50002`,
			// 通用错误码模式
			`"code":-1`, `"code":-2`,
		}
		for _, kw := range blockedKeywords {
			if strings.Contains(lower, kw) {
				return extractBlockedReason(lower)
			}
		}
		return ""
	}

	// HTML/XML 格式检测
	if strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") {
		blockedKeywords := []string{
			"access denied", "access to this page has been denied",
			"forbidden", "you don't have permission",
			"authorization failed", "authorization required",
			"unauthorized access", "unauthorized access denied",
			"权限不足", "拒绝访问", "无权访问", "认证失败",
			"登录后操作", "please login", "please sign in",
			"401 unauthorized", "403 forbidden",
			"error 401", "error 403",
		}
		for _, kw := range blockedKeywords {
			if strings.Contains(lower, kw) {
				return "页面含拦截内容"
			}
		}
	}

	// 纯文本响应检测
	plainBlocked := []string{
		"unauthorized", "forbidden", "access denied",
		"permission denied", "not authorized",
		"401 unauthorized", "403 forbidden",
		"error 401", "error 403",
	}
	for _, kw := range plainBlocked {
		if strings.Contains(lower, kw) {
			return "内容含拦截关键词"
		}
	}

	return ""
}

// extractBlockedReason 从响应中提取拦截原因
func extractBlockedReason(lower string) string {
	// 使用正则精确匹配错误码，避免误匹配 "1401", "2401" 等
	code401Regex := regexp.MustCompile(`"code":\s*401|"status":\s*401|"code":\s*"401"|"error_code":\s*401`)
	code403Regex := regexp.MustCompile(`"code":\s*403|"status":\s*403|"code":\s*"403"|"error_code":\s*403`)

	if code401Regex.MatchString(lower) {
		return "含401状态"
	}
	if code403Regex.MatchString(lower) {
		return "含403状态"
	}
	if strings.Contains(lower, "unauthorized") {
		return "含unauthorized"
	}
	if strings.Contains(lower, "forbidden") {
		return "含forbidden"
	}
	if strings.Contains(lower, "denied") {
		return "含denied"
	}
	return "含拦截关键词"
}

// detectLoginPage 智能检测响应是否为登录页面
// 改进: 区分「HTML 登录页面」和「API 错误响应中含登录关键词」
func detectLoginPage(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	trimmed := trimBody(body)
	if len(trimmed) == 0 {
		return false
	}
	lower := strings.ToLower(string(trimmed))

	// ── 判断响应类型 ──
	isHTML := strings.Contains(lower, "<html") || strings.Contains(lower, "<!doctype") ||
		strings.Contains(lower, "<!doctype html") || strings.Contains(lower, "<head") ||
		strings.Contains(lower, "<form") || strings.Contains(lower, "<body")
	isJSON := (trimmed[0] == '{' || trimmed[0] == '[')

	// ── JSON 响应: 仅检查强拒绝信号，不检查弱关键词 ──
	if isJSON {
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
		return matchCount > 0
	}

	// ── HTML 响应: 检查登录表单特征（需要 2+ 个信号） ──
	if isHTML {
		score := 0
		// 强信号: 登录表单 - 检查 type= 属性中有 password
		hasPasswordField := strings.Contains(lower, "type=") && strings.Contains(lower, "password")
		if hasPasswordField {
			score += 2
		}
		// 检查 name/id 属性中有 password
		hasPasswordName := strings.Contains(lower, `name="password"`) || strings.Contains(lower, `name='password'`) ||
			strings.Contains(lower, `id="password"`) || strings.Contains(lower, `id='password'`)
		if hasPasswordName {
			score++
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
		"account", "passport", "credential",
		// 注册相关
		"register", "signup", "join",
		// 验证/确认
		"verify", "confirm", "validation",
		// 会话
		"session", "logout", "signout",
		// 安全
		"security", "protected", "private",
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
	return code == 401 || code == 403 || code == 302 || code == 301 || code == 405 || code == 404 || code == 307 || code == 308
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
	if a == 0 || b == 0 {
		return 0.0
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
		strings.Contains(classification, "重定向(需关注") ||
		strings.Contains(classification, "内容拦截")
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

// bodyJaccardSimilarity 计算两个响应体的 Jaccard 相似度
// 基于词汇（单词）集合的交集/并集比率
func bodyJaccardSimilarity(body1, body2 []byte) float64 {
	if len(body1) == 0 && len(body2) == 0 {
		return 1.0
	}
	if len(body1) == 0 || len(body2) == 0 {
		return 0.0
	}

	words1 := extractWords(body1)
	words2 := extractWords(body2)

	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, w := range words1 {
		set1[w] = true
	}
	for _, w := range words2 {
		set2[w] = true
	}

	intersection := 0
	for w := range set1 {
		if set2[w] {
			intersection++
		}
	}

	union := len(set1) + len(set2) - intersection
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// extractWords 从响应体中提取词汇（用于相似度计算）
func extractWords(body []byte) []string {
	var words []string
	var current []byte
	inTag := false

	for _, b := range body {
		c := charToLower(b)
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' {
			current = append(current, c)
		} else if c == '<' {
			inTag = true
			if len(current) >= 3 {
				words = append(words, string(current))
			}
			current = nil
		} else if c == '>' {
			inTag = false
		} else {
			if !inTag && len(current) >= 3 {
				words = append(words, string(current))
			}
			current = nil
		}
	}
	if len(current) >= 3 {
		words = append(words, string(current))
	}
	return words
}

// charToLower 将字节转换为小写（ASCII 范围内）
func charToLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

// trimBody 去除 body 前面的空白字符和 BOM
func trimBody(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	// 跳过 UTF-8 BOM (0xEF 0xBB 0xBF)
	if len(body) >= 3 && body[0] == 0xEF && body[1] == 0xBB && body[2] == 0xBF {
		body = body[3:]
	}
	// 跳过空白字符
	i := 0
	for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r') {
		i++
	}
	return body[i:]
}

// detectWAFSignature 检测响应中是否包含 WAF 特征
func detectWAFSignature(meta ResponseMeta, body []byte) string {
	combined := strings.ToLower(string(body)) + strings.ToLower(meta.Server) + strings.ToLower(meta.XPoweredBy)

	wafSignatures := map[string]string{
		// Cloudflare
		"cloudflare":      "Cloudflare WAF",
		"cf-ray":          "Cloudflare",
		"__cfduid":        "Cloudflare",
		"cf-cache-status": "Cloudflare",
		"cf-request-id":   "Cloudflare",
		// Akamai
		"akamai":               "Akamai",
		"akamai-origin":        "Akamai",
		"x-akamai":             "Akamai",
		"akamai-x-cache":       "Akamai",
		"akamai-x-get-noncomm": "Akamai",
		// Imperva Incapsula
		"incapsula": "Imperva Incapsula",
		"incap_":    "Imperva Incapsula",
		// F5
		"f5-networks": "F5 ASM",
		"bigip":       "F5 BIG-IP",
		"x-cnection":  "F5",
		"x-profile":   "F5",
		// Fortinet
		"fortigate": "FortiGate",
		"fortiweb":  "FortiWeb",
		// AWS
		"aws-alb":          "AWS ALB",
		"aws-waf":          "AWS WAF",
		"aws-request-id":   "AWS",
		"x-amz-id":         "AWS S3/CloudFront",
		"x-amz-request-id": "AWS",
		// Azure
		"azure":             "Azure",
		"x-azure":           "Azure",
		"x-ec-custom-error": "Azure",
		// Google Cloud
		"google": "Google Cloud",
		"gws":    "Google Web Service",
		"x-goog": "Google Cloud",
		// CloudFront
		"cloudfront": "CloudFront",
		"x-amz-cf":   "CloudFront",
		// CDN
		"x-cdn":           "CDN",
		"x-edge-location": "Edge CDN",
		"x-snap":          "Snap Proxy",
		"x-cc":            "CacheFly",
		"fastly":          "Fastly",
		"x-srv":           "Fastly",
		// 国产 CDN/WAF
		"aliyun":      "阿里云",
		"alibaba":     "阿里云",
		"x-oss":       "阿里云 OSS",
		"tengine":     "阿里云Tengine",
		"tencent":     "腾讯云",
		"x-qcloud":    "腾讯云",
		"waf":         "WAF",
		"waf blocked": "WAF拦截",
		// 其他安全产品
		"signal":     "Signal Sciences",
		"sucuri":     "Sucuri",
		"x-sucuri":   "Sucuri",
		"denyall":    "DenyAll",
		"arrowpoint": "Cisco ArrowPoint",
		"sonicwall":  "SonicWALL",
		"paloalto":   "Palo Alto",
		"watchguard": "WatchGuard",
		"barracuda":  "Barracuda",
		"imperva":    "Imperva",
		"datPower":   "DatPower",
		// 安全响应特征
		"xsshijacking":         "XSS Protection",
		"x-ocsp":               "OCSP",
		"doss protection":      "DDoS Protection",
		"rate limit":           "Rate Limiting",
		"too many request":     "Rate Limiting",
		"security policy":      "Security Policy",
		"x-sql":                "SQL Injection Protection",
		"x-xss":                "XSS Protection",
		"x-content-type":       "Content Type Protection",
		"x-frame-options":      "Clickjacking Protection",
		"content-type-options": "MIME Sniffing Protection",
		// ModSecurity
		"mod_security": "ModSecurity",
		"modsecurity":  "ModSecurity",
		"paranoia":     "ModSecurity",
	}

	for sig, name := range wafSignatures {
		if strings.Contains(combined, sig) {
			return name
		}
	}

	// 检查特殊 WAF 响应码
	wafCodes := []string{
		"403 forbidden", "403 access denied", "403 forbidden",
		"403 you have been blocked", "403 this website is using a security service",
		"401 unauthorized", "awaits verification", "security check",
	}
	for _, code := range wafCodes {
		if strings.Contains(combined, code) {
			return "WAF拦截"
		}
	}

	return ""
}

// detectCacheChanges 检测缓存相关头的变化
// 返回变化描述，空字符串表示无显著变化
func detectCacheChanges(origMeta, newMeta ResponseMeta) string {
	changes := []string{}

	// ETag 变化
	if origMeta.ETag != "" && newMeta.ETag != "" && origMeta.ETag != newMeta.ETag {
		changes = append(changes, "ETag变化")
	}

	// Cache-Control 变化
	if origMeta.CacheControl != "" && newMeta.CacheControl != "" && origMeta.CacheControl != newMeta.CacheControl {
		changes = append(changes, "Cache-Control变化")
	}

	// Expires 变化
	if origMeta.Expires != "" && newMeta.Expires != "" && origMeta.Expires != newMeta.Expires {
		changes = append(changes, "Expires变化")
	}

	// Vary 变化
	if origMeta.Vary != "" && newMeta.Vary != "" && origMeta.Vary != newMeta.Vary {
		changes = append(changes, "Vary变化")
	}

	// Content-Length 与实际长度不符（压缩或传输编码变化）
	if newMeta.ContentLength > 0 && len(newMeta.Body) > 0 {
		ratio := float64(len(newMeta.Body)) / float64(newMeta.ContentLength)
		// 如果实际长度是声明长度的 10 倍以上，可能有编码差异
		if ratio > 10 {
			changes = append(changes, "Content-Length差异大")
		}
	}

	if len(changes) == 0 {
		return ""
	}
	return "[" + strings.Join(changes, ",") + "]"
}

// detectCORsChanges 检测 CORS 头的变化
// 返回变化描述，空字符串表示无显著变化
func detectCORsChanges(origMeta, newMeta ResponseMeta) string {
	changes := []string{}

	// Access-Control-Allow-Origin 变化
	if origMeta.AccessControlAllowOrigin != newMeta.AccessControlAllowOrigin {
		if newMeta.AccessControlAllowOrigin == "*" {
			changes = append(changes, "CORS:允许所有源")
		} else if newMeta.AccessControlAllowOrigin != "" {
			changes = append(changes, "CORS:Origin变化")
		}
	}

	// Access-Control-Allow-Methods 变化
	if origMeta.AccessControlAllowMethods != newMeta.AccessControlAllowMethods &&
		newMeta.AccessControlAllowMethods != "" {
		changes = append(changes, "CORS:Methods扩展")
	}

	// Access-Control-Allow-Headers 变化
	if origMeta.AccessControlAllowHeaders != newMeta.AccessControlAllowHeaders &&
		newMeta.AccessControlAllowHeaders != "" {
		changes = append(changes, "CORS:Headers扩展")
	}

	// Access-Control-Allow-Credentials 变化
	if !origMeta.AccessControlAllowCredentials && newMeta.AccessControlAllowCredentials {
		changes = append(changes, "CORS:Credentials启用")
	}

	// Access-Control-Expose-Headers 变化
	if origMeta.AccessControlExposeHeaders != newMeta.AccessControlExposeHeaders &&
		newMeta.AccessControlExposeHeaders != "" {
		changes = append(changes, "CORS:ExposeHeaders变化")
	}

	if len(changes) == 0 {
		return ""
	}
	return "[" + strings.Join(changes, ",") + "]"
}

// detectSecurityHeaderChanges 检测安全头的变化
// 返回变化描述，空字符串表示无显著变化
func detectSecurityHeaderChanges(origMeta, newMeta ResponseMeta) string {
	changes := []string{}

	// CSP 变化
	if origMeta.ContentSecurityPolicy != newMeta.ContentSecurityPolicy {
		if newMeta.ContentSecurityPolicy == "" {
			changes = append(changes, "CSP缺失")
		} else if strings.Contains(newMeta.ContentSecurityPolicy, "unsafe") {
			changes = append(changes, "CSP宽松")
		} else {
			changes = append(changes, "CSP变化")
		}
	}

	// X-Frame-Options 变化
	if origMeta.XFrameOptions != newMeta.XFrameOptions {
		if newMeta.XFrameOptions == "" {
			changes = append(changes, "X-Frame缺失")
		} else if strings.ToLower(newMeta.XFrameOptions) == "deny" {
			changes = append(changes, "X-Frame:DENY")
		} else if strings.ToLower(newMeta.XFrameOptions) == "sameorigin" {
			// Same origin is OK
		} else {
			changes = append(changes, "X-Frame变化")
		}
	}

	// X-Content-Type-Options 变化
	if origMeta.XContentTypeOptions != newMeta.XContentTypeOptions {
		if newMeta.XContentTypeOptions == "" {
			changes = append(changes, "X-Content-Type缺失")
		} else if strings.ToLower(newMeta.XContentTypeOptions) == "nosniff" {
			// This is good
		} else {
			changes = append(changes, "X-Content-Type变化")
		}
	}

	// HSTS 变化
	if origMeta.StrictTransportSecurity != newMeta.StrictTransportSecurity {
		if newMeta.StrictTransportSecurity == "" {
			changes = append(changes, "HSTS缺失")
		} else {
			changes = append(changes, "HSTS变化")
		}
	}

	if len(changes) == 0 {
		return ""
	}
	return "[" + strings.Join(changes, ",") + "]"
}

// detectResponseTimeAnomaly 检测响应时间异常
// 响应时间异常快可能表示绕过了某些检查
// 响应时间异常慢可能表示触发了 WAF 或其他安全机制
func detectResponseTimeAnomaly(responseTimeMs int64, baselineTimeMs int64) string {
	if responseTimeMs <= 0 || baselineTimeMs <= 0 {
		return ""
	}

	// 如果响应时间小于基线的 10%，可能是绕过了某些检查
	if float64(responseTimeMs) < float64(baselineTimeMs)*0.1 {
		return "[响应极快]"
	}

	// 如果响应时间是基线的 5 倍以上，可能是触发了 WAF
	if float64(responseTimeMs) > float64(baselineTimeMs)*5 && responseTimeMs > 1000 {
		return "[响应慢:WAF嫌疑]"
	}

	return ""
}

// BuildEnhancedSignals 构建增强的信号标记
// 综合 WAF、缓存、CORS、安全头、时间等多维度信号
func BuildEnhancedSignals(origMeta, newMeta ResponseMeta, responseTimeMs, baselineTimeMs int64) string {
	var signals []string

	waf := detectWAFSignature(newMeta, newMeta.Body)
	if waf != "" {
		signals = append(signals, waf)
	}

	cache := detectCacheChanges(origMeta, newMeta)
	if cache != "" {
		signals = append(signals, cache)
	}

	cors := detectCORsChanges(origMeta, newMeta)
	if cors != "" {
		signals = append(signals, cors)
	}

	security := detectSecurityHeaderChanges(origMeta, newMeta)
	if security != "" {
		signals = append(signals, security)
	}

	timeAnomaly := detectResponseTimeAnomaly(responseTimeMs, baselineTimeMs)
	if timeAnomaly != "" {
		signals = append(signals, timeAnomaly)
	}

	if len(signals) == 0 {
		return ""
	}
	return " " + strings.Join(signals, " ")
}
