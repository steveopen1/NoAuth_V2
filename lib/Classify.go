package lib

import (
	"fmt"
	"io"
	"strings"
)

// Baseline 表示一个接口的响应基准特征
type Baseline struct {
	Code int
	Len  int
	Body []byte // 前 4KB，用于关键词检测
}

// ClassifyContext 双基线判定上下文
// Auth: 鉴权接口的原始响应（预期被拦截）
// NoAuth: 无鉴权接口的响应（预期正常可访问，作为正向基准）
type ClassifyContext struct {
	Auth   Baseline
	NoAuth Baseline
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
		Body: truncateBody(body, 4096),
	}, nil
}

// ClassifyResult 智能判定引擎 v2
//
// 核心改进:
//  1. 双基线比较 — 同时参考 noauth 正向基准和 auth 拦截基准
//  2. 比例阈值 — 长度差异按原始响应比例计算，而非固定 100 字节
//  3. 内容分析 — 检测响应体是否包含登录/错误页面特征，降低误报
//  4. 重定向分析 — 区分跳转到登录页 vs 跳转到业务页面
//  5. 置信度分级 — 高/中/低，帮助红队工程师优先排序
func ClassifyResult(ctx ClassifyContext, newCode, newLen int, bodySnippet []byte, redirectTarget string) string {
	origCode := ctx.Auth.Code
	origLen := ctx.Auth.Len
	noauthCode := ctx.NoAuth.Code
	noauthLen := ctx.NoAuth.Len

	hasLogin := DetectLoginKeywords(bodySnippet)

	// ═══════════════════════════════════════════════════
	// 规则 1: 状态码从拦截变为 200（最强绕过信号）
	// ═══════════════════════════════════════════════════
	if newCode == 200 && isBlockedCode(origCode) {
		// 与无鉴权接口做相似度比较
		if noauthCode == 200 && noauthLen > 0 {
			sim := lengthSimilarity(newLen, noauthLen)
			if sim > 0.9 && !hasLogin {
				// 响应高度接近无鉴权页面，且不含登录特征 → 高置信
				return "可能绕过(高)"
			}
			if sim > 0.7 && !hasLogin {
				return "可能绕过(中)"
			}
		}
		// 没有 noauth 基线或不够相似
		if hasLogin {
			// 返回了 200 但内容是登录页 → WAF/中间件返回了自定义 200 错误页
			return "可能绕过(低)"
		}
		return "可能绕过(中)"
	}

	// ═══════════════════════════════════════════════════
	// 规则 2: 重定向分析（区分登录跳转 vs 业务跳转）
	// ═══════════════════════════════════════════════════
	if newCode == 302 || newCode == 301 {
		if redirectTarget != "" {
			lower := strings.ToLower(redirectTarget)
			loginPaths := []string{
				"login", "signin", "sign-in", "sign_in",
				"auth", "sso", "cas", "oauth", "saml",
				"account", "passport",
			}
			isLoginRedirect := false
			for _, kw := range loginPaths {
				if strings.Contains(lower, kw) {
					isLoginRedirect = true
					break
				}
			}
			if !isLoginRedirect {
				// 重定向到非登录路径，可能是绕过后的业务跳转
				target := truncateStr(redirectTarget, 60)
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
	// 规则 4: 同为 200，按比例比较长度差异
	// ═══════════════════════════════════════════════════
	if newCode == 200 && origCode == 200 {
		diff := absInt(newLen - origLen)
		// 按比例计算阈值：原始长度的 20%，最小 50 字节
		threshold := maxInt(origLen/5, 50)

		if diff > threshold {
			// 进一步: 是否更接近 noauth 页面
			if noauthLen > 0 && noauthCode == 200 {
				diffToNoAuth := absInt(newLen - noauthLen)
				if diffToNoAuth < diff && lengthSimilarity(newLen, noauthLen) > 0.8 {
					return "长度差异大(高)"
				}
			}
			return "长度差异大(中)"
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

// DetectLoginKeywords 检测响应体是否包含登录/错误页面特征
// 用于识别 WAF 或中间件返回的伪 200 页面
func DetectLoginKeywords(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := strings.ToLower(string(body))
	keywords := []string{
		// English — 登录相关
		"login", "sign in", "signin", "log in",
		"username", "password", "authenticate",
		// English — 拒绝相关
		"unauthorized", "access denied", "forbidden",
		"not authorized", "permission denied",
		// Chinese
		"登录", "登陆", "用户名", "密码",
		"认证失败", "无权访问", "拒绝访问", "权限不足",
		// HTML 表单特征（登录表单）
		"type=\"password\"", "type='password'",
		"name=\"password\"", "name='password'",
	}
	for _, kw := range keywords {
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
// "可能绕过(高)" → "可能绕过"
// "重定向(需关注→/dashboard)" → "重定向(需关注)"
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
