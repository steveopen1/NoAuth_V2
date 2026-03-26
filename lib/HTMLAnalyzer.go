package lib

import (
	"regexp"
	"strings"
)

type HTMLAnalyzer struct{}

type HTMLStructure struct {
	Title         string
	Forms         []FormInfo
	Links         []string
	Scripts       []string
	MetaTags      map[string]string
	HasPassword   bool
	HasLogin      bool
	ErrorPatterns []string
}

type FormInfo struct {
	Action      string
	Method      string
	HasUsername bool
	HasPassword bool
	HasEmail    bool
}

func NewHTMLAnalyzer() *HTMLAnalyzer {
	return &HTMLAnalyzer{}
}

func (h *HTMLAnalyzer) Analyze(body []byte) HTMLStructure {
	structure := HTMLStructure{
		MetaTags: make(map[string]string),
	}

	if len(body) == 0 {
		return structure
	}

	lowerBody := strings.ToLower(string(body))

	structure.Title = h.extractTitle(body)
	structure.Forms = h.extractForms(body)
	structure.HasPassword = h.hasPasswordField(body)
	structure.HasLogin = h.hasLoginKeywords(lowerBody)
	structure.ErrorPatterns = h.extractErrorPatterns(body)

	return structure
}

func (h *HTMLAnalyzer) extractTitle(body []byte) string {
	titleRegex := regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	matches := titleRegex.FindSubmatch(body)
	if len(matches) > 1 {
		return strings.TrimSpace(string(matches[1]))
	}
	return ""
}

func (h *HTMLAnalyzer) extractForms(body []byte) []FormInfo {
	formRegex := regexp.MustCompile(`(?i)<form[^>]*>`)
	forms := formRegex.FindAllIndex(body, -1)

	var formInfos []FormInfo
	for _, formIdx := range forms {
		formStart := formIdx[0]
		formEnd := findTagEnd(body, formStart)
		if formEnd == -1 {
			continue
		}

		formContent := body[formStart:formEnd]
		formInfo := FormInfo{}

		actionRegex := regexp.MustCompile(`(?i)action\s*=\s*["']?([^"'\s>]+)`)
		if actionMatch := actionRegex.FindSubmatch(formContent); len(actionMatch) > 1 {
			formInfo.Action = string(actionMatch[1])
		}

		methodRegex := regexp.MustCompile(`(?i)method\s*=\s*["']?([^"'\s>]+)`)
		if methodMatch := methodRegex.FindSubmatch(formContent); len(methodMatch) > 1 {
			formInfo.Method = strings.ToUpper(string(methodMatch[1]))
		}

		formInfo.HasUsername = h.hasInputWithName(formContent, []string{"username", "user", "login", "email", "account"})
		formInfo.HasPassword = h.hasInputWithName(formContent, []string{"password", "pwd", "pass"})
		formInfo.HasEmail = h.hasInputWithName(formContent, []string{"email", "e-mail", "mail"})

		formInfos = append(formInfos, formInfo)
	}

	return formInfos
}

func (h *HTMLAnalyzer) hasInputWithName(content []byte, names []string) bool {
	inputRegex := regexp.MustCompile(`(?i)<input[^>]*>`)
	inputs := inputRegex.FindAll(content, -1)

	for _, input := range inputs {
		for _, name := range names {
			nameRegex := regexp.MustCompile(`(?i)name\s*=\s*["']?([^"'\s>]+)`)
			if match := nameRegex.FindSubmatch(input); len(match) > 1 {
				inputName := strings.ToLower(string(match[1]))
				if strings.Contains(inputName, name) {
					return true
				}
			}
		}
	}
	return false
}

func (h *HTMLAnalyzer) hasPasswordField(body []byte) bool {
	passwordRegex := regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']?password["']?[^>]*>`)
	return passwordRegex.Match(body)
}

func (h *HTMLAnalyzer) hasLoginKeywords(body string) bool {
	loginKeywords := []string{
		"login", "signin", "sign in", "log in",
		"username", "password", "email",
		"remember me", "forgot password", "forgot your password",
		"create account", "register", "signup", "sign up",
	}

	count := 0
	for _, keyword := range loginKeywords {
		if strings.Contains(body, keyword) {
			count++
		}
	}

	return count >= 2
}

func (h *HTMLAnalyzer) extractErrorPatterns(body []byte) []string {
	var patterns []string

	errorKeywords := []string{
		"error", "invalid", "incorrect", "failed",
		"denied", "unauthorized", "forbidden", "blocked",
		"incorrect", "wrong", "mismatch", "expired",
	}

	lowerBody := strings.ToLower(string(body))

	for _, keyword := range errorKeywords {
		if strings.Contains(lowerBody, keyword) {
			patterns = append(patterns, keyword)
		}
	}

	return patterns
}

func (h *HTMLAnalyzer) CompareStructures(orig, new HTMLStructure) (bool, string) {
	var differences []string

	if orig.HasPassword != new.HasPassword {
		if new.HasPassword {
			differences = append(differences, "NewPasswordField")
		} else {
			differences = append(differences, "RemovedPasswordField")
		}
	}

	if orig.HasLogin && !new.HasLogin {
		differences = append(differences, "LoginKeywordsRemoved")
	}

	if len(orig.Forms) != len(new.Forms) {
		differences = append(differences, "FormCountChanged")
	}

	if orig.Title != new.Title && orig.Title != "" && new.Title != "" {
		differences = append(differences, "TitleChanged")
	}

	if len(differences) > 0 {
		return true, strings.Join(differences, ",")
	}

	return false, ""
}

func (h *HTMLAnalyzer) DetectDOMAnomalies(origBody, newBody []byte) (bool, string) {
	origStruct := h.Analyze(origBody)
	newStruct := h.Analyze(newBody)

	changed, diffStr := h.CompareStructures(origStruct, newStruct)
	if changed {
		return true, diffStr
	}

	origLen := len(origBody)
	newLen := len(newBody)
	if origLen > 0 && newLen > 0 {
		lenRatio := float64(newLen) / float64(origLen)
		if lenRatio < 0.5 || lenRatio > 2.0 {
			return true, "BodySizeAnomaly"
		}
	}

	return false, ""
}

func findTagEnd(body []byte, start int) int {
	depth := 1
	for i := start + 1; i < len(body); i++ {
		if body[i] == '>' {
			return i + 1
		}
		if i+1 < len(body) && body[i] == '<' && body[i+1] == '/' {
			depth--
			if depth == 0 {
				return -1
			}
		}
	}
	return -1
}

type DOMChangeDetector struct {
	origTitle         string
	origFormCount     int
	origHasPassword   bool
	origLoginKeywords int
}

func NewDOMChangeDetector(body []byte) *DOMChangeDetector {
	analyzer := NewHTMLAnalyzer()
	structure := analyzer.Analyze(body)

	loginCount := 0
	lowerBody := strings.ToLower(string(body))
	loginWords := []string{"login", "signin", "username", "password", "email", "account"}
	for _, word := range loginWords {
		if strings.Contains(lowerBody, word) {
			loginCount++
		}
	}

	return &DOMChangeDetector{
		origTitle:         structure.Title,
		origFormCount:     len(structure.Forms),
		origHasPassword:   structure.HasPassword,
		origLoginKeywords: loginCount,
	}
}

func (d *DOMChangeDetector) Detect(body []byte) (bool, string) {
	analyzer := NewHTMLAnalyzer()
	structure := analyzer.Analyze(body)

	var changes []string

	if d.origHasPassword && !structure.HasPassword {
		changes = append(changes, "PasswordFieldRemoved")
	}

	if structure.HasPassword && !d.origHasPassword {
		changes = append(changes, "PasswordFieldAdded")
	}

	if len(structure.Forms) < d.origFormCount {
		changes = append(changes, "FormRemoved")
	}

	loginCount := 0
	lowerBody := strings.ToLower(string(body))
	loginWords := []string{"login", "signin", "username", "password", "email", "account"}
	for _, word := range loginWords {
		if strings.Contains(lowerBody, word) {
			loginCount++
		}
	}
	if loginCount < d.origLoginKeywords-1 {
		changes = append(changes, "LoginElementsReduced")
	}

	if structure.Title != "" && d.origTitle != "" && structure.Title != d.origTitle {
		changes = append(changes, "TitleChanged")
	}

	if len(changes) > 0 {
		return true, strings.Join(changes, ",")
	}

	return false, ""
}
