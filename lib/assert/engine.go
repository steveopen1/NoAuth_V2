package assert

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type RuleType string

const (
	RuleTypeSuccessStatus RuleType = "success-status"
	RuleTypeFailStatus    RuleType = "fail-status"
	RuleTypeFailRegex     RuleType = "fail-regex"
	RuleTypeFailSize      RuleType = "fail-size"
	RuleTypeContains      RuleType = "contains"
	RuleTypeNotContains   RuleType = "not-contains"
	RuleTypeAnd           RuleType = "and"
	RuleTypeOr            RuleType = "or"
	RuleTypeNot           RuleType = "not"
)

type AssertRule struct {
	Type   RuleType     `json:"type"`
	Value  string       `json:"value"`
	Margin int          `json:"margin,omitempty"`
	Rules  []AssertRule `json:"rules,omitempty"`
}

type Rule interface {
	Check(resp *http.Response, body []byte, size int) (bool, error)
	Name() string
}

type SuccessStatusRule struct {
	StatusCodes []int
}

func (r *SuccessStatusRule) Check(resp *http.Response, body []byte, size int) (bool, error) {
	for _, code := range r.StatusCodes {
		if resp.StatusCode == code {
			return true, nil
		}
	}
	return false, nil
}

func (r *SuccessStatusRule) Name() string {
	return "success-status"
}

type FailStatusRule struct {
	StatusCode int
}

func (r *FailStatusRule) Check(resp *http.Response, body []byte, size int) (bool, error) {
	if resp.StatusCode == r.StatusCode {
		return true, nil
	}
	return false, nil
}

func (r *FailStatusRule) Name() string {
	return "fail-status"
}

type FailRegexRule struct {
	Pattern *regexp.Regexp
}

func (r *FailRegexRule) Check(resp *http.Response, body []byte, size int) (bool, error) {
	if r.Pattern.Match(body) {
		return true, nil
	}
	return false, nil
}

func (r *FailRegexRule) Name() string {
	return "fail-regex"
}

type FailSizeRule struct {
	Size   int
	Margin int
}

func (r *FailSizeRule) Check(resp *http.Response, body []byte, size int) (bool, error) {
	lowerBound := r.Size - r.Margin
	upperBound := r.Size + r.Margin
	if size < lowerBound || size > upperBound {
		return true, nil
	}
	return false, nil
}

func (r *FailSizeRule) Name() string {
	return "fail-size"
}

type ContainsRule struct {
	Content string
}

func (r *ContainsRule) Check(resp *http.Response, body []byte, size int) (bool, error) {
	if strings.Contains(strings.ToLower(string(body)), strings.ToLower(r.Content)) {
		return true, nil
	}
	return false, nil
}

func (r *ContainsRule) Name() string {
	return "contains"
}

type NotContainsRule struct {
	Content string
}

func (r *NotContainsRule) Check(resp *http.Response, body []byte, size int) (bool, error) {
	if !strings.Contains(strings.ToLower(string(body)), strings.ToLower(r.Content)) {
		return true, nil
	}
	return false, nil
}

func (r *NotContainsRule) Name() string {
	return "not-contains"
}

type AndRule struct {
	Rules []Rule
}

func (r *AndRule) Check(resp *http.Response, body []byte, size int) (bool, error) {
	for _, rule := range r.Rules {
		matched, err := rule.Check(resp, body, size)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

func (r *AndRule) Name() string {
	return "and"
}

type OrRule struct {
	Rules []Rule
}

func (r *OrRule) Check(resp *http.Response, body []byte, size int) (bool, error) {
	for _, rule := range r.Rules {
		matched, err := rule.Check(resp, body, size)
		if err != nil {
			continue
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func (r *OrRule) Name() string {
	return "or"
}

type NotRule struct {
	Rule Rule
}

func (r *NotRule) Check(resp *http.Response, body []byte, size int) (bool, error) {
	matched, err := r.Rule.Check(resp, body, size)
	if err != nil {
		return false, err
	}
	return !matched, nil
}

func (r *NotRule) Name() string {
	return "not"
}

type AssertEngine struct {
	Rules []Rule
}

func NewAssertEngine(rules []AssertRule) (*AssertEngine, error) {
	parsedRules := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		r, err := parseRule(rule)
		if err != nil {
			return nil, err
		}
		parsedRules = append(parsedRules, r)
	}
	return &AssertEngine{Rules: parsedRules}, nil
}

func parseRule(rule AssertRule) (Rule, error) {
	switch rule.Type {
	case RuleTypeSuccessStatus:
		codes := parseStatusCodes(rule.Value)
		return &SuccessStatusRule{StatusCodes: codes}, nil

	case RuleTypeFailStatus:
		var code int
		fmt.Sscanf(rule.Value, "%d", &code)
		return &FailStatusRule{StatusCode: code}, nil

	case RuleTypeFailRegex:
		pattern, err := regexp.Compile(rule.Value)
		if err != nil {
			return nil, fmt.Errorf("invalid regex pattern: %w", err)
		}
		return &FailRegexRule{Pattern: pattern}, nil

	case RuleTypeFailSize:
		var size int
		fmt.Sscanf(rule.Value, "%d", &size)
		return &FailSizeRule{Size: size, Margin: rule.Margin}, nil

	case RuleTypeContains:
		return &ContainsRule{Content: rule.Value}, nil

	case RuleTypeNotContains:
		return &NotContainsRule{Content: rule.Value}, nil

	case RuleTypeAnd:
		subRules := make([]Rule, 0, len(rule.Rules))
		for _, sub := range rule.Rules {
			r, err := parseRule(sub)
			if err != nil {
				return nil, err
			}
			subRules = append(subRules, r)
		}
		return &AndRule{Rules: subRules}, nil

	case RuleTypeOr:
		subRules := make([]Rule, 0, len(rule.Rules))
		for _, sub := range rule.Rules {
			r, err := parseRule(sub)
			if err != nil {
				return nil, err
			}
			subRules = append(subRules, r)
		}
		return &OrRule{Rules: subRules}, nil

	case RuleTypeNot:
		if len(rule.Rules) != 1 {
			return nil, fmt.Errorf("not rule requires exactly one sub-rule")
		}
		sub, err := parseRule(rule.Rules[0])
		if err != nil {
			return nil, err
		}
		return &NotRule{Rule: sub}, nil

	default:
		return nil, fmt.Errorf("unknown rule type: %s", rule.Type)
	}
}

func parseStatusCodes(value string) []int {
	var codes []int
	parts := strings.Split(value, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		var code int
		if _, err := fmt.Sscanf(part, "%d", &code); err == nil {
			codes = append(codes, code)
		}
	}
	return codes
}

func (e *AssertEngine) Check(resp *http.Response, body []byte) (bool, error) {
	if len(e.Rules) == 0 {
		return resp.StatusCode == 200, nil
	}

	size := len(body)
	for _, rule := range e.Rules {
		matched, err := rule.Check(resp, body, size)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

func CheckWithRules(resp *http.Response, body []byte, rules []AssertRule) (bool, error) {
	engine, err := NewAssertEngine(rules)
	if err != nil {
		return false, err
	}
	return engine.Check(resp, body)
}

func ParseRulesJSON(data []byte) ([]AssertRule, error) {
	var rules []AssertRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse rules JSON: %w", err)
	}
	return rules, nil
}

func ParseRulesFromFile(path string) ([]AssertRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}
	return ParseRulesJSON(data)
}

func LoadDefaultRules() []AssertRule {
	return []AssertRule{
		{Type: RuleTypeFailRegex, Value: "(?i)(login|signin|password|username)"},
		{Type: RuleTypeFailRegex, Value: "(?i)(unauthorized|forbidden|denied|access denied)"},
		{Type: RuleTypeFailSize, Value: "0", Margin: 50},
	}
}
