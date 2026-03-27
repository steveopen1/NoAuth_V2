package analyze

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type WhitelistRule struct {
	Pattern     string `json:"pattern"`
	Description string `json:"description,omitempty"`
	MatchType   string `json:"match_type,omitempty"`
}

type Whitelist struct {
	Rules    []WhitelistRule
	Patterns []*regexp.Regexp
}

func LoadWhitelist(path string) (*Whitelist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read whitelist file: %w", err)
	}

	var rules []WhitelistRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse whitelist JSON: %w", err)
	}

	patterns := make([]*regexp.Regexp, 0, len(rules))
	for _, rule := range rules {
		pattern := rule.Pattern
		if rule.MatchType == "contains" {
			pattern = ".*" + regexp.QuoteMeta(pattern) + ".*"
		}
		re, err := regexp.Compile(pattern)
		if err == nil {
			patterns = append(patterns, re)
		}
	}

	return &Whitelist{Rules: rules, Patterns: patterns}, nil
}

func (w *Whitelist) ShouldFilter(url string, classification string, body []byte) bool {
	if w == nil {
		return false
	}

	for _, re := range w.Patterns {
		if re.MatchString(url) {
			return true
		}
	}

	classLower := strings.ToLower(classification)
	for _, rule := range w.Rules {
		if rule.MatchType == "classification" {
			if strings.Contains(classLower, strings.ToLower(rule.Pattern)) {
				return true
			}
		}
	}

	return false
}

func ParseWhitelistRules(data []byte) ([]WhitelistRule, error) {
	var rules []WhitelistRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}

func LoadWhitelistFromReader(r io.Reader) (*Whitelist, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	rules, err := ParseWhitelistRules(data)
	if err != nil {
		return nil, err
	}

	patterns := make([]*regexp.Regexp, 0, len(rules))
	for _, rule := range rules {
		pattern := rule.Pattern
		if rule.MatchType == "contains" {
			pattern = ".*" + regexp.QuoteMeta(pattern) + ".*"
		}
		re, err := regexp.Compile(pattern)
		if err == nil {
			patterns = append(patterns, re)
		}
	}

	return &Whitelist{Rules: rules, Patterns: patterns}, nil
}

func DefaultWhitelist() *Whitelist {
	rules := []WhitelistRule{
		{Pattern: ".*\\.css$", Description: "CSS files", MatchType: "contains"},
		{Pattern: ".*\\.js$", Description: "JavaScript files", MatchType: "contains"},
		{Pattern: ".*\\.png$", Description: "PNG images", MatchType: "contains"},
		{Pattern: ".*\\.jpg$", Description: "JPEG images", MatchType: "contains"},
		{Pattern: ".*\\.svg$", Description: "SVG images", MatchType: "contains"},
		{Pattern: ".*\\.woff2?$", Description: "Font files", MatchType: "contains"},
		{Pattern: "/favicon", Description: "Favicon requests", MatchType: "contains"},
		{Pattern: "/robots\\.txt", Description: "Robots.txt", MatchType: "contains"},
		{Pattern: "/sitemap\\.xml", Description: "Sitemap", MatchType: "contains"},
	}

	patterns := make([]*regexp.Regexp, 0, len(rules))
	for _, rule := range rules {
		re, _ := regexp.Compile(".*" + regexp.QuoteMeta(rule.Pattern) + ".*")
		patterns = append(patterns, re)
	}

	return &Whitelist{Rules: rules, Patterns: patterns}
}
