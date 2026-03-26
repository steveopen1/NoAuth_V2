package lib

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type SessionFixationCase struct {
	method  string
	url     string
	headers map[string]string
	desc    string
}

type SessionFixationResult struct {
	CanFixate  bool
	SessionID  string
	Vulnerable bool
	Evidence   string
}

func BuildSessionFixationCases(baseURL string) []SessionFixationCase {
	var cases []SessionFixationCase

	loginEndpoints := []string{
		"/login",
		"/signin",
		"/auth/login",
		"/api/login",
		"/api/auth/login",
		"/api/v1/login",
		"/account/login",
		"/user/login",
	}

	for _, login := range loginEndpoints {
		cases = append(cases, SessionFixationCase{
			method:  "GET",
			url:     baseURL + login,
			headers: map[string]string{},
			desc:    fmt.Sprintf("SessionFix[GetSession from %s]", login),
		})

		cases = append(cases, SessionFixationCase{
			method:  "POST",
			url:     baseURL + login,
			headers: map[string]string{},
			desc:    fmt.Sprintf("SessionFix[Login via %s]", login),
		})
	}

	return cases
}

func DetectSessionFixation(targetURL string) (bool, string) {
	testCookies := []string{
		"TEST_Session_ID",
		"SESS_FIXATION_TEST",
		"PHPSESSID=test123",
		"JSESSIONID=test456",
		"SESSION=test789",
		"SESSIONID=testabc",
		"csrf_token=testdef",
	}

	for _, testCookie := range testCookies {
		resp1, err := HttpClient.Get(targetURL)
		if err != nil {
			continue
		}
		defer resp1.Body.Close()

		cookies := extractSessionCookies(resp1)

		if len(cookies) == 0 {
			parts := strings.Split(testCookie, "=")
			if len(parts) == 2 {
				cookies = append(cookies, &http.Cookie{Name: parts[0], Value: parts[1]})
			}
		}

		canAccess := testSessionAccess(targetURL, cookies)
		if canAccess {
			return true, fmt.Sprintf("SessionFixation possible with cookie: %s", testCookie)
		}
	}

	return false, ""
}

func extractSessionCookies(resp *http.Response) []*http.Cookie {
	var sessionCookies []*http.Cookie

	sessionCookieNames := []string{
		"JSESSIONID",
		"PHPSESSID",
		"SESSION",
		"SESSIONID",
		"SESSID",
		"ASP.NET_SessionId",
		"CSRFTOKEN",
		"csrf_token",
		"XSRF-TOKEN",
		"_session_id",
		"connect.sid",
	}

	for _, name := range sessionCookieNames {
		cookies := resp.Cookies()
		for _, cookie := range cookies {
			if cookie.Name == name {
				sessionCookies = append(sessionCookies, cookie)
			}
		}
	}

	return sessionCookies
}

func testSessionAccess(targetURL string, cookies []*http.Cookie) bool {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return false
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	resp, err := HttpClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		bodyStr := strings.ToLower(string(body))

		notAuthKeywords := []string{
			"login", "signin", "password", "username",
			"unauthorized", "denied", "forbidden", "error",
		}

		matchCount := 0
		for _, keyword := range notAuthKeywords {
			if strings.Contains(bodyStr, keyword) {
				matchCount++
			}
		}

		if matchCount < 2 {
			return true
		}
	}

	return false
}

type SessionFixationChecker struct {
	baseURL       string
	sessionCookie *http.Cookie
	authenticated bool
}

func NewSessionFixationChecker(baseURL string) *SessionFixationChecker {
	return &SessionFixationChecker{
		baseURL: baseURL,
	}
}

func (s *SessionFixationChecker) Step1_GetPublicPage() (*http.Cookie, error) {
	resp, err := HttpClient.Get(s.baseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	sessionCookies := extractSessionCookies(resp)
	if len(sessionCookies) > 0 {
		s.sessionCookie = sessionCookies[0]
		return s.sessionCookie, nil
	}

	return nil, fmt.Errorf("no session cookie found")
}

func (s *SessionFixationChecker) Step2_LoginWithFixedSession(username, password string) (bool, error) {
	if s.sessionCookie == nil {
		return false, fmt.Errorf("no session cookie available")
	}

	loginURL, err := url.JoinPath(s.baseURL, "/login")
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest("POST", loginURL, strings.NewReader(fmt.Sprintf("username=%s&password=%s", username, password)))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(s.sessionCookie)

	resp, err := HttpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 || resp.StatusCode == 200 {
		newCookies := extractSessionCookies(resp)
		for _, newCookie := range newCookies {
			if newCookie.Name == s.sessionCookie.Name && newCookie.Value == s.sessionCookie.Value {
				s.authenticated = true
				return true, nil
			}
		}
	}

	return false, nil
}

func (s *SessionFixationChecker) Step3_AccessProtectedWithSameSession() (bool, error) {
	if s.sessionCookie == nil {
		return false, fmt.Errorf("no session cookie available")
	}

	protectedURL, err := url.JoinPath(s.baseURL, "/dashboard")
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest("GET", protectedURL, nil)
	if err != nil {
		return false, err
	}

	req.AddCookie(s.sessionCookie)

	resp, err := HttpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200, nil
}

func (s *SessionFixationChecker) CheckVulnerability() (bool, string) {
	cookie, err := s.Step1_GetPublicPage()
	if err != nil {
		return false, fmt.Sprintf("Step1 failed: %v", err)
	}

	loginSuccess, err := s.Step2_LoginWithFixedSession("testuser", "testpass")
	if err != nil {
		return false, fmt.Sprintf("Step2 failed: %v", err)
	}

	if !loginSuccess {
		return false, "Login did not use the fixed session"
	}

	canAccess, err := s.Step3_AccessProtectedWithSameSession()
	if err != nil {
		return false, fmt.Sprintf("Step3 failed: %v", err)
	}

	if canAccess && s.authenticated {
		return true, fmt.Sprintf("VULNERABLE: Session fixation possible. Cookie %s was not rotated on login", cookie.Name)
	}

	return false, "Session was properly rotated on login"
}

func DetectSessionFixationAdvanced(targetURL string) SessionFixationResult {
	result := SessionFixationResult{}

	sessionID := "malicious_session_id_12345"

	req1, _ := http.NewRequest("GET", targetURL, nil)
	req1.Header.Set("Cookie", fmt.Sprintf("SESSIONID=%s", sessionID))
	resp1, err := HttpClient.Do(req1)
	if err != nil {
		result.Evidence = fmt.Sprintf("Initial request failed: %v", err)
		return result
	}
	defer resp1.Body.Close()

	result.SessionID = sessionID

	cookies := extractSessionCookies(resp1)
	if len(cookies) == 0 {
		cookies = []*http.Cookie{{Name: "SESSIONID", Value: sessionID}}
	}

	loginURL := targetURL
	if !strings.HasSuffix(loginURL, "/login") {
		loginURL = targetURL + "/login"
	}

	req2, _ := http.NewRequest("POST", loginURL, strings.NewReader("username=attacker&password=password"))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req2.AddCookie(c)
	}

	resp2, err := HttpClient.Do(req2)
	if err != nil {
		result.Evidence = fmt.Sprintf("Login request failed: %v", err)
		return result
	}
	defer resp2.Body.Close()

	resp2Cookies := extractSessionCookies(resp2)
	sessionNotChanged := false
	for _, c := range resp2Cookies {
		if c.Name == "SESSIONID" && c.Value == sessionID {
			sessionNotChanged = true
			break
		}
	}

	if sessionNotChanged {
		protectedURL := targetURL
		if !strings.HasSuffix(protectedURL, "/dashboard") {
			protectedURL = targetURL + "/dashboard"
		}

		req3, _ := http.NewRequest("GET", protectedURL, nil)
		for _, c := range cookies {
			req3.AddCookie(c)
		}

		resp3, err := HttpClient.Do(req3)
		if err != nil {
			result.Evidence = fmt.Sprintf("Protected resource request failed: %v", err)
			return result
		}
		defer resp3.Body.Close()

		if resp3.StatusCode == 200 {
			body, _ := io.ReadAll(io.LimitReader(resp3.Body, 1024*1024))
			bodyStr := strings.ToLower(string(body))

			authKeywords := []string{"dashboard", "welcome", "profile", "account", "logout", "settings"}
			foundAuth := false
			for _, kw := range authKeywords {
				if strings.Contains(bodyStr, kw) {
					foundAuth = true
					break
				}
			}

			if foundAuth {
				result.CanFixate = true
				result.Vulnerable = true
				result.Evidence = fmt.Sprintf("Session fixation confirmed: Cookie SESSIONID=%s was reused after login and granted access to protected resource", sessionID)
			}
		}
	} else {
		result.Evidence = "Session ID was rotated on login (secure behavior)"
	}

	return result
}
