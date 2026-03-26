package lib

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ScanSession struct {
	TargetURL       string    `json:"target_url"`
	NoAuthPath      string    `json:"noauth_path"`
	AuthPath        string    `json:"auth_path"`
	StartTime       time.Time `json:"start_time"`
	LastUpdate      time.Time `json:"last_update"`
	CompletedPhases []string  `json:"completed_phases"`
	HitPayloads     []string  `json:"hit_payloads"`
	Status          string    `json:"status"`
}

const sessionFile = ".noauth_session.json"

func SaveSession(targetURL, noauth, auth string, phase string, hitPayloads []string) error {
	session := ScanSession{
		TargetURL:   targetURL,
		NoAuthPath:  noauth,
		AuthPath:    auth,
		StartTime:   time.Now(),
		LastUpdate:  time.Now(),
		Status:      "in_progress",
		HitPayloads: hitPayloads,
	}

	dir := GetOutputDir(targetURL)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	sessionPath := filepath.Join(dir, sessionFile)
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(sessionPath, data, 0644)
}

func LoadSession(targetURL string) (*ScanSession, error) {
	dir := GetOutputDir(targetURL)
	sessionPath := filepath.Join(dir, sessionFile)

	data, err := os.ReadFile(sessionPath)
	if err != nil {
		return nil, err
	}

	var session ScanSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func HasSession(targetURL string) bool {
	dir := GetOutputDir(targetURL)
	sessionPath := filepath.Join(dir, sessionFile)
	_, err := os.Stat(sessionPath)
	return err == nil
}

func DeleteSession(targetURL string) error {
	dir := GetOutputDir(targetURL)
	sessionPath := filepath.Join(dir, sessionFile)
	return os.Remove(sessionPath)
}

func MarkPhaseComplete(targetURL, phase string, hitPayloads []string) error {
	session, err := LoadSession(targetURL)
	if err != nil {
		session = &ScanSession{
			TargetURL:       targetURL,
			LastUpdate:      time.Now(),
			CompletedPhases: []string{},
			HitPayloads:     []string{},
		}
	}

	session.LastUpdate = time.Now()

	found := false
	for _, p := range session.CompletedPhases {
		if p == phase {
			found = true
			break
		}
	}
	if !found {
		session.CompletedPhases = append(session.CompletedPhases, phase)
	}

	for _, h := range hitPayloads {
		found = false
		for _, existing := range session.HitPayloads {
			if existing == h {
				found = true
				break
			}
		}
		if !found {
			session.HitPayloads = append(session.HitPayloads, h)
		}
	}

	dir := GetOutputDir(targetURL)
	sessionPath := filepath.Join(dir, sessionFile)
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(sessionPath, data, 0644)
}

func GetSessionProgress(targetURL string) string {
	session, err := LoadSession(targetURL)
	if err != nil {
		return "无历史会话"
	}

	parts := append([]string(nil), session.CompletedPhases...)

	if len(parts) == 0 {
		return "会话存在但无阶段记录"
	}

	return fmt.Sprintf("已完成: %s", strings.Join(parts, " → "))
}

func ExportSessionToJSON(targetURL string) (string, error) {
	session, err := LoadSession(targetURL)
	if err != nil {
		return "", err
	}

	dir := GetOutputDir(targetURL)
	outputPath := filepath.Join(dir, "session_export.json")

	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return "", err
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return "", err
	}

	return outputPath, nil
}
