package lib

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

const (
	textBlack = iota + 30
	textRed
	textGreen
	textYellow
	textBlue
	textPurple
	textCyan
	textWhite
)

// colorEnabled 标记终端是否支持 ANSI 颜色
var colorEnabled = true

func init() {
	// 检测是否支持颜色输出
	colorEnabled = detectColorSupport()
}

// detectColorSupport 检测当前终端是否支持 ANSI 颜色码
func detectColorSupport() bool {
	// 如果设置了 NO_COLOR 环境变量，禁用颜色
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// 强制开启颜色
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}

	// Linux/macOS 默认支持 ANSI
	if runtime.GOOS != "windows" {
		return true
	}

	// Windows: 检测是否在支持 ANSI 的终端中运行
	// Windows Terminal、PowerShell Core、VS Code Terminal、Git Bash 等支持 ANSI
	// 传统 cmd.exe 不支持

	// WT_SESSION 存在说明在 Windows Terminal 中
	if os.Getenv("WT_SESSION") != "" {
		return true
	}

	// TERM_PROGRAM 存在说明在第三方终端（如 VS Code）
	if os.Getenv("TERM_PROGRAM") != "" {
		return true
	}

	// ANSICON 存在说明安装了 ANSICON
	if os.Getenv("ANSICON") != "" {
		return true
	}

	// ConEmuANSI=ON 说明在 ConEmu/Cmder 中
	if strings.ToUpper(os.Getenv("ConEmuANSI")) == "ON" {
		return true
	}

	// TERM 环境变量存在（Git Bash / MSYS2 / Cygwin）
	if os.Getenv("TERM") != "" {
		return true
	}

	// 尝试启用 Windows 10+ 的虚拟终端处理
	if enableWindowsVT() {
		return true
	}

	// 默认: 传统 cmd.exe，不支持颜色
	return false
}

func Black(str string) string {
	return textColor(textBlack, str)
}

func Red(str string) string {
	return textColor(textRed, str)
}
func Yellow(str string) string {
	return textColor(textYellow, str)
}
func Green(str string) string {
	return textColor(textGreen, str)
}
func Cyan(str string) string {
	return textColor(textCyan, str)
}
func Blue(str string) string {
	return textColor(textBlue, str)
}
func Purple(str string) string {
	return textColor(textPurple, str)
}
func White(str string) string {
	return textColor(textWhite, str)
}

func textColor(color int, str string) string {
	if !colorEnabled {
		return str
	}
	return fmt.Sprintf("\x1b[0;%dm%s\x1b[0m", color, str)
}
