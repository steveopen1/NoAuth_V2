//go:build !windows

package lib

// enableWindowsVT 在非 Windows 平台上不需要做任何事
func enableWindowsVT() bool {
	return false
}
