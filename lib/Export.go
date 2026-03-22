package lib

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/xuri/excelize/v2"
)

// ExportToExcel 将结果数据导出到指定目录下的 Excel 文件
// data 格式: [][]string，每行为 [URL, 响应长度, 状态码]
func ExportToExcel(targetURL, filename string, headers []string, data [][]string) {
	if len(data) == 0 {
		return
	}

	// 从目标 URL 中提取域名作为输出目录
	dir := extractDomain(targetURL)
	if dir == "" {
		dir = "unknown_host"
	}

	// 创建目录（如果不存在）
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf(Red("[-] 创建输出目录失败: %s\n"), err)
		return
	}

	filePath := filepath.Join(dir, filename)

	f := excelize.NewFile()
	defer f.Close()

	sheetName := "Sheet1"

	// 写入表头
	for i, h := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellValue(sheetName, cell, h)
	}

	// 写入数据
	for rowIdx, row := range data {
		for colIdx, val := range row {
			cell, _ := excelize.CoordinatesToCellName(colIdx+1, rowIdx+2)
			f.SetCellValue(sheetName, cell, val)
		}
	}

	// 设置列宽以便于阅读
	f.SetColWidth(sheetName, "A", "A", 80)
	f.SetColWidth(sheetName, "B", "B", 15)
	f.SetColWidth(sheetName, "C", "C", 15)
	f.SetColWidth(sheetName, "D", "D", 15)
	f.SetColWidth(sheetName, "E", "E", 20)

	// 表头加粗样式
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#D9E1F2"}, Pattern: 1},
	})
	for i := range headers {
		cell, _ := excelize.CoordinatesToCellName(i+1, 1)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}

	if err := f.SaveAs(filePath); err != nil {
		fmt.Printf(Red("[-] 保存 Excel 文件失败: %s\n"), err)
		return
	}

	fmt.Printf(Green("[+] 结果已导出到: %s\n"), filePath)
}

// extractDomain 从 URL 中提取域名（含端口），并处理 Windows 不允许目录名含冒号的问题
func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Host
	// Windows 文件系统不允许目录名包含冒号，将 : 替换为 _
	if runtime.GOOS == "windows" {
		host = strings.ReplaceAll(host, ":", "_")
	}
	return host
}
