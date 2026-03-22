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

// SheetData 表示一个 Sheet 的数据
type SheetData struct {
	Name          string     // Sheet 名称
	Headers       []string   // 表头
	Data          [][]string // 数据行
	TotalPayloads int        // 总 Payload/测试用例数
}

// ExportAllToExcel 将多个 Sheet 的数据导出到同一个 Excel 文件
func ExportAllToExcel(targetURL string, sheets []SheetData) {
	var validSheets []SheetData
	for _, s := range sheets {
		if len(s.Data) > 0 {
			validSheets = append(validSheets, s)
		}
	}
	if len(validSheets) == 0 {
		fmt.Println(Yellow("[!] 所有测试结果为空，跳过 Excel 导出"))
		return
	}

	dir := GetOutputDir(targetURL)
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf(Red("[-] 创建输出目录失败: %s\n"), err)
		return
	}

	filePath := filepath.Join(dir, "results.xlsx")

	f := excelize.NewFile()
	defer f.Close()

	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "#FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#4472C4"}, Pattern: 1},
	})

	bypassStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "#9C0006"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"#FFC7CE"}, Pattern: 1},
	})

	for i, sheet := range validSheets {
		sheetName := sheet.Name
		if i == 0 {
			f.SetSheetName("Sheet1", sheetName)
		} else {
			f.NewSheet(sheetName)
		}

		for ci, h := range sheet.Headers {
			cell, _ := excelize.CoordinatesToCellName(ci+1, 1)
			f.SetCellValue(sheetName, cell, h)
			f.SetCellStyle(sheetName, cell, cell, headerStyle)
		}

		for ri, row := range sheet.Data {
			isBypass := false
			for ci, val := range row {
				cell, _ := excelize.CoordinatesToCellName(ci+1, ri+2)
				f.SetCellValue(sheetName, cell, val)
				if IsHighRisk(val) {
					isBypass = true
				}
			}
			if isBypass {
				for ci := range row {
					cell, _ := excelize.CoordinatesToCellName(ci+1, ri+2)
					f.SetCellStyle(sheetName, cell, cell, bypassStyle)
				}
			}
		}

		colWidths := []float64{80, 15, 15, 15, 20, 100}
		for ci := 0; ci < len(sheet.Headers) && ci < len(colWidths); ci++ {
			col, _ := excelize.ColumnNumberToName(ci + 1)
			f.SetColWidth(sheetName, col, col, colWidths[ci])
		}

		lastCol, _ := excelize.ColumnNumberToName(len(sheet.Headers))
		lastRow := len(sheet.Data) + 1
		f.AutoFilter(sheetName, fmt.Sprintf("A1:%s%d", lastCol, lastRow), nil)
	}

	if err := f.SaveAs(filePath); err != nil {
		fmt.Printf(Red("[-] 保存 Excel 文件失败: %s\n"), err)
		return
	}

	fmt.Printf(Green("[+] 结果已导出到: %s\n"), filePath)
}

// GetOutputDir 获取输出目录
func GetOutputDir(targetURL string) string {
	dir := extractDomain(targetURL)
	if dir == "" {
		dir = "unknown_host"
	}
	return dir
}

// extractDomain 从 URL 中提取域名，处理 Windows 冒号问题
func extractDomain(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Host
	if runtime.GOOS == "windows" {
		host = strings.ReplaceAll(host, ":", "_")
	}
	return host
}
