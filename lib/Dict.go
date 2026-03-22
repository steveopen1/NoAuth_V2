package lib

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"noauth/poc"
	"os"
)

func Dict(noauth, auth string) {
	fmt.Println(Blue("[+] dict start"))

	fileName := randomFileName()
	file, err := os.Create(fileName)
	if err != nil {
		fmt.Println("[-] 文件创建失败:", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	for _, value := range poc.Summary(noauth, auth) {
		fmt.Println(value)
		_, err := writer.WriteString(value + "\n")
		if err != nil {
			fmt.Println("[-] 写入文件失败:", err)
			return
		}
	}
	writer.Flush()

	fmt.Println(Blue("[+] dict文件已保存:" + fileName))
}

func randomFileName() string {
	bytes := make([]byte, 8) // 8字节随机数据
	_, err := rand.Read(bytes)
	if err != nil {
		fmt.Println("[-] 生成随机文件名失败:", err)
		return "default.txt"
	}
	return hex.EncodeToString(bytes) + ".txt" // 转换为十六进制字符串
}
