package output

import (
	"os"
)

// appendToFile 将文本追加到文件中
func AppendToFile(filename, text string) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(text + "\n")
	return err
}

// 清空文件内容
func ClearFileContent(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// 创建一个新的文件（实际上是清空原有内容）
	return nil
}