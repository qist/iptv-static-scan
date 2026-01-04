package output

import (
	"os"
	"path/filepath"
)

// 删除流媒体文件
func DeleteStreamFiles() error {
	files, err := filepath.Glob("stream9527_*")
	if err != nil {
		return err
	}

	for _, file := range files {
		err := os.Remove(file)
		if err != nil {
			// log.Printf("删除文件 %s 失败: %v\n", file, err)
		} else {
			// log.Printf("成功删除文件 %s\n", file)
		}
	}

	return nil
}