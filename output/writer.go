package output

import (
	"bufio"
	"os"
	"sync"
)

// BufferedWriter 带缓冲的文件写入器，批量刷盘减少系统调用
type BufferedWriter struct {
	mu     sync.Mutex
	file   *os.File
	writer *bufio.Writer
}

// NewBufferedWriter 创建带缓冲的文件写入器
func NewBufferedWriter(filename string) (*BufferedWriter, error) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return &BufferedWriter{
		file:   file,
		writer: bufio.NewWriterSize(file, 64*1024), // 64KB 缓冲
	}, nil
}

// Write 写入一行（带锁，线程安全）
func (bw *BufferedWriter) Write(text string) error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	_, err := bw.writer.WriteString(text)
	if err != nil {
		return err
	}
	err = bw.writer.WriteByte('\n')
	if err != nil {
		return err
	}
	// 每 100 行刷一次盘，由 bufio 自动管理
	return nil
}

// Flush 刷盘
func (bw *BufferedWriter) Flush() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	return bw.writer.Flush()
}

// Close 刷盘并关闭文件
func (bw *BufferedWriter) Close() error {
	bw.mu.Lock()
	defer bw.mu.Unlock()
	if err := bw.writer.Flush(); err != nil {
		return err
	}
	return bw.file.Close()
}

// AppendToFile 将文本追加到文件中（保留旧接口兼容）
func AppendToFile(filename, text string) error {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(text + "\n")
	return err
}

// ClearFileContent 清空文件内容
func ClearFileContent(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	return nil
}
