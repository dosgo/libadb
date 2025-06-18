package libadb

import (
	"bufio"
	"io"
)

type BufferedReadWriteCloser struct {
	conn io.ReadWriteCloser // 底层连接
	br   *bufio.Reader      // 读缓冲区
}

// NewBufferedReadWriteCloser 创建一个带缓冲的ReadWriteCloser
func NewBufferedReadWriteCloser(conn io.ReadWriteCloser, size int) *BufferedReadWriteCloser {
	return &BufferedReadWriteCloser{
		conn: conn,
		br:   bufio.NewReaderSize(conn, size),
	}
}

// Read 实现了io.Reader接口，使用缓冲读
func (b *BufferedReadWriteCloser) Read(p []byte) (n int, err error) {
	return b.br.Read(p)
}

// Write 实现了io.Writer接口，使用缓冲写
func (b *BufferedReadWriteCloser) Write(p []byte) (n int, err error) {
	return b.conn.Write(p)
}

// Close 关闭连接，先刷新写缓冲区再关闭底层连接
func (b *BufferedReadWriteCloser) Close() error {
	return b.conn.Close()
}
