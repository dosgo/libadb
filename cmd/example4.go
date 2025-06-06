package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/dosgo/libadb"
	"github.com/gorilla/websocket"
)

func main() {

	http.HandleFunc("/usbWs", handleWebSocket)
	http.Handle("/", http.FileServer(http.Dir("./")))
	http.ListenAndServe(":9999", nil)
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	//如果是usb连接上的websocket

	netConn := NewWebsocketConnAdapter(conn)
	var adbClient = libadb.AdbClient{CertFile: "adbkey.pub", KeyFile: "adbkey.key", PeerName: "test8"}
	fmt.Printf("start UsbConnect\r\n")
	connected := adbClient.UsbConnect(netConn)
	fmt.Printf("connected:%+v", connected)
	startTime := time.Now()
	err = adbClient.Pull("/storage/emulated/0/Download/v9.4.2d_tl_google_demo_20250424_1332.apk", "test.apk")
	fmt.Printf("pull err:%+v", err)
	duration := time.Since(startTime)
	fmt.Printf("duration: %v\n", duration)
	return

}

// 定义适配器结构体
type WebsocketConnAdapter struct {
	conn    *websocket.Conn
	rbuf    []byte // 读缓冲区
	writeMu sync.Mutex
	readMu  sync.Mutex
}

func NewWebsocketConnAdapter(conn *websocket.Conn) *WebsocketConnAdapter {
	return &WebsocketConnAdapter{
		conn: conn,
	}
}

// 实现Read方法
func (a *WebsocketConnAdapter) Read(b []byte) (int, error) {
	a.readMu.Lock()
	defer a.readMu.Unlock()
	// 如果缓冲区有数据，先从中读取
	if len(a.rbuf) > 0 {
		n := copy(b, a.rbuf)
		a.rbuf = a.rbuf[n:]
		fmt.Printf("rbuf\r\n")
		return n, nil
	}

	// 读取下一个WebSocket消息
	msgType, data, err := a.conn.ReadMessage()
	if err != nil {
		return 0, err
	}

	// 只处理二进制和文本消息
	if msgType != websocket.BinaryMessage && msgType != websocket.TextMessage {
		fmt.Printf("eeee\r\n")
		// 跳过非数据帧，继续读取下一个
		return a.Read(b)
	}

	// 将消息放入缓冲区
	a.rbuf = data
	n := copy(b, a.rbuf)
	a.rbuf = a.rbuf[n:]
	return n, nil
}

// 实现Write方法
func (a *WebsocketConnAdapter) Write(b []byte) (int, error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	// 将数据写入为二进制消息
	err := a.conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// 实现Close方法
func (a *WebsocketConnAdapter) Close() error {
	// 发送一个关闭消息并关闭连接
	return a.conn.Close()
}
