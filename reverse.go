package libadb

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

func (adbClient *AdbClient) Reverse(local string, remote string) error {
	if adbClient.adbConn == nil {
		return errors.New("未连接设备")
	}
	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)
	// 构造forward服务命令
	forwardCmd := fmt.Sprintf("reverse:forward:%s;%s\x00", local, remote)

	send_message(adbClient.adbConn, A_OPEN, localId, 0, []byte(forwardCmd))

	// 读取响应
	// Read OKAY
	message, err := adbClient.ReadMessage(localId)
	if err != nil {
		return err
	}
	if message.command != uint32(A_OKAY) {
		err1 := errors.New("转发命令执行失败")
		fmt.Printf("Forward5 err1:%+v\r\n", message)
		return err1
	}
	remoteId := message.arg0
	// 关闭流
	send_message(adbClient.adbConn, A_CLSE, localId, int32(remoteId), []byte{})
	return nil
}

func (adbClient *AdbClient) getLocalConnet(message Message) (net.Conn, error) {
	hostInfo := strings.Split(strings.TrimRight(string(message.payload), "\x00"), ":")
	if hostInfo[0] != "tcp" {
		return nil, errors.New("不支持的协议")
	}
	localConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%s", hostInfo[1]), time.Millisecond*300)
	if localConn == nil || err != nil {
		return nil, err
	}
	return localConn, nil
}
func (adbClient *AdbClient) conectHost(message Message, localConn net.Conn) {

	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)

	remoteId := message.arg0
	ChannelMapInstance.Bind(localId, remoteId)
	send_message(adbClient.adbConn, A_OKAY, localId, int32(remoteId), []byte{})

	go func() {
		buf := make([]byte, 1024*32)
		defer ChannelMapInstance.DeleteChannel(localId)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				return
			}
			send_message(adbClient.adbConn, A_WRTE, localId, int32(remoteId),
				buf[:n])

		}
	}()
	defer localConn.Close()
	for {
		msg, err := adbClient.ReadMessage(localId)
		if err != nil && err.Error() == "timeout" {
			continue
		}
		if err != nil && err.Error() != "timeout" {
			return
		}
		if msg.command == A_WRTE {
			localConn.Write(msg.payload)
			send_message(adbClient.adbConn, A_OKAY, localId, int32(remoteId), []byte{})

		}
	}
}
