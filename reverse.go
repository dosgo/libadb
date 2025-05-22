package libadb

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

func (adbClient *AdbClient) Reverse(local string, remote string) error {
	if adbClient.adbConn == nil {
		return errors.New("未连接设备")
	}
	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)
	// 构造forward服务命令
	forwardCmd := fmt.Sprintf("reverse:forward:%s;%s\x00", local, remote)

	openMessage := generate_message(A_OPEN, localId, 0, []byte(forwardCmd))
	adbClient.adbConn.Write(openMessage)
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
	clseMessage := generate_message(A_CLSE, localId, int32(remoteId), []byte{})
	adbClient.adbConn.Write(clseMessage)
	return nil
}

func (adbClient *AdbClient) conectHost(message Message) {
	hostInfo := strings.Split(strings.TrimRight(string(message.payload), "\x00"), ":")
	if hostInfo[0] != "tcp" {
		return
	}
	localConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%s", hostInfo[1]))
	if localConn == nil || err != nil {
		return
	}
	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)

	remoteId := message.arg0
	ChannelMapInstance.Bind(localId, remoteId)
	clseMessage := generate_message(A_OKAY, localId, int32(remoteId), []byte{})
	adbClient.adbConn.Write(clseMessage)

	go func() {
		defer localConn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				return
			}
			wrteMessage := generate_message(A_WRTE, localId, int32(remoteId),
				buf[:n])
			adbClient.adbConn.Write(wrteMessage)
		}
	}()

	for {
		msg, err := adbClient.ReadMessage(localId)
		if err != nil {
			return
		}
		if msg.command == A_WRTE {
			localConn.Write(msg.payload)
			okayMessage := generate_message(A_OKAY, localId, int32(remoteId), []byte{})
			adbClient.adbConn.Write(okayMessage)
		}
	}
}
