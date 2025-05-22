package libadb

import (
	"errors"
	"fmt"
	"log"
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
	remoteInfo := strings.Split(remote, ":")
	if remoteInfo[0] == "tcp" {
		go adbClient.StartReverse(remoteInfo[1], remote)
	}
	return nil
}

func (adbClient *AdbClient) StartReverse(localPort string, remote string) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", localPort))
	if err != nil {
		fmt.Printf("StartReverse1 err:%+v\r\n", err)
		return err
	}

	go func() {
		for {
			localConn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			fmt.Printf("StartReverse1 addr:\r\n", localConn.LocalAddr())
		}
	}()
	return nil
}
