package libadb

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
)

func (adbClient *AdbClient) Forward(local string, remote string) error {
	if adbClient.adbConn == nil {
		return errors.New("未连接设备")
	}

	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)
	fmt.Printf("Forward2 localIdL%d\r\n", localId)
	// 构造forward服务命令
	//forwardCmd := fmt.Sprintf("host-serial:172.30.16.134:39379:forward:%s;%s\x00", local, remote)
	forwardCmd := fmt.Sprintf("host:\x00")

	adbClient.send_message(adbClient.adbConn, A_OPEN, localId, 0, []byte(forwardCmd))
	fmt.Printf("forwardCmd:%s\r\n", forwardCmd)
	// 读取响应
	// Read OKAY
	message, err := adbClient.ReadMessage(localId)
	if err != nil {
		return err
	}
	fmt.Printf("Forward4\r\n")
	if message.command != uint32(A_OKAY) {
		err1 := errors.New("转发命令执行失败")
		fmt.Printf("Forward5 err1:%+v\r\n", message)
		return err1
	}
	remoteId := message.arg0
	// 关闭流
	adbClient.send_message(adbClient.adbConn, A_CLSE, localId, int32(remoteId), []byte{})
	localInfo := strings.Split(local, ":")
	fmt.Printf("Forward4 localInfo:%+v\r\n", localInfo)
	if localInfo[0] == "tcp" {
		fmt.Printf("本地端口%s已转发到远程端口%s\r\n", localInfo[1], remote)
		go adbClient.StartForward(localInfo[1], remote)
	}
	return nil
}

func (adbClient *AdbClient) StartForward(localPort string, remote string) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", localPort))
	if err != nil {
		return err
	}

	go func() {
		for {
			localConn, err := listener.Accept()
			if err != nil {
				log.Printf("Accept error: %v", err)
				continue
			}
			go adbClient.handleForwardConnection(localConn, remote)
		}
	}()
	return nil
}

func (adbClient *AdbClient) handleForwardConnection(localConn net.Conn, remote string) {
	defer localConn.Close()

	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)

	// 建立ADB数据通道
	adbClient.send_message(adbClient.adbConn, A_OPEN, localId, 0,
		[]byte(fmt.Sprintf("%s\x00", remote)))

	// Read OKAY
	message, err := adbClient.ReadMessage(localId)
	if err != nil {
		return
	}
	if message.command != uint32(A_OKAY) {
		fmt.Printf("创建数据通道失败: %v\n", "Not OKAY command")
		return
	}
	remoteId := message.arg0
	defer func() {
		adbClient.send_message(adbClient.adbConn, A_CLSE, localId, int32(remoteId), []byte{})
	}()
	// 读写循环
	go func() {
		defer localConn.Close()
		buf := make([]byte, 4096)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				return
			}
			adbClient.send_message(adbClient.adbConn, A_WRTE, localId, int32(remoteId),
				buf[:n])
		}
	}()

	// 接收ADB数据
	for {
		msg, err := adbClient.ReadMessage(localId)
		if err != nil {
			return
		}
		if msg.command == A_WRTE {
			localConn.Write(msg.payload)
			adbClient.send_message(adbClient.adbConn, A_OKAY, localId, int32(remoteId), []byte{})

		}
	}
}
