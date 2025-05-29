package libadb

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

const ADB_HEADER_LENGTH = 24
const SYSTEM_IDENTITY_STRING_HOST = "host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,openscreen_mdns"
const A_CNXN uint32 = 0x4e584e43
const A_OPEN uint32 = 0x4e45504f
const A_OKAY uint32 = 0x59414b4f
const A_CLSE uint32 = 0x45534c43
const A_WRTE uint32 = 0x45545257
const A_STLS uint32 = 0x534c5453
const A_AUTH uint32 = 0x48545541
const A_SYNC uint32 = 0x434e5953

/*
#define ID_STAT MKID('S','T','A','T')
#define ID_LIST MKID('L','I','S','T')
#define ID_ULNK MKID('U','L','N','K')
#define ID_SEND MKID('S','E','N','D')
#define ID_RECV MKID('R','E','C','V')
#define ID_DENT MKID('D','E','N','T')
#define ID_DONE MKID('D','O','N','E')
#define ID_DATA MKID('D','A','T','A')
#define ID_OKAY MKID('O','K','A','Y')
#define ID_FAIL MKID('F','A','I','L')
#define ID_QUIT MKID('Q','U','I','T')
*/

// wireless debug introduced in Android 11, so must use TLS
const A_VERSION uint32 = 0x01000001
const MAX_PAYLOAD int32 = 1024 * 1024
const A_STLS_VERSION uint32 = 0x01000000

const ADB_AUTH_TOKEN uint32 = 1
const ADB_AUTH_SIGNATURE uint32 = 2
const ADB_AUTH_RSAPUBLICKEY uint32 = 3

type Message struct {
	command     uint32
	arg0        uint32
	arg1        uint32
	data_length uint32
	data_check  uint32
	magic       uint32
	payload     []byte
}

type SyncMsg struct {
	id      []byte
	namelen uint32
}

type SyncMsgStat struct {
	id   []byte
	mode uint32
	size uint32
	time uint32
}
type SyncMsgDent struct {
	id      []byte
	Mode    uint32
	Size    uint32
	Time    uint32
	namelen uint32
	Name    string
}

type AdbClient struct {
	CertFile string
	KeyFile  string
	PeerName string
	adbConn  net.Conn
	LocalId  uint32
}

type Framebuffer_head struct {
	version      uint32
	bpp          uint32
	size         uint32
	width        uint32
	height       uint32
	red_offset   uint32
	red_length   uint32
	blue_offset  uint32
	blue_length  uint32
	green_offset uint32
	green_length uint32
	alpha_offset uint32
	alpha_length uint32
}

type Framebuffer_headV2 struct {
	version      uint32
	bpp          uint32
	colorSpace   uint32
	size         uint32
	width        uint32
	height       uint32
	red_offset   uint32
	red_length   uint32
	blue_offset  uint32
	blue_length  uint32
	green_offset uint32
	green_length uint32
	alpha_offset uint32
	alpha_length uint32
}

func get_payload_checksum(data []byte, offset int, length int) int {
	checksum := 0

	// 确保索引不会越界
	endIndex := offset + length
	if endIndex > len(data) {
		endIndex = len(data)
	}

	for i := offset; i < endIndex; i++ {
		checksum += int(data[i])
	}

	return checksum
}

func generate_message(command uint32, arg0 uint32, arg1 int32, data []byte) []byte {
	var message bytes.Buffer
	binary.Write(&message, binary.LittleEndian, command)
	binary.Write(&message, binary.LittleEndian, arg0)
	binary.Write(&message, binary.LittleEndian, arg1)
	if len(data) != 0 {

		binary.Write(&message, binary.LittleEndian, int32(len(data)))
		checksum := get_payload_checksum(data, 0, len(data))
		binary.Write(&message, binary.LittleEndian, int32(checksum))
	} else {
		binary.Write(&message, binary.LittleEndian, int32(0))
		binary.Write(&message, binary.LittleEndian, int32(0))
	}
	binary.Write(&message, binary.LittleEndian, ^command)
	if len(data) != 0 {
		message.Write(data)
	}
	return message.Bytes()
}

func message_parse(conn net.Conn) (Message, error) {
	var buffer = make([]byte, ADB_HEADER_LENGTH)
	_, err := io.ReadFull(conn, buffer)
	var header Message
	if err != nil {
		return header, err
	}
	header.command = binary.LittleEndian.Uint32(buffer[:4])
	header.arg0 = binary.LittleEndian.Uint32(buffer[4:8])
	header.arg1 = binary.LittleEndian.Uint32(buffer[8:12])
	header.data_length = binary.LittleEndian.Uint32(buffer[12:16])
	header.data_check = binary.LittleEndian.Uint32(buffer[16:20])
	header.magic = binary.LittleEndian.Uint32(buffer[20:24])
	if header.data_length > 0 {
		data_raw := make([]byte, header.data_length)
		io.ReadFull(conn, data_raw)
		header.payload = data_raw
	}
	return header, nil
}

func generate_sync_message(id []byte, len uint32) []byte {
	var message bytes.Buffer
	message.Write(id)
	binary.Write(&message, binary.LittleEndian, len)
	return message.Bytes()
}

func (adbClient *AdbClient) Connect(addr string) error {
	if !fileExists(adbClient.CertFile) || !fileExists(adbClient.KeyFile) {
		err := generateCert(adbClient.CertFile, adbClient.KeyFile, adbClient.PeerName)
		if err != nil {
			return err
		}
	}
	//如果连接成功，启动接收协程
	defer func() {
		if adbClient.adbConn != nil {
			go adbClient.recvLoop()
		}
	}()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	// Send CNXN first
	var cnxn_message = generate_message(
		A_CNXN,
		A_VERSION,
		MAX_PAYLOAD,
		[]byte(SYSTEM_IDENTITY_STRING_HOST),
	)
	conn.Write(cnxn_message)
	// Read Auth command
	var message, _ = message_parse(conn)
	if message.command == A_CNXN {
		fmt.Printf("No auth required\r\n")
		adbClient.adbConn = conn
		return nil
	}

	//tls auth android 11+
	if message.command == A_STLS {
		// Send STLS packet
		var stls_message = generate_message(A_STLS, A_STLS_VERSION, 0, []byte{})
		conn.Write(stls_message)

		certificates, err := tls.LoadX509KeyPair(adbClient.CertFile, adbClient.KeyFile)
		if err != nil {
			fmt.Printf("certificates error err:%+v\r\n", err)
			return err
		}

		tlsConfig := tls.Config{
			MinVersion: tls.VersionTLS13,
			MaxVersion: tls.VersionTLS13,
			// 客户端证书和私钥
			Certificates: []tls.Certificate{
				certificates,
			},
			ServerName:         adbClient.PeerName,
			InsecureSkipVerify: true, // 不要跳过证书验证
		}
		//这个设置证书才行
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &certificates, nil
		}

		// 设置密钥对
		conn = tls.Client(conn, &tlsConfig)
		message, _ = message_parse(conn)
		//连接成功
		if message.command == A_CNXN {
			adbClient.adbConn = conn
			return nil
		}
	}
	//android 10
	if message.command == A_AUTH {

		if message.arg0 != ADB_AUTH_TOKEN {
			return errors.New("ddd")
		}

		certificates, err := tls.LoadX509KeyPair(adbClient.CertFile, adbClient.KeyFile)
		if err != nil {
			fmt.Printf("certificates error err:%+v\r\n", err)
			return err
		}
		privateKey, ok := certificates.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			fmt.Printf("certificates error err:%+v\r\n", err)
			return err
		}
		// 使用私钥生成 RSA 签名
		signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, message.payload)
		if err != nil {
			log.Printf("err:%+v\r\n", err)
			return nil
		}

		var sign_message = generate_message(A_AUTH, ADB_AUTH_SIGNATURE, 0, signature)
		conn.Write(sign_message)
		message, _ = message_parse(conn)
		if message.command == A_AUTH && message.arg0 == ADB_AUTH_TOKEN {
			publicKeybyte, _ := encodeRSAPublicKey(&certificates.PrivateKey.(*rsa.PrivateKey).PublicKey)
			pubKeyByte := base64.StdEncoding.EncodeToString(publicKeybyte)
			pubKeyByte = pubKeyByte + " " + adbClient.PeerName + "\x00"
			var auth_message = generate_message(A_AUTH, ADB_AUTH_RSAPUBLICKEY, 0, []byte(pubKeyByte))
			conn.Write(auth_message)
			message, _ = message_parse(conn)
		}
		//连接成功
		if message.command == A_CNXN {
			adbClient.adbConn = conn
			return nil
		}
	}
	return errors.New("auth error")
}

func (adbClient *AdbClient) write(chanel chan Message, message Message) {
	select {
	case chanel <- message:
		//fmt.Println("发送成功，通道未满")
	default:
		fmt.Println("通道已满，无法发送")
	}
}
func (adbClient *AdbClient) recvLoop() error {
	defer func() {
		if adbClient.adbConn != nil {
			adbClient.adbConn.Close()
			adbClient.adbConn = nil
		}
		ChannelMapInstance.CloseAllAndClear()
	}()
	for {
		message, err := message_parse(adbClient.adbConn)
		if err != nil {
			fmt.Println("recvLoop error:", err)
			return err
		}
		//fmt.Printf("recvLoop message:%d  message.arg0:%d message.arg1:%d\r\n", message.command, message.arg0, message.arg1)
		if len(message.payload) < 50 {
			//fmt.Printf("recvLoop message.payload:%s\r\n", message.payload)

		}
		switch message.command {
		case A_OKAY:
			chanel := ChannelMapInstance.GetChannel(message.arg1, false)
			ChannelMapInstance.Bind(message.arg1, message.arg0)
			if chanel != nil {
				adbClient.write(chanel, message)
			}
		case A_WRTE:
			chanel := ChannelMapInstance.GetChannel(message.arg0, true)
			if chanel != nil {
				adbClient.write(chanel, message)
			}
		case A_CLSE:
			fmt.Printf("A_CLSE arg0:%d\r\n", message.arg0)
			chanel := ChannelMapInstance.GetChannel(message.arg0, true)
			if chanel != nil {
				adbClient.write(chanel, message)
			}
			if message.arg0 == 0 {
				chanel = ChannelMapInstance.GetChannel(message.arg1, false)
				if chanel != nil {
					adbClient.write(chanel, message)
				}
			}
		case A_OPEN:
			fmt.Printf("A_OPEN message:%d  message.arg0:%d message.arg1:%d payload:%s\r\n", message.command, message.arg0, message.arg1, message.payload)

			localConn, err := adbClient.getLocalConnet(message)
			if err != nil {
				continue
			}
			go adbClient.conectHost(message, localConn)
		default:
			fmt.Printf("unknown command\r\n")
		}
	}
}

func (adbClient *AdbClient) ReadMessage(localId uint32) (*Message, error) {
	chanel := ChannelMapInstance.GetChannel(localId, false)
	if chanel == nil {
		return nil, errors.New("channel not found")
	}
	select {
	case message, ok := <-chanel:
		if !ok {
			return nil, errors.New("channel closed")
		}
		return &message, nil
	case <-time.After(30 * time.Second):
		return nil, errors.New("timeout")
	}
}

func printHex(key string, data []byte) {
	fmt.Println(key)
	for _, b := range data {
		fmt.Printf("%02X ", b)
	}
	fmt.Println() // 换行
}

func (adbClient *AdbClient) getLocalId() uint32 {
	adbClient.LocalId++
	ChannelMapInstance.AddChannel(adbClient.LocalId, nil)
	return adbClient.LocalId
}
func (adbClient *AdbClient) Shell(cmd string) (string, error) {
	return adbClient.ShellCmd(cmd, false)
}

func (adbClient *AdbClient) ShellCmd(cmd string, block bool) (string, error) {
	if adbClient.adbConn == nil {
		return "", errors.New("not connect")
	}
	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)
	// Send OPEN
	var shell_cmd = "shell:" + cmd + "\n\x00"
	var open_message = generate_message(A_OPEN, localId, 0, []byte(shell_cmd))
	adbClient.adbConn.Write(open_message)

	// Read OKAY
	message, err := adbClient.ReadMessage(localId)
	if err != nil {
		return "", err
	}
	if message.command != uint32(A_OKAY) {
		log.Printf("Not OKAY command %d\r\n", message.command)
		return "", errors.New("Not OKAY command")
	}
	remoteId := message.arg0
	defer func() {
		clse_message := generate_message(A_CLSE, localId, int32(remoteId), []byte{})
		adbClient.adbConn.Write(clse_message)
	}()
	// Read WRTE
	var out = ""
	for {
		//adbClient.adbConn.SetReadDeadline(time.Now().Add(time.Second * 35))
		message, err := adbClient.ReadMessage(localId)
		if block && err != nil && err.Error() == "timeout" {
			continue
		}
		if block && message == nil {
			break
		}
		if message.command != A_OKAY {
			var okay_message = generate_message(A_OKAY, localId, int32(remoteId), []byte{})
			adbClient.adbConn.Write(okay_message)
		}
		if message.command != uint32(A_WRTE) || message.data_length == 0 {
			break
		}

		if block {
			os.Stdout.Write(message.payload)
		} else {
			out = out + string(message.payload)
		}
	}
	return out, nil
}

func (adbClient *AdbClient) Ls(path string) ([]SyncMsgDent, error) {
	if adbClient.adbConn == nil {
		return nil, errors.New("not connect")
	}
	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)
	// Send OPEN
	var shell_cmd = "sync:\x00"
	var open_message = generate_message(A_OPEN, localId, 0, []byte(shell_cmd))
	adbClient.adbConn.Write(open_message)

	// Read OKAY
	message, err := adbClient.ReadMessage(localId)
	if err != nil {
		fmt.Printf("err:%+v\r\n", err) // 打印错误信息，包括错误类型和错误描述
		return nil, err
	}
	if message.command != uint32(A_OKAY) {
		log.Printf("Ls Not OKAY command:%d err:%+v\r\n", message.command, err)
		return nil, err
	}
	remoteId := int32(message.arg0)
	list_message := generate_sync_message([]byte("LIST"), uint32(len(path)))
	wrte_message := generate_message(A_WRTE, localId, remoteId, append(list_message, []byte(path)...))
	adbClient.adbConn.Write(wrte_message)

	//读取okey
	message, err = adbClient.ReadMessage(localId)
	if message.command != uint32(A_OKAY) {
		log.Printf("Not OKEY command\r\n")
	}
	var readDone = true
	var lists []SyncMsgDent
	for readDone {
		// Read WRTE
		message, err = adbClient.ReadMessage(localId)
		if message.command != uint32(A_WRTE) {
			log.Printf("Not WRTE command:%d\r\n", message.command)
			break
		}
		//	fmt.Printf("data_length:%d\r\n", message.data_length)
		payloadConn := bytes.NewReader(message.payload)
		for {

			var cmd = make([]byte, 4)
			io.ReadFull(payloadConn, cmd)
			if string(cmd) == "DONE" {
				readDone = false
				break
			}
			if string(cmd) != "DENT" {
				break
			}

			var dentHead = make([]byte, 16)
			io.ReadFull(payloadConn, dentHead)

			fileDent := SyncMsgDent{}
			//fileDent.id = cmd
			fileDent.Mode = binary.LittleEndian.Uint32(dentHead[0:4])
			fileDent.Size = binary.LittleEndian.Uint32(dentHead[4:8])
			fileDent.Time = binary.LittleEndian.Uint32(dentHead[8:12])
			fileDent.namelen = binary.LittleEndian.Uint32(dentHead[12:16])
			var name = make([]byte, fileDent.namelen)
			io.ReadFull(payloadConn, name)
			fileDent.Name = string(name)
			lists = append(lists, fileDent)

		}
		// Send OKAY
		var okay_message = generate_message(A_OKAY, localId, remoteId, []byte{})
		adbClient.adbConn.Write(okay_message)
	}
	//send clse
	clse_message := generate_message(A_CLSE, localId, int32(remoteId), []byte{})
	adbClient.adbConn.Write(clse_message)
	return lists, nil
}

func (adbClient *AdbClient) Pull(path string, dest string) error {
	file, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer file.Close()
	fileStat, err := adbClient.PullStream(path, file)
	if err != nil {
		return err
	}
	// 设置文件的修改时间
	os.Chtimes(dest, time.Unix(int64(fileStat.time), 0), time.Unix(int64(fileStat.time), 0))
	// 设置文件的权限
	os.Chmod(dest, os.FileMode(fileStat.mode))
	return nil
}

func (adbClient *AdbClient) PullStream(path string, dest io.Writer) (*SyncMsgStat, error) {
	if adbClient.adbConn == nil {
		return nil, errors.New("not connect")
	}
	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)
	fmt.Printf("PullStream path:%s\r\n", path)
	// 打开通道
	var shell_cmd = "sync:\x00"
	var open_message = generate_message(A_OPEN, localId, 0, []byte(shell_cmd))
	adbClient.adbConn.Write(open_message)

	// 读取remoteId
	message, err := adbClient.ReadMessage(localId)
	if err != nil {
		return nil, err
	}
	if message.command != uint32(A_OKAY) {
		log.Printf("Not OKAY command\r\n")
	}
	remoteId := message.arg0
	//发送 A_write STAT
	stat_message := generate_sync_message([]byte("STAT"), uint32(len(path)))
	wrte_message := generate_message(A_WRTE, localId, int32(remoteId), append(stat_message, []byte(path)...))
	adbClient.adbConn.Write(wrte_message)

	//读取okey
	message, err = adbClient.ReadMessage(localId)
	if err != nil {
		return nil, err
	}
	if message.command != uint32(A_OKAY) {
		log.Printf("Not OKEY command\r\n")
	}
	//fmt.Printf("okey111:%+v\rn", message)
	// Read WRTE响应 stat
	message, err = adbClient.ReadMessage(localId)
	if err != nil {
		return nil, err
	}
	if message.command != uint32(A_WRTE) {
		log.Printf("Not WRTE command\r\n")
	}

	//fmt.Printf("fileStat msg:%+v\r\n", message.payload)
	fileStat := SyncMsgStat{}

	fileStat.mode = binary.LittleEndian.Uint32(message.payload[4:8])
	fileStat.size = binary.LittleEndian.Uint32(message.payload[8:12])
	fileStat.time = binary.LittleEndian.Uint32(message.payload[12:16])

	// Send OKAY
	var okay_message = generate_message(A_OKAY, localId, int32(remoteId), []byte{})
	adbClient.adbConn.Write(okay_message)

	//发送
	//发送 A_write STAT
	recv_message := generate_sync_message([]byte("RECV"), uint32(len(path)))
	wrte_message = generate_message(A_WRTE, localId, int32(remoteId), append(recv_message, []byte(path)...))
	adbClient.adbConn.Write(wrte_message)
	//read okey
	message, err = adbClient.ReadMessage(localId)
	if err != nil {
		return nil, err
	}
	if message.command != uint32(A_OKAY) {
		log.Printf("Not OKEY command\r\n")
	}

	var fileBuf []byte
	var recvRun = true
	for recvRun {
		//read A_write
		message, err = adbClient.ReadMessage(localId)
		if message.command != uint32(A_WRTE) || message.data_length < 1 || err != nil {
			log.Printf("Not A_WRTE command1111111111\r\n")
			break
		}
		fileBuf = append(fileBuf, message.payload...)
		// Send OKAY
		okay_message = generate_message(A_OKAY, localId, int32(remoteId), []byte{})
		adbClient.adbConn.Write(okay_message)
		for {
			if len(fileBuf) < 8 {
				break
			}
			if string(fileBuf[:4]) == "DONE" {
				recvRun = false
				break
			}
			if string(fileBuf[:4]) != string("DATA") {
				fmt.Printf("not data:%+v\r\n", fileBuf[:4])
				break
			}

			datalen := binary.LittleEndian.Uint32(fileBuf[4:])
			if len(fileBuf) >= int(datalen)+8 {
				_, err := dest.Write(fileBuf[8 : 8+datalen])
				if err != nil {
					log.Printf("dest write err:%+v\r\n", err)
				}
				if len(fileBuf) == int(datalen)+8 {
					fileBuf = []byte{}
				} else {
					fileBuf = fileBuf[8+datalen:]
				}
			} else {
				break
			}
		}
	}

	quit_message := generate_sync_message([]byte("QUIT"), 0)
	wrte_message = generate_message(A_WRTE, localId, int32(remoteId), append(quit_message))
	adbClient.adbConn.Write(wrte_message)

	//read okey
	message, err = adbClient.ReadMessage(localId)

	//send clse
	clse_message := generate_message(A_CLSE, localId, int32(remoteId), []byte{})
	adbClient.adbConn.Write(clse_message)
	//read okey
	adbClient.ReadMessage(localId)
	return &fileStat, nil
}

func (adbClient *AdbClient) Push(localFile string, remotePath string, mode int) error {
	if adbClient.adbConn == nil {
		return errors.New("not connect")
	}
	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)
	// 打开通道
	var shell_cmd = "sync:\x00"
	var open_message = generate_message(A_OPEN, localId, 0, []byte(shell_cmd))
	adbClient.adbConn.Write(open_message)

	// 读取remoteId

	message, err := adbClient.ReadMessage(localId)
	if err != nil {
		return err
	}
	if message.command != uint32(A_OKAY) {
		return errors.New("Not OKEY command 1")
	}
	remoteId := message.arg0

	//发送
	//发送 A_write SEND
	sendBuf := fmt.Sprintf("%s,%d", remotePath, mode)
	recv_message := generate_sync_message([]byte("SEND"), uint32(len(sendBuf)))
	wrte_message := generate_message(A_WRTE, localId, int32(remoteId), append(recv_message, []byte(sendBuf)...))
	adbClient.adbConn.Write(wrte_message)
	//read okey
	message, err = adbClient.ReadMessage(localId)
	if err != nil {
		return err
	}
	if message.command != uint32(A_OKAY) {
		return errors.New("Not OKEY command 4")
	}

	file, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer file.Close()
	// 创建一个 bufio.Reader 实例
	reader := bufio.NewReader(file)
	// 分块读取文件
	bufSize := 64 * 1024 // 每次读取的缓冲区大小
	buffer := make([]byte, bufSize)

	for {
		n, err := reader.Read(buffer)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		//发送 A_write STAT
		data_message := generate_sync_message([]byte("DATA"), uint32(n))
		wrte_message = generate_message(A_WRTE, localId, int32(remoteId), append(data_message, buffer[:n]...))
		adbClient.adbConn.Write(wrte_message)

		adbClient.ReadMessage(localId)
	}

	//发送 A_write DONE
	done_message := generate_sync_message([]byte("DONE"), uint32(time.Now().Unix()))
	wrte_message = generate_message(A_WRTE, localId, int32(remoteId), done_message)
	adbClient.adbConn.Write(wrte_message)

	//read okey
	message, err = adbClient.ReadMessage(localId)
	if err != nil {
		return err
	}
	if message.command != uint32(A_OKAY) {
		return errors.New("Not OKEY command 5")
	}

	//send quit
	quit_message := generate_sync_message([]byte("QUIT"), 0)
	wrte_message = generate_message(A_WRTE, localId, int32(remoteId), append(quit_message))
	adbClient.adbConn.Write(wrte_message)

	//send clse
	clse_message := generate_message(A_CLSE, localId, int32(remoteId), []byte{})
	adbClient.adbConn.Write(clse_message)

	return nil
}

func (adbClient *AdbClient) Install(localFile string) error {
	tmpFile := fmt.Sprintf("/data/local/tmp/%d.apk", time.Now().UnixNano())
	err := adbClient.Push(localFile, tmpFile, 0664)
	if err != nil {
		return err
	}
	adbClient.Shell("pm install " + tmpFile)
	return nil
}

func (adbClient *AdbClient) Reboot() error {
	if adbClient.adbConn == nil {
		return errors.New("not connect")
	}
	localId := adbClient.getLocalId()
	defer ChannelMapInstance.DeleteChannel(localId)
	// Send OPEN
	var shell_cmd = "reboot:\x00"
	var open_message = generate_message(A_OPEN, localId, 0, []byte(shell_cmd))
	adbClient.adbConn.Write(open_message)

	// Read OKAY
	message, err := adbClient.ReadMessage(localId)
	if err != nil {
		return err
	}
	if message.command != uint32(A_OKAY) {
		log.Printf("Not OKAY command\r\n")
		return errors.New("Not OKAY command")
	}
	// Send OKAY
	var okay_message = generate_message(A_OKAY, localId, int32(message.arg0), []byte{})
	adbClient.adbConn.Write(okay_message)
	return nil
}

func (adbClient *AdbClient) Close() error {
	if adbClient.adbConn != nil {
		adbClient.adbConn.Close()
		adbClient.adbConn = nil
	}
	return nil
}
func (adbClient *AdbClient) IsConnect() bool {
	if adbClient.adbConn != nil {
		return true
	}
	return false
}
