package libadb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/dosgo/spake2-go/spake2"
	"golang.org/x/crypto/hkdf"
)

const (
	clientName = "adb pair client\x00"
	serverName = "adb pair server\x00"
	info       = "adb pairing_auth aes-128-gcm key"
	hkdfKeyLen = 16 // 128 bits
	gcmIVLen   = 12
)

type PairingAuthCtx struct {
	spacke2Ctx *spake2.Spake2Ctx
	secretKey  []byte
	password   []byte
	decIV      uint64
	encIV      uint64
}

func createAlice(password []byte) (*PairingAuthCtx, error) {
	return createPairingAuthCtx(0, password)
}

func createPairingAuthCtx(myRole int, _password []byte) (*PairingAuthCtx, error) {
	alice, _ := spake2.SPAKE2_CTX_new(myRole, []byte(clientName), []byte(serverName))
	return &PairingAuthCtx{
		spacke2Ctx: alice,
		password:   _password,
		secretKey:  make([]byte, 16),
	}, nil
}

func (adbClient *AdbClient) Pair(password string, addr string) error {

	if !fileExists(adbClient.CertFile) || !fileExists(adbClient.KeyFile) {
		err := generateCert(adbClient.CertFile, adbClient.KeyFile, adbClient.PeerName)
		if err != nil {
			return err
		}
	}
	// 加载客户端证书和私钥
	clientCert, err := tls.LoadX509KeyPair(adbClient.CertFile, adbClient.KeyFile)
	if err != nil {
		return err
	}

	// 创建TLS配置，并设置客户端证书
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true,
		ClientAuth:         tls.RequireAnyClientCert,
	}

	// 使用TLS配置创建一个TCP连接
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return err
	}
	//conn.Handshake()
	defer conn.Close()
	state := conn.ConnectionState()
	keyMaterial, _ := state.ExportKeyingMaterial("adb-label\x00", nil, 64)
	// 创建Alice（客户端）
	alice, err := createAlice(append([]byte(password), keyMaterial...))
	if err != nil {
		return err
	}

	// 发送客户端的消息
	clientMsg, err := alice.GetMsg()
	if err != nil {
		return err
	}

	headerBuf := packetHeader(1, 0, uint32(len(clientMsg)))
	conn.Write(headerBuf)
	_, err = conn.Write(clientMsg)
	if err != nil {
		return err
	}

	_, _, headerLen := readPacketHeader(conn)
	buf := make([]byte, headerLen)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	serverMsg := buf[:n]
	ok, err := alice.ProcessMsg(serverMsg)
	if !ok || err != nil {
		return err
	}

	//
	peerInfo := adbClient.genPeerInfo(&clientCert.PrivateKey.(*rsa.PrivateKey).PublicKey)
	ciphertext, err := alice.Encrypt(peerInfo)
	if err != nil {
		return err
	}

	peerInfoHead := packetHeader(1, 1, uint32(len(ciphertext)))
	conn.Write(peerInfoHead)
	_, err = conn.Write(ciphertext)
	if err != nil {
		return err
	}
	_, _, bufLen := readPacketHeader(conn)

	// 读取并解密设备的响应
	peerInfoBuf := make([]byte, bufLen)
	n, err = conn.Read(peerInfoBuf)
	if err != nil {
		log.Printf("read err:%+v\r\n", err)
		return err
	}
	encryptedResponse := peerInfoBuf[:n]
	_, err = alice.Decrypt(encryptedResponse)
	if err != nil {
		log.Printf("encrypted err:%+v\r\n", err)
		return err
	}
	return nil
}

func (p *PairingAuthCtx) GetMsg() ([]byte, error) {
	return p.spacke2Ctx.SPAKE2_generate_msg(p.password)
}

func (p *PairingAuthCtx) ProcessMsg(theirMsg []byte) (bool, error) {
	var err error
	buf, err := p.spacke2Ctx.SPAKE2_process_msg(theirMsg)
	if err != nil {
		return false, err
	}
	var keyInfo = "adb pairing_auth aes-128-gcm key"
	// 创建一个新的HKDF实例，使用SHA-256作为哈希函数
	hkdfExtractor := hkdf.New(sha256.New, buf, nil, []byte(keyInfo))
	p.secretKey = make([]byte, hkdfKeyLen)
	// 生成密钥
	if _, err := hkdfExtractor.Read(p.secretKey); err != nil {
		return false, err
	}
	return true, nil
}

func (p *PairingAuthCtx) Encrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.secretKey)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcmIVLen)
	binary.LittleEndian.PutUint64(iv, p.encIV)
	p.encIV++
	return aesGCM.Seal(nil, iv, in, nil), nil
}

func (p *PairingAuthCtx) Decrypt(in []byte) ([]byte, error) {
	block, err := aes.NewCipher(p.secretKey)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		log.Printf("aesGCM err:%+v\r\n", err)
		return nil, err
	}
	iv := make([]byte, gcmIVLen)
	if len(in) < gcmIVLen {
		return nil, fmt.Errorf("ciphertext too short")
	}
	ciphertext := in
	binary.LittleEndian.PutUint64(iv, p.decIV)
	p.decIV++
	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func readPacketHeader(r io.Reader) (byte, byte, uint32) {
	var version byte
	var msgType byte
	var payloadSize uint32
	// 读取版本号
	if err := binary.Read(r, binary.BigEndian, &version); err != nil {
		return version, msgType, payloadSize
	}
	// 读取消息类型
	if err := binary.Read(r, binary.BigEndian, &msgType); err != nil {
		return version, msgType, payloadSize
	}
	// 读取负载大小
	if err := binary.Read(r, binary.BigEndian, &payloadSize); err != nil {
		return version, msgType, payloadSize
	}
	return version, msgType, payloadSize
}

func packetHeader(version byte, msgType byte, payloadSize uint32) []byte {
	var sendBuf bytes.Buffer
	// 使用binary.Write将字段按大端字节序写入缓冲区
	if err := binary.Write(&sendBuf, binary.BigEndian, version); err != nil {
		fmt.Printf("Error writing version: %v\n", err)
		return nil
	}
	if err := binary.Write(&sendBuf, binary.BigEndian, msgType); err != nil {
		fmt.Printf("Error writing type: %v\n", err)
		return nil
	}
	if err := binary.Write(&sendBuf, binary.BigEndian, payloadSize); err != nil {
		fmt.Printf("Error writing payload size: %v\n", err)
		return nil
	}
	return sendBuf.Bytes()
}

func generateCert(_certFile, keyFile string, peerName string) error {
	// 生成 RSA 私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	// 创建证书模板
	template := x509.Certificate{
		Version:               2,
		SerialNumber:          big.NewInt(time.Now().Unix()),
		Subject:               pkix.Name{CommonName: peerName},
		Issuer:                pkix.Name{CommonName: peerName},
		NotBefore:             time.Now().AddDate(0, 0, -1),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		BasicConstraintsValid: false,
		IsCA:                  false,
	}

	// 自签名证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	// 编码私钥为 PEM 格式并写入文件
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	privateKeyFile, err := os.Create(keyFile)
	if err != nil {
		log.Fatalf("创建私钥文件失败: %v", err)
	}
	defer privateKeyFile.Close()
	pem.Encode(privateKeyFile, privateKeyPEM)

	certPEM := &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}
	certFile, err := os.Create(_certFile)
	if err != nil {
		log.Fatalf("创建证书文件失败: %v", err)
	}
	defer certFile.Close()
	pem.Encode(certFile, certPEM)
	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

func readRSAPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	// 读取文件内容
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	// 解析PEM块
	block, _ := pem.Decode(pemData)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("failed to decode PEM block containing the certificate")
	}

	// 解析证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 断言公钥类型为*rsa.PublicKey
	rsaPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("the public key is not an RSA public key")
	}
	return rsaPub, nil
}

const ANDROID_PUBKEY_MODULUS_SIZE = 256
const ANDROID_PUBKEY_ENCODED_SIZE = ANDROID_PUBKEY_MODULUS_SIZE + 8

func encodeRSAPublicKey(publicKey *rsa.PublicKey) ([]byte, error) {
	modulusBytes := publicKey.N.Bytes()
	if len(modulusBytes) < ANDROID_PUBKEY_MODULUS_SIZE {
		return nil, errors.New("Invalid key length")
	}

	var keyStruct bytes.Buffer
	// Store the modulus size.

	binary.Write(&keyStruct, binary.LittleEndian, uint32(ANDROID_PUBKEY_MODULUS_SIZE/4))

	// Compute and store n0inv = -1 / N[0] mod 2^32.
	r32 := big.NewInt(1).Lsh(big.NewInt(1), 32)
	n0 := big.NewInt(0).SetBytes(modulusBytes)
	n0inv := big.NewInt(0).Mod(n0, r32)
	n0inv = n0inv.ModInverse(n0inv, r32)
	n0inv = r32.Sub(r32, n0inv)
	binary.Write(&keyStruct, binary.LittleEndian, uint32(n0inv.Int64()))

	// Store the modulus.
	modulusLittleEndian := bigEndianToLittleEndianPadded(ANDROID_PUBKEY_MODULUS_SIZE, modulusBytes)

	keyStruct.Write(modulusLittleEndian)

	// Compute and store rr = (2^(rsa_size)) ^ 2 mod N.
	rr := big.NewInt(1).Lsh(big.NewInt(1), ANDROID_PUBKEY_MODULUS_SIZE*8)
	rr = rr.Exp(rr, big.NewInt(2), publicKey.N)
	rrLittleEndian := bigEndianToLittleEndianPadded(ANDROID_PUBKEY_MODULUS_SIZE, rr.Bytes())
	keyStruct.Write(rrLittleEndian)

	// Store the exponent.
	binary.Write(&keyStruct, binary.LittleEndian, uint32(publicKey.E))
	return keyStruct.Bytes(), nil
}
func bigEndianToLittleEndianPadded(size int, data []byte) []byte {
	result := make([]byte, size)
	for i, j := 0, len(data)-1; i < size && j >= 0; i, j = i+1, j-1 {
		result[i] = data[j]
	}
	return result
}

func (adbClient *AdbClient) genPeerInfo(publicKey *rsa.PublicKey) []byte {
	ADB_RSA_PUB_KEY := byte(0)
	bufByte := make([]byte, 8192) //这个必须大点
	// 创建一个足够大的缓冲区
	buf := new(bytes.Buffer)
	// 编码公钥
	publicKeybyte, _ := encodeRSAPublicKey(publicKey)
	encodedPublicKey := base64.StdEncoding.EncodeToString(publicKeybyte)
	if _, err := buf.Write([]byte(encodedPublicKey)); err != nil {
		return nil
	}
	// 获取并写入用户信息
	userInfo := fmt.Sprintf(" %s\x00", adbClient.PeerName)
	if _, err := buf.Write([]byte(userInfo)); err != nil {
		return nil
	}
	bufByte[0] = ADB_RSA_PUB_KEY
	copy(bufByte[1:], buf.Bytes())
	return bufByte
}
