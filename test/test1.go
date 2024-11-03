package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {

	pemFile, err := os.ReadFile("adbkey")
	if err != nil {
		fmt.Println("Error reading PEM file:", err)
		return
	}

	// 解析 PEM 数据
	block, _ := pem.Decode(pemFile)

	if block == nil {
		fmt.Println("Error decoding PEM block or not an RSA private key")
		return
	}

	// 解析 RSA 私钥
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("Error parsing RSA private key:", err)
		return
	}
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	fmt.Println("ok:", ok)
	payload := []byte{0x85, 0xe1, 0x66, 0x34, 0xc4, 0xe8, 0x2a, 0xc1, 0x02, 0x45, 0x25, 0x3e, 0xb4, 0x54, 0x4d, 0x0e, 0x3d, 0xff, 0x06, 0x9f}

	signature1, err := rsa.SignPKCS1v15(rand.Reader, rsaPrivateKey, crypto.SHA1, payload[:])
	printHex(" signature1", signature1)

}
func printHex(key string, data []byte) {
	fmt.Println(key)
	for _, b := range data {
		fmt.Printf("%02X ", b)
	}
	fmt.Println() // 换行
}
