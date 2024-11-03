package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
)

func main() {

	certificates, err := tls.LoadX509KeyPair("adbkey.pub", "adbkey.key")
	if err != nil {
		fmt.Printf("certificates error err:%+v\r\n", err)
		return
	}
	privateKey, ok := certificates.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		fmt.Printf("certificates error err:%+v\r\n", err)
		return
	}

	//
	hash := sha1.Sum([]byte("dddddddddddddddddddd"))
	//c := new(big.Int).SetBytes(hash[:])
	//signByte := c.Exp(c, privateKey.D, privateKey.N).Bytes()
	// 使用私钥生成 RSA 签名

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.Hash(0), hash[:])
	signature1, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA1, hash[:])
	fmt.Printf("len:%d signature:%+v\r\n", len(signature), signature)
	fmt.Printf("len:%d signature1:%+v\r\n", len(signature1), signature1)

	dd, _ := readRSAPublicKeyFromFile("F:/cert.pem")
	fmt.Printf("dddd n%+v\r\n", dd)
	pubKeyByte, _ := encodeRSAPublicKey(dd)

	fmt.Println("pubKeyByte")
	for _, b := range pubKeyByte {
		fmt.Printf("%02X ", b)
	}
	fmt.Println() // 换行

	fmt.Printf("pubKeyBytelen :%d\r\n", len(pubKeyByte))
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

func reverseBytes(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func adbEncode2(key *rsa.PublicKey) ([]byte, error) {
	moduleSize := 2048 / 8
	moduleSizeWords := moduleSize / 4

	r32 := big.NewInt(0).SetInt64(int64(math.Pow(2, 32)))
	modRemainder := big.NewInt(0).Mod(key.N, r32)
	modInverse := big.NewInt(0).ModInverse(modRemainder, r32)
	n0inv := big.NewInt(0).Sub(r32, modInverse).Int64()

	modules := reverseBytes(key.N.Bytes())

	base := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(int64(moduleSize*8)), nil)

	rr := modPow(base, big.NewInt(2), key.N).Bytes()
	rr = reverseBytes(rr)

	exponent := key.E

	encodedPubKey := make([]byte, 4*3+moduleSize*2)
	buffer := binary.LittleEndian
	buffer.PutUint32(encodedPubKey[:4], uint32(moduleSizeWords))
	buffer.PutUint32(encodedPubKey[4:8], uint32(n0inv))
	if len(modules) < moduleSize {
		copy(encodedPubKey[8:8+len(modules)], modules)
		for i := len(modules); i < moduleSize; i++ {
			encodedPubKey[8+i] = 0
		}
	} else {
		copy(encodedPubKey[8:8+moduleSize], modules[:moduleSize])
	}
	if len(rr) < moduleSize {
		copy(encodedPubKey[8+moduleSize:8+moduleSize+len(rr)], rr)
		for i := len(rr); i < moduleSize; i++ {
			encodedPubKey[8+moduleSize+i] = 0
		}
	} else {
		copy(encodedPubKey[8+moduleSize:8+moduleSize*2], rr[:moduleSize])
	}
	buffer.PutUint32(encodedPubKey[8+moduleSize*2:8+moduleSize*2+4], uint32(exponent))

	return encodedPubKey, nil
}
func modPow(base, exponent, modulus *big.Int) *big.Int {
	result := big.NewInt(1)
	base = base.Mod(base, modulus)
	for exponent.BitLen() > 0 {
		if exponent.Bit(0) == 1 {
			result = result.Mul(result, base).Mod(result, modulus)
		}
		base = base.Mul(base, base).Mod(base, modulus)
		exponent = exponent.Rsh(exponent, 1)
	}
	return result
}

// adbEncode encodes an RSA public key into a byte array in the specific format.
func adbEncode(key *rsa.PublicKey) ([]byte, error) {
	if key == nil || key.N.BitLen() != 2048 {
		return nil, fmt.Errorf("PublicKey is not RSAPublicKey or has incorrect size")
	}

	modulesSize := 2048 / 8
	moduleSizeWords := modulesSize / 4

	// 2^32
	r32 := big.NewInt(0).SetBit(big.NewInt(0), 32, 1)

	// -1 / N[0] mod 2^32
	n0 := new(big.Int).Mod(key.N, r32)
	n0inv := new(big.Int).ModInverse(n0, r32)
	n0inv = new(big.Int).Sub(r32, n0inv)

	// Get modulus as byte array and reverse it
	modules := key.N.Bytes()
	if len(modules) > modulesSize {
		modules = modules[len(modules)-modulesSize:]
	} else if len(modules) < modulesSize {
		modules = append(bytes.Repeat([]byte{0}, modulesSize-len(modules)), modules...)
	}
	modules = reverseBytes(modules)

	// (2^(rsa_size)) ^ 2 mod N
	rr := new(big.Int).Lsh(big.NewInt(1), uint(modulesSize*8))
	rr.Mod(rr, key.N)
	rrBytes := rr.Bytes()
	if len(rrBytes) > modulesSize {
		rrBytes = rrBytes[len(rrBytes)-modulesSize:]
	} else if len(rrBytes) < modulesSize {
		rrBytes = append(bytes.Repeat([]byte{0}, modulesSize-len(rrBytes)), rrBytes...)
	}
	rrBytes = reverseBytes(rrBytes)

	exponent := int32(key.E)

	bb := bytes.NewBuffer([]byte{})
	binary.Write(bb, binary.LittleEndian, moduleSizeWords)
	binary.Write(bb, binary.LittleEndian, int32(n0inv.Int64()))
	binary.Write(bb, binary.LittleEndian, modules)
	binary.Write(bb, binary.LittleEndian, rrBytes)
	binary.Write(bb, binary.LittleEndian, exponent)

	return bb.Bytes(), nil
}

// reverseBytes reverses the order of elements in a byte slice.
func reverseBytes1(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}

func adbEncode11(key *rsa.PublicKey) ([]byte, error) {
	moduleSize := 2048 / 8
	moduleSizeWords := moduleSize / 4

	r32 := big.NewInt(0).SetBit(big.NewInt(0), 32, 1)

	// Calculate -1 / N[0] mod 2^32
	modRemainder := big.NewInt(0).Mod(key.N, r32)
	modInverse := big.NewInt(0).ModInverse(modRemainder, r32)
	n0inv := big.NewInt(0).Sub(r32, modInverse).Int64()

	modules := key.N.Bytes()
	if len(modules) > moduleSize {
		modules = modules[len(modules)-moduleSize:]
	} else if len(modules) < moduleSize {
		modules = append(make([]byte, moduleSize-len(modules)), modules...)
	}
	modules = reverseBytes(modules)

	// Calculate (2^(rsa_size)) ^ 2 mod N
	two := big.NewInt(2)
	power := big.NewInt(int64(moduleSize * 8))
	twoToThePower := new(big.Int).Exp(two, power, nil)
	rr := new(big.Int).Mod(twoToThePower, key.N)
	rrBytes := rr.Bytes()
	if len(rrBytes) > moduleSize {
		rrBytes = rrBytes[len(rrBytes)-moduleSize:]
	} else if len(rrBytes) < moduleSize {
		padLength := moduleSize - len(rrBytes)
		pad := make([]byte, padLength)
		rrBytes = append(pad, rrBytes...)
	}
	rrBytes = reverseBytes(rrBytes)

	exponent := key.E

	encodedPubKey := make([]byte, 4*3+moduleSize*2)
	buffer := binary.LittleEndian
	buffer.PutUint32(encodedPubKey[:4], uint32(moduleSizeWords))
	buffer.PutUint32(encodedPubKey[4:8], uint32(n0inv))
	copy(encodedPubKey[8:8+moduleSize], modules)
	copy(encodedPubKey[8+moduleSize:8+moduleSize*2], rrBytes)
	buffer.PutUint32(encodedPubKey[8+moduleSize*2:8+moduleSize*2+4], uint32(exponent))

	return encodedPubKey, nil
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
