package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// TLS 트래픽 시크릿을 바탕으로 HKDF를 통해 키 생성
func deriveKey(secret []byte, label string, length int) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, secret, nil, []byte(label))
	key := make([]byte, length)
	_, err := io.ReadFull(hkdf, key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// AES-GCM 암호화 함수
func encryptAESGCM(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, aesgcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// AES-GCM 복호화 함수
func decryptAESGCM(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func main() {
	// 예시로 사용할 client_application_traffic_secret_0 값
	secretHex := "cf394009d413f7f2e4698eaa73fc2fe51cdbbc1fe317bedc603ca73e26b0b912"
	secret, _ := hex.DecodeString(secretHex)

	// 파생된 AES 키 생성
	label := "tls13 derived key"
	key, err := deriveKey(secret, label, 32) // 256비트 키 생성
	if err != nil {
		fmt.Println("키 파생 실패:", err)
		return
	}
	fmt.Printf("파생된 키: %x\n", key)

	// 암호화할 평문
	plaintext := []byte("Hello, TLS encryption test!")

	// AES-GCM 암호화
	ciphertext, nonce, err := encryptAESGCM(key, plaintext)
	if err != nil {
		fmt.Println("암호화 실패:", err)
		return
	}
	fmt.Printf("암호문: %x\n", ciphertext)
	fmt.Printf("Nonce: %x\n", nonce)

	// AES-GCM 복호화
	decryptedText, err := decryptAESGCM(key, ciphertext, nonce)
	if err != nil {
		fmt.Println("복호화 실패:", err)
		return
	}
	fmt.Printf("복호화된 평문: %s\n", decryptedText)
}
