package main

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

const DefaultKey = "2650053489059452"

func md5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
}

func aesEncrypt(plainText, keyStr string) []byte {
	key := []byte(keyStr)
	// PKCS5Padding
	blockSize := aes.BlockSize
	padding := blockSize - len(plainText)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	payload := append([]byte(plainText), padtext...)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	encrypted := make([]byte, len(payload))
	// ECB Mode? Java uses AES/ECB/PKCS5Padding
	// Go's crypto/cipher doesn't support ECB out of the box for security reasons.
	// We implement it manually here by encrypting block by block.

	for bs, be := 0, blockSize; bs < len(payload); bs, be = bs+blockSize, be+blockSize {
		block.Encrypt(encrypted[bs:be], payload[bs:be])
	}
	return encrypted
}

func generateLoginPayload(username, password string) string {
	passHash := md5Hash(password)
	// Timestamp in milliseconds (Java System.currentTimeMillis())
	timestamp := fmt.Sprintf("%d", time.Now().UnixNano()/1e6)

	original := fmt.Sprintf("%s###%s###%s", username, passHash, timestamp)

	// Step 1: Base64(original)
	step1 := base64.StdEncoding.EncodeToString([]byte(original))

	// Step 2: Encrypt(Step1) -> Base64
	// Java: encryptWithDefaultKey(base64Encoded) -> Returns Base64 String
	step2Bytes := aesEncrypt(step1, DefaultKey)
	step2 := base64.StdEncoding.EncodeToString(step2Bytes)

	// Step 3: Encrypt(Step2) -> Base64
	// Java: encryptWithDefaultKey(aesEncrypted1) -> Returns Base64 String
	step3Bytes := aesEncrypt(step2, DefaultKey)
	step3 := base64.StdEncoding.EncodeToString(step3Bytes)

	// Step 4: Base64(Step3)
	// Java: base64Encode(aesEncrypted2)
	finalKey := base64.StdEncoding.EncodeToString([]byte(step3))

	sum := md5Hash(finalKey)
	// Java line 80: md5Hash(hashMap.get("sum") + username + ".....")
	sumBig := md5Hash(sum + username + ".....")
	// Java line 88: md5Hash("......" + hashMap.get("sumBig") + "......")
	sumBigX := md5Hash("......" + sumBig + "......")
	// Java line 96: md5Hash("craftrise#" + username)
	sumBigY := md5Hash("craftrise#" + username)

	payload := map[string]interface{}{
		"messageType": "tryLogin",
		"datas": map[string]string{
			"sumBigX":          sumBigX,
			"password":         password,
			"sumBig":           sumBig,
			"sumBigY":          sumBigY,
			"sum":              sum,
			"key":              finalKey, // This now matches Java's layers
			"username":         username,
			"staticSessionKey": "null",
		},
	}

	jsonData, _ := json.Marshal(payload)
	return string(jsonData)
}

func main() {
	userFlag := flag.String("u", "", "Username")
	passFlag := flag.String("p", "", "Password")
	flag.Parse()

	if *userFlag == "" || *passFlag == "" {
		fmt.Fprintln(os.Stderr, "Usage: create_hashs -u <username> -p <password>")
		os.Exit(1)
	}

	payload := generateLoginPayload(*userFlag, *passFlag)
	fmt.Print(payload)
}
