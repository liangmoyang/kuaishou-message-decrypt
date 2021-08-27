package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func main(){
	message := "快手传过来的密文"
	secret := "你的快手应用的消息秘钥"

	res, _ := decrypt(message,secret)

	fmt.Println(res)
}

// 快手 - 解密消息体
func decrypt(message, secret string) ([]byte, error) {

	crypt, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return nil, err
	}

	key, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, err
	}

	res, err := aesDecrypt(crypt, key)
	if err != nil {
		return nil, err
	}

	return res, nil
}

//AES解密
func aesDecrypt(crypt, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := make([]byte, aes.BlockSize)
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypt))

	blockMode.CryptBlocks(origData, crypt)
	origData = pKCS5UnPadding(origData)
	return origData, nil
}

// aes反填充
func pKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
