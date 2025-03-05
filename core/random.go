package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	rand2 "math/rand"
	"strings"
)

const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(length int) string {
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand2.Intn(len(charset))]
	}
	return string(result)
}

// 生成随机 HEX 字符串
func generateRandomHex(length int, uppercase bool) (string, error) {
	randomBytes := make([]byte, length/2)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// 将随机字节转换为 HEX 字符串
	hexString := hex.EncodeToString(randomBytes)
	if uppercase {
		return strings.ToUpper(hexString), nil
	}
	return hexString, nil
}

// 生成 64 字节的随机 HEX 字符串（必须成功，否则 panic）
func generateRandomHexMust(length int, uppercase bool) string {
	hexString, err := generateRandomHex(length, uppercase)
	if err != nil {
		panic(err) // 如果生成失败，直接 panic
	}
	return hexString
}

func generateRandomMACMust() string {
	mac, err := generateRandomMAC()
	if err != nil {
		panic(err) // 如果生成失败，直接 panic
	}
	return mac
}

// 生成随机 MAC 地址
func generateRandomMAC() (string, error) {
	// MAC 地址是 6 字节
	mac := make([]byte, 6)

	// 使用 crypto/rand 生成随机字节
	_, err := rand.Read(mac)
	if err != nil {
		return "", fmt.Errorf("failed to generate random MAC: %w", err)
	}

	// 确保 MAC 地址的第一个字节的最低有效位为 0（表示单播地址）
	// 并且第二最低有效位为 1（表示本地管理的地址）
	mac[0] &= 0xFE // 确保最低有效位为 0
	mac[0] |= 0x02 // 确保第二最低有效位为 1

	// 将字节转换为十六进制字符串
	macHex := hex.EncodeToString(mac)

	// 每两个字符用冒号分隔
	macFormatted := ""
	for i := 0; i < len(macHex); i += 2 {
		if i > 0 {
			macFormatted += ":"
		}
		macFormatted += macHex[i : i+2]
	}

	return macFormatted, nil
}
