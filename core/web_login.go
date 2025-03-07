package core

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"math/big"
	"regexp"
	"resty.dev/v3"
	"runtime/debug"
	"strconv"
	"strings"
)

var ERR_NEXT_AUTH_SMS = errors.New("SMS Code required")
var ERR_NEXT_AUTH_TOTP = errors.New("Current user's TOTP bound")

func SMSAuth(client *resty.Client, twfId string, smsCode string) (string, error) {

	resp, err := client.R().
		SetFormData(
			map[string]string{
				"svpn_inputsms": smsCode,
			},
		).
		Post("/por/login_sms1.csp?apiversion=1")

	if err != nil {
		debug.PrintStack()
		return "", err
	}

	response := resp.String()

	if !strings.Contains(response, "Auth sms suc") {
		debug.PrintStack()
		return "", errors.New("SMS Code verification FAILED: " + response)
	}

	twfId = regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindStringSubmatch(response)[1]
	log.Print("SMS Code verification SUCCESS")

	return twfId, nil
}

// TOTPAuth JHong Implementing.......
func TOTPAuth(client *resty.Client, twfId string, TOTPCode string) (string, error) {

	resp, err := client.R().
		SetFormData(
			map[string]string{
				"svpn_inputtoken": TOTPCode,
			},
		).
		Post("/por/login_token.csp")

	if err != nil {
		debug.PrintStack()
		return "", err
	}

	response := resp.String()

	if !strings.Contains(response, "suc") {
		debug.PrintStack()
		return "", errors.New("TOTP token verification FAILED: " + response)
	}

	twfId = regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindStringSubmatch(response)[1]
	log.Print("TOTP verification SUCCESS")

	return twfId, nil
}

func GetECAgentToken(client *resty.Client) (string, error) {
	resp1, err := client.R().Get("/por/conf.csp")
	if err != nil {
		debug.PrintStack()
		return "", errors.New("ECAgent Request invalid: error " + err.Error())
	}

	if resp1.StatusCode() != 200 {
		debug.PrintStack()
		return "", errors.New("ECAgent Request failed with status code: " + strconv.Itoa(resp1.StatusCode()))
	}

	resp2, err := client.R().Get("/por/rclist.csp")
	if err != nil {
		debug.PrintStack()
		return "", errors.New("ECAgent Request invalid: error " + err.Error())
	}

	if resp2.StatusCode() != 200 {
		debug.PrintStack()
		return "", errors.New("ECAgent Request failed with status code: " + strconv.Itoa(resp2.StatusCode()))
	}

	if resp1.RawResponse.TLS == nil || len(resp1.RawResponse.TLS.PeerCertificates) == 0 {
		return "", errors.New("no TLS peer certificates found")
	}

	sessionId := resp1.RawResponse.TLS.PeerCertificates[0].SerialNumber.String()
	log.Printf("Server Session ID: %q", sessionId)

	hexString := hex.EncodeToString([]byte(sessionId))
	// 检查 hexString 长度是否足够进行 [:31] 切片操作
	if len(hexString) < 31 {
		return "", errors.New("hex encoded session id is too short")
	}

	return hexString[:31] + "\x00", nil
}

// LoginAuthResponse XML 结构体定义
type LoginAuthResponse struct {
	XMLName       xml.Name `xml:"Auth"`
	ErrorCode     int      `xml:"ErrorCode"`
	Message       string   `xml:"Message"`
	CSRFRandCode  string   `xml:"CSRF_RAND_CODE"`
	TwfID         string   `xml:"TwfID"`
	RSAEncryptKey string   `xml:"RSA_ENCRYPT_KEY"`
	RSAEncryptExp string   `xml:"RSA_ENCRYPT_EXP"`
}

type LoginPswResponse struct {
	XMLName            xml.Name `xml:"Auth"`
	ErrorCode          int      `xml:"ErrorCode"`
	Message            string   `xml:"Message"`
	Result             int      `xml:"Result"`
	CurAuth            int      `xml:"CurAuth"`
	NextAuth           int      `xml:"NextAuth"`
	NextService        string   `xml:"NextService"`
	NextServiceSubType string   `xml:"NextServiceSubType"`
	TwfID              string   `xml:"TwfID"`
}

type SubmitHIDResponse struct {
	XMLName   xml.Name `xml:"Auth"`
	ErrorCode int      `xml:"ErrorCode"`
	Message   string   `xml:"Message"`
	Result    int      `xml:"Result"`
	TwfID     string   `xml:"TwfID"`
}

// LoginWeb 处理登录流程
func LoginWeb(client *resty.Client, username, password string) (string, error) {
	// 第一阶段：获取登录参数
	authResp := LoginAuthResponse{}
	resp, err := client.R().
		SetResult(&authResp).
		Get("/por/login_auth.csp?apiversion=1")

	if err != nil {
		return "", fmt.Errorf("login auth request failed: %w", err)
	}

	if resp.StatusCode() != 200 {
		return "", fmt.Errorf("invalid status code: %d", resp.StatusCode())
	}

	// 处理 RSA 参数
	if authResp.RSAEncryptExp == "" {
		authResp.RSAEncryptExp = "65537"
	}
	if authResp.CSRFRandCode != "" {
		password += "_" + authResp.CSRFRandCode
	}

	// 生成加密密码
	pubKey, err := parseRSAPublicKey(authResp.RSAEncryptKey, authResp.RSAEncryptExp)
	if err != nil {
		return "", fmt.Errorf("RSA key parse failed: %w", err)
	}

	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, []byte(password))
	if err != nil {
		return "", fmt.Errorf("password encryption failed: %w", err)
	}
	encryptedHex := hex.EncodeToString(encrypted)

	// 提交登录请求
	loginResp := LoginPswResponse{}
	resp, err = client.R().
		SetFormData(map[string]string{
			"svpn_rand_code":    "",
			"mitm":              "",
			"svpn_req_randcode": authResp.CSRFRandCode,
			"svpn_name":         username,
			"svpn_password":     encryptedHex,
		}).
		SetResult(&loginResp).
		Post("/por/login_psw.csp?anti_replay=1&encrypt=1&type=cs")

	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}

	// 处理多因素认证
	switch {
	case loginResp.NextService == "auth/sms" || loginResp.NextAuth == 2:
		return authResp.TwfID, ERR_NEXT_AUTH_SMS
	case loginResp.NextService == "auth/token" || loginResp.NextServiceSubType == "totp":
		return authResp.TwfID, ERR_NEXT_AUTH_TOTP
	case loginResp.NextService == "auth/hid":
		return handleHIDAuth(client)
	}

	// 验证最终结果
	if loginResp.Result != 1 && loginResp.Result != 3 {
		return "", fmt.Errorf("login failed (result code: %d)", loginResp.Result)
	}

	// 更新 TwfID
	if loginResp.TwfID != "" {
		authResp.TwfID = loginResp.TwfID
	}
	return authResp.TwfID, nil
}

// 处理 HID 认证
func handleHIDAuth(client *resty.Client) (string, error) {
	hidResp := SubmitHIDResponse{}
	hid := generateRandomHexMust(32, true)
	macAddress := generateRandomMACMust()
	hostname := randomString(20)
	fmt.Println("generateRandomHexMust:", hid, "generateRandomHexMust:", macAddress, "hostname:", hostname)

	resp, err := client.R().
		SetFormData(map[string]string{
			"hostname":   hostname,
			"macaddress": macAddress,
			"hid":        hid,
		}).
		SetResult(&hidResp).
		Post("/por/submithid.csp?apiversion=1")

	if err != nil || resp.StatusCode() != 200 {
		return "", fmt.Errorf("HID auth failed: %w", err)
	}

	if !strings.Contains(hidResp.Message, "submit hardid success") {
		return "", fmt.Errorf("HID auth failed with response: %#v\n", hidResp)
	}

	return hidResp.TwfID, nil
}

// 解析 RSA 公钥
func parseRSAPublicKey(modulusHex, expStr string) (*rsa.PublicKey, error) {
	modulus := new(big.Int)
	if _, ok := modulus.SetString(modulusHex, 16); !ok {
		return nil, errors.New("invalid modulus")
	}

	exp, err := strconv.Atoi(expStr)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent: %w", err)
	}

	return &rsa.PublicKey{
		N: modulus,
		E: exp,
	}, nil
}
