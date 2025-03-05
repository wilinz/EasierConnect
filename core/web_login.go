package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

var ERR_NEXT_AUTH_SMS = errors.New("SMS Code required")
var ERR_NEXT_AUTH_TOTP = errors.New("Current user's TOTP bound")

func AuthSms(server string, username string, password string, twfId string, smsCode string) (string, error) {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}

	buf := make([]byte, 40960)

	addr := "https://" + server + "/por/login_sms1.csp?apiversion=1"
	log.Printf("SMS Request: " + addr)
	form := url.Values{
		"svpn_inputsms": {smsCode},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err := c.Do(req)
	if err != nil {
		debug.PrintStack()
		return "", err
	}

	n, _ := resp.Body.Read(buf)
	defer resp.Body.Close()

	if !strings.Contains(string(buf[:n]), "Auth sms suc") {
		debug.PrintStack()
		return "", errors.New("SMS Code verification FAILED: " + string(buf[:n]))
	}

	twfId = string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])[1])
	log.Print("SMS Code verification SUCCESS")

	return twfId, nil
}

// JHong Implementing.......
func TOTPAuth(server string, username string, password string, twfId string, TOTPCode string) (string, error) {
	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}

	buf := make([]byte, 40960)

	addr := "https://" + server + "/por/login_token.csp"
	log.Printf("TOTP token Request: " + addr)
	form := url.Values{
		"svpn_inputtoken": {TOTPCode},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err := c.Do(req)
	if err != nil {
		debug.PrintStack()
		return "", err
	}

	n, _ := resp.Body.Read(buf)
	defer resp.Body.Close()

	if !strings.Contains(string(buf[:n]), "suc") {
		debug.PrintStack()
		return "", errors.New("TOTP token verification FAILED: " + string(buf[:n]))
	}

	twfId = string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])[1])
	log.Print("TOTP verification SUCCESS")

	return twfId, nil
}

func ECAgentToken(server string, twfId string) (string, error) {
	dialConn, err := net.Dial("tcp", server)
	defer dialConn.Close()
	conn := utls.UClient(dialConn, &utls.Config{InsecureSkipVerify: true}, utls.HelloGolang)
	defer conn.Close()

	// WTF???
	// When you establish a HTTPS connection to server and send a valid request with TWFID to it
	// The **TLS ServerHello SessionId** is the first part of token
	log.Printf("ECAgent Request: /por/conf.csp & /por/rclist.csp")
	io.WriteString(conn, "GET /por/conf.csp HTTP/1.1\r\nHost: "+server+"\r\nCookie: TWFID="+twfId+"\r\n\r\nGET /por/rclist.csp HTTP/1.1\r\nHost: "+server+"\r\nCookie: TWFID="+twfId+"\r\n\r\n")

	log.Printf("Server Session ID: %q", conn.HandshakeState.ServerHello.SessionId)

	buf := make([]byte, 40960)
	n, err := conn.Read(buf)
	if n == 0 || err != nil {
		debug.PrintStack()
		return "", errors.New("ECAgent Request invalid: error " + err.Error() + "\n" + string(buf[:n]))
	}

	return hex.EncodeToString(conn.HandshakeState.ServerHello.SessionId)[:31] + "\x00", nil
}

// XML 结构体定义
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

// 创建 resty 客户端
func createRestyClient(baseUrl string) *resty.Client {
	return resty.New().
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetBaseURL(baseUrl).
		SetHeader("User-Agent", "Mozilla/5.0").
		SetRedirectPolicy(resty.NoRedirectPolicy())
}

// WebLogin 处理登录流程
func WebLogin(server, username, password string) (string, error) {
	serverURL := "https://" + server
	client := createRestyClient(serverURL)

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
		SetHeader("Cookie", "TWFID="+authResp.TwfID).
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
		return handleHIDAuth(client, serverURL, authResp.TwfID)
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
func handleHIDAuth(client *resty.Client, serverURL, twfID string) (string, error) {
	hidResp := SubmitHIDResponse{}
	resp, err := client.R().
		SetHeader("Cookie", "TWFID="+twfID).
		SetFormData(map[string]string{
			"hostname":   "",
			"macaddress": generateRandomMACMust(),
			"hid":        ""}).
		SetResult(&hidResp).
		Post("/por/submithid.csp?apiversion=1")

	if err != nil || resp.StatusCode() != 200 {
		return "", fmt.Errorf("HID auth failed: %w", err)
	}

	if !strings.Contains(hidResp.Message, "submit hardid success") {
		return "", fmt.Errorf("HID auth failed with response: %#v\n", hidResp)
	}

	// 更新 TwfID
	if hidResp.TwfID != "" {
		twfID = hidResp.TwfID
	}
	return twfID, nil
}

// 生成 64 字节的随机 HEX 字符串（长度为 128）
func generateRandom64ByteHex() (string, error) {
	// 生成 64 字节的随机数据
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// 将随机字节转换为 HEX 字符串
	hexString := hex.EncodeToString(randomBytes)
	return hexString, nil
}

// 生成 64 字节的随机 HEX 字符串（必须成功，否则 panic）
func generateRandom64ByteHexMust() string {
	hexString, err := generateRandom64ByteHex()
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
