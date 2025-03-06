package core

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/pquerna/otp/totp"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"
)

type EasyConnectClient struct {
	httpClient *resty.Client
	cookieJar  http.CookieJar
	queryConn  net.Conn
	clientIp   []byte
	token      *[48]byte
	twfId      string

	endpoint *EasyConnectEndpoint
	ipStack  *stack.Stack

	ctx                context.Context
	cancelFunc         context.CancelFunc
	insecureSkipVerify bool

	server   string
	username string
	password string
}

func GetAddressFormURL(uri *url.URL) string {
	portString := uri.Port()
	if portString != "" {
		return fmt.Sprintf("%s:%s", uri.Host, portString)
	}
	var port = 80
	if uri.Scheme == "https" {
		port = 443
	}
	return fmt.Sprintf("%s:%d", uri.Host, port)
}

func NewEasyConnectClient(vpnUrl *url.URL, insecureSkipVerify bool) *EasyConnectClient {
	ctx, cancel := context.WithCancel(context.Background())
	cookieJar := NewMemoryCookieJar()
	return &EasyConnectClient{
		server:     GetAddressFormURL(vpnUrl),
		cookieJar:  cookieJar,
		httpClient: createRestyClient(vpnUrl.String(), insecureSkipVerify, cookieJar),
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

func createRestyClient(baseUrl string, insecureSkipVerify bool, jar http.CookieJar) *resty.Client {
	return resty.New().
		SetCookieJar(jar).
		SetProxy("http://127.0.0.1:9000").
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: insecureSkipVerify}).
		SetBaseURL(baseUrl).
		SetHeader("User-Agent", "Mozilla/5.0").
		SetRedirectPolicy(resty.NoRedirectPolicy())
}

func (client *EasyConnectClient) Close() error {
	var errs []error

	// 取消所有通过context控制的协程
	if client.cancelFunc != nil {
		client.cancelFunc()
	}

	// 关闭查询IP的连接
	if client.queryConn != nil {
		if err := client.queryConn.Close(); err != nil {
			errs = append(errs, fmt.Errorf("关闭查询连接失败: %w", err))
		}
		client.queryConn = nil
	}

	// 关闭协议栈（假设stack.Stack有Close方法）
	if client.ipStack != nil {
		client.ipStack.Close()
	}

	// 关闭端点资源
	if client.endpoint != nil {
		client.endpoint.Close()
	}

	// 关闭HTTP客户端的空闲连接
	if client.httpClient != nil {
		client.httpClient.GetClient().CloseIdleConnections()
	}

	// 合并错误信息
	if len(errs) > 0 {
		return fmt.Errorf("关闭客户端时发生错误: %v", errs)
	}
	return nil
}

func (client *EasyConnectClient) Login(username string, password string) ([]byte, error) {
	client.username = username
	client.password = password

	// Web login part (Get TWFID & ECAgent Token => Final token used in binary stream)
	twfId, err := LoginWeb(client.httpClient, client.username, client.password)

	// Store TWFID for AuthSMS
	client.twfId = twfId
	if err != nil {
		return nil, err
	}

	return client.LoginByTwfId(twfId)
}

func (client *EasyConnectClient) AuthSMSCode(code string) ([]byte, error) {
	if client.twfId == "" {
		return nil, errors.New("SMS Auth not required")
	}

	twfId, err := SMSAuth(client.httpClient, client.twfId, code)
	if err != nil {
		return nil, err
	}

	return client.LoginByTwfId(twfId)
}

func (client *EasyConnectClient) AuthTOTP(code string) ([]byte, error) {
	if client.twfId == "" {
		return nil, errors.New("TOTP Auth not required")
	}

	twfId, err := TOTPAuth(client.httpClient, client.twfId, code)
	if err != nil {
		return nil, err
	}

	return client.LoginByTwfId(twfId)
}

func (client *EasyConnectClient) LoginByTwfId(twfId string) ([]byte, error) {
	agentToken, err := GetECAgentToken(client.httpClient)
	if err != nil {
		return nil, err
	}

	client.token = (*[48]byte)([]byte(agentToken + twfId))

	// Query IP (keep the connection used so it's not closed too early, otherwise i/o stream will be closed)
	client.clientIp, client.queryConn, err = QueryIp(client.server, client.token, client.insecureSkipVerify)
	if err != nil {
		return nil, err
	}

	return client.clientIp, nil
}

func (client *EasyConnectClient) StartProtocol(debugDump bool) {
	// Link-level endpoint used in gvisor netstack
	client.endpoint = NewEasyConnectEndpoint()
	client.ipStack = SetupStack(client.clientIp, client.endpoint)
	// Sangfor Easyconnect protocol
	StartProtocol(client.endpoint, client.server, client.token, client.clientIp, debugDump, client.ctx, client.insecureSkipVerify)
}

func (client *EasyConnectClient) ServeSocks5(socksBind string, debugDump bool) {
	// Link-level endpoint used in gvisor netstack
	client.StartProtocol(debugDump)
	// Socks5 server
	ServeSocks5(client.ipStack, client.clientIp, socksBind)
}

func NewEasyConnectClientByLogin(vpnUrl *url.URL, username string, password string, twfId string, totpKey string, skipSsl bool) (*EasyConnectClient, error) {
	client := NewEasyConnectClient(vpnUrl, skipSsl)

	t1 := time.Now()
	var ip []byte
	var err error
	if twfId != "" {
		if len(twfId) != 16 {
			return nil, errors.New("len(twfid) should be 16!")
		}
		ip, err = client.LoginByTwfId(twfId)
	} else {
		ip, err = client.Login(username, password)
		if errors.Is(err, ERR_NEXT_AUTH_SMS) {
			fmt.Print(">>>Please enter your sms code<<<:")
			smsCode := ""
			fmt.Scan(&smsCode)

			ip, err = client.AuthSMSCode(smsCode)
		} else if errors.Is(err, ERR_NEXT_AUTH_TOTP) {
			TOTPCode := ""

			if totpKey == "" {
				fmt.Print(">>>Please enter your TOTP Auth code<<<:")
				fmt.Scan(&TOTPCode)
			} else {
				TOTPCode, err = totp.GenerateCode(totpKey, time.Now())
				if err != nil {
					return nil, err
				}
				log.Printf("Generated TOTP code %s", TOTPCode)
			}

			ip, err = client.AuthTOTP(TOTPCode)
		}
	}

	t2 := time.Now()

	if err != nil {
		return nil, err
	}
	log.Printf("Login success, your IP: %d.%d.%d.%d, consuming: %d ms", ip[0], ip[1], ip[2], ip[3], t2.Sub(t1).Milliseconds())
	return client, nil
}
