package core

import (
	"EasierConnect/utils"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"golang.org/x/exp/slices"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"net"
	"net/http"
	"net/url"
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
	cookieJar := NewMemoryCookieJar()
	return &EasyConnectClient{
		server:     GetAddressFormURL(vpnUrl),
		cookieJar:  cookieJar,
		httpClient: createRestyClient(vpnUrl.String(), insecureSkipVerify, cookieJar),
	}
}

func createRestyClient(baseUrl string, insecureSkipVerify bool, jar http.CookieJar) *resty.Client {
	return resty.New().
		SetCookieJar(jar).
		SetProxy("http://127.0.0.1:9000").
		SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		SetBaseURL(baseUrl).
		SetHeader("User-Agent", "Mozilla/5.0").
		SetRedirectPolicy(resty.NoRedirectPolicy())
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
	client.clientIp, client.queryConn, err = QueryIp(client.server, client.token)
	if err != nil {
		return nil, err
	}

	return client.clientIp, nil
}

func (client *EasyConnectClient) ServeSocks5(socksBind string, debugDump bool) {
	// Link-level endpoint used in gvisor netstack
	client.endpoint = &EasyConnectEndpoint{}
	client.ipStack = SetupStack(client.clientIp, client.endpoint)

	ip := slices.Clone(client.clientIp)
	utils.ReverseSlices(ip)

	// Sangfor Easyconnect protocol
	StartProtocol(client.endpoint, client.server, client.token, (*[4]byte)(ip), debugDump)

	// Socks5 server
	ServeSocks5(client.ipStack, client.clientIp, socksBind)
}
