package core

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/orcaman/concurrent-map/v2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func ServeSocks5Mode1(ipStack *stack.Stack, selfIp []byte, bindAddr string) {

	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithDialAndRequest(func(ctx context.Context, network, addr string, request *socks5.Request) (net.Conn, error) {
			log.Printf("socks dial: %s", addr)

			if network != "tcp" {
				return nil, errors.New("only support tcp")
			}

			parts := strings.Split(addr, ":")
			target, err := net.ResolveIPAddr("ip", parts[0])
			if err != nil {
				return nil, errors.New("resolve ip addr failed: " + parts[0])
			}

			port, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, errors.New("invalid port: " + parts[1])
			}

			addrTarget := tcpip.FullAddress{
				NIC:  defaultNIC,
				Port: uint16(port),
				Addr: tcpip.Address(target.IP),
			}

			bind := tcpip.FullAddress{
				NIC:  defaultNIC,
				Addr: tcpip.Address(selfIp),
			}

			return gonet.DialTCPWithBind(ctx, ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
		}),
	)

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		panic("socks listen failed: " + err.Error())
	}

	log.Printf(">>>SOCKS5 SERVER listening on<<<: " + bindAddr)

	err = server.Serve(listener)
	panic(err)
}

func ServeSocks5Mode2(bindAddr string) {

	auth := NewCustomAuthenticator()
	server := socks5.NewServer(
		socks5.WithLogger(socks5.NewLogger(log.New(os.Stdout, "socks5: ", log.LstdFlags))),
		socks5.WithAuthMethods([]socks5.Authenticator{auth}),
		socks5.WithDialAndRequest(func(ctx context.Context, network, addr string, request *socks5.Request) (_ net.Conn, err error) {

			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("panic: %v", r)
				}
			}()

			log.Printf("socks dial: %s", addr)

			if network != "tcp" {
				return nil, errors.New("only support tcp")
			}

			parts := strings.Split(addr, ":")
			target, err := net.ResolveIPAddr("ip", parts[0])
			if err != nil {
				return nil, errors.New("resolve ip addr failed: " + parts[0])
			}

			port, err := strconv.Atoi(parts[1])
			if err != nil {
				return nil, errors.New("invalid port: " + parts[1])
			}

			upstreamClientKey := request.AuthContext.Payload[AuthContextPayloadUpstreamClientKey]
			client, ok := auth.UpstreamClientPool.Get(upstreamClientKey)

			if !ok || client.IsClosed {
				return nil, errors.New("upstream connect closed")
			}

			client.Touch()
			auth.clientManager.Update(client, upstreamClientKey)

			addrTarget := tcpip.FullAddress{
				NIC:  defaultNIC,
				Port: uint16(port),
				Addr: tcpip.Address(target.IP),
			}

			bind := tcpip.FullAddress{
				NIC:  defaultNIC,
				Addr: tcpip.Address(client.clientIp),
			}

			return gonet.DialTCPWithBind(context.Background(), client.ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
		}),
	)

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		panic("socks listen failed: " + err.Error())
	}

	log.Printf(">>>SOCKS5 SERVER listening on<<<: " + bindAddr)

	err = server.Serve(listener)
	panic(err)
}

const (
	AuthContextPayloadUpstreamClientKey = "upstream_client_key"
	AuthContextPayloadUserAddr          = "user_addr"
	DefaultTimeout                      = time.Minute * 60
	DefaultSkipSsl                      = false
)

var ()

// CustomAuthenticator 实现了 socks5.Authenticator 接口
type CustomAuthenticator struct {
	UpstreamClientPool cmap.ConcurrentMap[string, *EasyConnectClient]
	clientManager      *ClientPoolManager
}

func NewCustomAuthenticator() *CustomAuthenticator {
	auth := &CustomAuthenticator{
		UpstreamClientPool: cmap.New[*EasyConnectClient](),
		clientManager:      NewClientPoolManager(),
	}
	go auth.clientManager.StartCleaner(auth.UpstreamClientPool)
	return auth
}

// Authenticate 实现基于 RFC 1929 的认证逻辑，并管理 easyconnect 容器
// 此处我们额外把认证结果保存到 globalAuthMap，key 为客户端的 RemoteAddr
func (a *CustomAuthenticator) Authenticate(reader io.Reader, writer io.Writer, userAddr string) (_ *socks5.AuthContext, err error) {

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	if _, err := writer.Write([]byte{statute.VersionSocks5, statute.MethodUserPassAuth}); err != nil {
		return nil, err
	}
	userInfo, err := ParseUserInfo(reader, writer)
	if err != nil {
		return nil, err
	}
	key := fmt.Sprintf("%s->->->%s", userInfo.VPNURL, userInfo.Username)
	client, ok := a.UpstreamClientPool.Get(key)
	if !ok || client.IsClosed {
		fmt.Println("用户不存在，正在登录上游客户端")
		tries := 3
		for i := 0; i < tries; i++ {
			client, err = NewEasyConnectClientByLogin(userInfo.VPNURL, userInfo.Username, userInfo.Password, "", "", userInfo.SkipSSL)
			if err != nil {
				if i == tries-1 {
					return nil, err
				}
				time.Sleep(time.Millisecond * 1000)
				log.Printf("出错了，正在重试...")
			} else {
				break
			}
		}
		go client.StartProtocol(false)
		a.UpstreamClientPool.Set(key, client)
		client.IdleTimeout = userInfo.Timeout
		client.MaxLifetime = 24 * time.Hour
		client.Touch()
		a.clientManager.Update(client, key)
	}
	fmt.Println("用户存在")
	_, err = writer.Write([]byte{0x01, 0x00}) // success
	if err != nil {
		return nil, err
	}
	return &socks5.AuthContext{
		Method: a.GetCode(),
		Payload: map[string]string{
			AuthContextPayloadUpstreamClientKey: key,
			AuthContextPayloadUserAddr:          userAddr,
		},
	}, nil
}

func ParseUserInfo(reader io.Reader, writer io.Writer) (UserInfo, error) {

	userInfo := UserInfo{}
	writeError := func(err error) (UserInfo, error) {
		_, writeErr := writer.Write([]byte{0x01, 0x01})
		if writeErr != nil {
			return UserInfo{}, writeErr
		}
		return UserInfo{}, err
	}
	// SOCKS5用户名/密码认证子协商格式:
	// +----+------+----------+------+----------+
	// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	// +----+------+----------+------+----------+
	// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	// +----+------+----------+------+----------+

	// 读取认证版本（应该为0x01）
	var version byte
	if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
		return userInfo, err
	}
	if version != 0x01 {
		return userInfo, errors.New("unsupported authentication version")
	}

	// 读取用户名长度
	var usernameLen byte
	if err := binary.Read(reader, binary.BigEndian, &usernameLen); err != nil {
		return userInfo, err
	}

	// 读取用户名
	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(reader, username); err != nil {
		return userInfo, err
	}

	// 读取密码长度
	var passwordLen byte
	if err := binary.Read(reader, binary.BigEndian, &passwordLen); err != nil {
		return userInfo, err
	}

	// 读取密码
	password := make([]byte, passwordLen)
	if _, err := io.ReadFull(reader, password); err != nil {
		return userInfo, err
	}

	usernameEncoded := string(username)
	passwordEncoded := string(password)

	// URL解码
	decodedUser, err := url.QueryUnescape(usernameEncoded)
	if err != nil {
		return writeError(err)
	}
	password1, err := url.QueryUnescape(passwordEncoded)
	if err != nil {
		return writeError(err)
	}

	userInfo, err = DecodeUserInfo(decodedUser)
	if err != nil {
		return writeError(err)
	}
	userInfo.Password = password1
	return userInfo, nil
}

// GetCode 返回该认证器对应的认证方法代码（此处使用 0x02 表示用户名/密码认证）
func (a *CustomAuthenticator) GetCode() uint8 {
	return 0x02
}

// UserInfo 定义用户信息
type UserInfo struct {
	VPNURL   *url.URL
	Username string
	Password string
	Timeout  time.Duration
	SkipSSL  bool
}

// EncodeUserInfo 将 UserInfo 编码为查询字符串格式，布尔值使用 “0” 和 “1”
func EncodeUserInfo(info UserInfo) string {
	// 对各字段进行 URL 编码
	v := url.QueryEscape(info.VPNURL.String())
	u := url.QueryEscape(info.Username)
	t := url.QueryEscape(info.Timeout.String())

	// 将布尔值转换为 "0" 或 "1"
	var s string
	if info.SkipSSL {
		s = "1"
	} else {
		s = "0"
	}
	s = url.QueryEscape(s)

	// 构造查询字符串格式
	return fmt.Sprintf("v=%s&u=%s&t=%s&s=%s", v, u, t, s)
}

// DecodeUserInfo 从编码字符串中解析出 UserInfo，布尔值解析为 "0" 和 "1"
func DecodeUserInfo(encoded string) (UserInfo, error) {
	values, err := url.ParseQuery(encoded)
	if err != nil {
		return UserInfo{}, err
	}

	info := UserInfo{
		Timeout: DefaultTimeout,
		SkipSSL: DefaultSkipSsl,
	}

	// 解析 VPN URL
	if vpnEncoded := values.Get("v"); vpnEncoded != "" {
		vpnUrl, err := url.QueryUnescape(vpnEncoded)
		if err != nil {
			return info, err
		}
		info.VPNURL, err = url.Parse(vpnUrl)
		if err != nil {
			return info, err
		}
	}
	// 解析 Username
	if userEncoded := values.Get("u"); userEncoded != "" {
		if info.Username, err = url.QueryUnescape(userEncoded); err != nil {
			return info, err
		}
	}
	// 解析 Timeout
	if timeoutEncoded := values.Get("t"); timeoutEncoded != "" {
		var timeoutStr = timeoutEncoded
		info.Timeout, err = time.ParseDuration(timeoutStr)
		if err != nil {
			info.Timeout = DefaultTimeout
		}
	}
	// 解析 SkipSSL 布尔值（"1" 为 true，"0" 为 false）
	if skipEncoded := values.Get("s"); skipEncoded != "" {
		var skipStr = skipEncoded
		if skipStr == "1" {
			info.SkipSSL = true
		} else if skipStr == "0" {
			info.SkipSSL = false
		} else {
			info.SkipSSL = DefaultSkipSsl
		}
	}

	return info, nil
}
