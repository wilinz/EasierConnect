# EasierConnect

import (
	"context"
	"errors"
	"log"
	"net"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"tailscale.com/net/socks5"
)

func ServeSocks5(ipStack *stack.Stack, selfIp []byte, bindAddr string) {
	server := socks5.Server{
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {

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

			return gonet.DialTCPWithBind(context.Background(), ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
		},
	}

	listener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		panic("socks listen failed: " + err.Error())
	}

	log.Printf(">>>SOCKS5 SERVER listening on<<<: " + bindAddr)

	err = server.Serve(listener)
	panic(err)
}
```

```go
package core

import (
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const defaultNIC tcpip.NICID = 1
const defaultMTU uint32 = 1400

// implements LinkEndpoint
type EasyConnectEndpoint struct {
	dispatcher stack.NetworkDispatcher
	OnRecv     func(buf []byte)
}

func (ep *EasyConnectEndpoint) MTU() uint32 {
	return defaultMTU
}

func (ep *EasyConnectEndpoint) MaxHeaderLength() uint16 {
	return 0
}

func (ep *EasyConnectEndpoint) LinkAddress() tcpip.LinkAddress {
	return ""
}

func (ep *EasyConnectEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}

func (ep *EasyConnectEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	ep.dispatcher = dispatcher
}

func (ep *EasyConnectEndpoint) IsAttached() bool {
	return ep.dispatcher != nil
}

func (ep *EasyConnectEndpoint) Wait() {}

func (ep *EasyConnectEndpoint) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareNone
}

func (ep *EasyConnectEndpoint) AddHeader(buffer *stack.PacketBuffer) {}

func (ep *EasyConnectEndpoint) WritePackets(list stack.PacketBufferList) (int, tcpip.Error) {
	for _, packetBuffer := range list.AsSlice() {
		buf := []byte{}
		for _, t := range packetBuffer.AsSlices() {
			buf = append(buf, t...)
		}

		if ep.OnRecv != nil {
			ep.OnRecv(buf)
		}
	}
	return list.Len(), nil
}

func (ep *EasyConnectEndpoint) WriteTo(buf []byte) {
	if ep.IsAttached() {
		packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: bufferv2.MakeWithData(buf),
		})
		ep.dispatcher.DeliverNetworkPacket(header.IPv4ProtocolNumber, packetBuffer)
		packetBuffer.DecRef()
	}
}

func SetupStack(ip []byte, endpoint *EasyConnectEndpoint) *stack.Stack {

	// init IP stack
	ipStack := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		HandleLocal:        true,
	})

	// create NIC associated to the endpoint
	err := ipStack.CreateNIC(defaultNIC, endpoint)
	if err != nil {
		panic(err)
	}

	// assign ip
	addr := tcpip.Address(ip)
	protoAddr := tcpip.ProtocolAddress{
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   addr,
			PrefixLen: 32,
		},
		Protocol: ipv4.ProtocolNumber,
	}

	err = ipStack.AddProtocolAddress(defaultNIC, protoAddr, stack.AddressProperties{})
	if err != nil {
		panic(err)
	}

	// other settings
	sOpt := tcpip.TCPSACKEnabled(true)
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &sOpt)
	cOpt := tcpip.CongestionControlOption("cubic")
	ipStack.SetTransportProtocolOption(tcp.ProtocolNumber, &cOpt)
	ipStack.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: defaultNIC})

	return ipStack
}

```
[web_login.go](core%2Fweb_login.go)
```go
package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"errors"
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

func WebLogin(server string, username string, password string) (string, error) {
	server = "https://" + server

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}

	addr := server + "/por/login_auth.csp?apiversion=1"
	log.Printf("Login Request: %s", addr)

	resp, err := c.Get(addr)
	if err != nil {
		debug.PrintStack()
		return "", err
	}

	defer resp.Body.Close()

	buf := make([]byte, 40960)
	n, _ := resp.Body.Read(buf)

	twfId := string(regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])[1])
	log.Printf("Twf Id: %s", twfId)

	rsaKey := string(regexp.MustCompile(`<RSA_ENCRYPT_KEY>(.*)</RSA_ENCRYPT_KEY>`).FindSubmatch(buf[:n])[1])
	log.Printf("RSA Key: %s", rsaKey)

	rsaExpMatch := regexp.MustCompile(`<RSA_ENCRYPT_EXP>(.*)</RSA_ENCRYPT_EXP>`).FindSubmatch(buf[:n])
	rsaExp := ""
	if rsaExpMatch != nil {
		rsaExp = string(rsaExpMatch[1])
	} else {
		log.Printf("Warning: No RSA_ENCRYPT_EXP, using default.")
		rsaExp = "65537"
	}
	log.Printf("RSA Exp: %s", rsaExp)

	csrfMatch := regexp.MustCompile(`<CSRF_RAND_CODE>(.*)</CSRF_RAND_CODE>`).FindSubmatch(buf[:n])
	csrfCode := ""
	if csrfMatch != nil {
		csrfCode = string(csrfMatch[1])
		log.Printf("CSRF Code: %s", csrfCode)
		password += "_" + csrfCode
	} else {
		log.Printf("WARNING: No CSRF Code Match. Maybe you're connecting to an older server? Continue anyway...")
	}
	log.Printf("Password to encrypt: %s", password)

	pubKey := rsa.PublicKey{}
	pubKey.E, _ = strconv.Atoi(rsaExp)
	moduls := big.Int{}
	moduls.SetString(rsaKey, 16)
	pubKey.N = &moduls

	encryptedPassword, err := rsa.EncryptPKCS1v15(rand.Reader, &pubKey, []byte(password))
	if err != nil {
		debug.PrintStack()
		return "", err
	}
	encryptedPasswordHex := hex.EncodeToString(encryptedPassword)
	log.Printf("Encrypted Password: %s", encryptedPasswordHex)

	addr = server + "/por/login_psw.csp?anti_replay=1&encrypt=1&type=cs"
	log.Printf("Login Request: %s", addr)

	form := url.Values{
		"svpn_rand_code":    {""},
		"mitm":              {""},
		"svpn_req_randcode": {csrfCode},
		"svpn_name":         {username},
		"svpn_password":     {encryptedPasswordHex},
	}

	req, err := http.NewRequest("POST", addr, strings.NewReader(form.Encode()))
	req.Header.Set("Cookie", "TWFID="+twfId)

	resp, err = c.Do(req)
	if err != nil {
		debug.PrintStack()
		return "", err
	}

	n, _ = resp.Body.Read(buf)
	defer resp.Body.Close()

	// log.Printf("First stage login response: %s", string(buf[:n]))

	// SMS Code Process
	if strings.Contains(string(buf[:n]), "<NextService>auth/sms</NextService>") || strings.Contains(string(buf[:n]), "<NextAuth>2</NextAuth>") {
		log.Print("SMS code required.")

		addr = server + "/por/login_sms.csp?apiversion=1"
		log.Printf("SMS Request: " + addr)
		req, err = http.NewRequest("POST", addr, nil)
		req.Header.Set("Cookie", "TWFID="+twfId)

		resp, err = c.Do(req)
		if err != nil {
			debug.PrintStack()
			return "", err
		}

		n, _ := resp.Body.Read(buf)
		defer resp.Body.Close()

		if !strings.Contains(string(buf[:n]), "验证码已发送到您的手机") && !strings.Contains(string(buf[:n]), "<USER_PHONE>") {
			debug.PrintStack()
			return "", errors.New("unexpected sms resp: " + string(buf[:n]))
		}

		log.Printf("SMS Code is sent or still valid.")

		return twfId, ERR_NEXT_AUTH_SMS
	}

	// TOTP Authnication Process (Edited by JHong)
	if strings.Contains(string(buf[:n]), "<NextService>auth/token</NextService>") || strings.Contains(string(buf[:n]), "<NextServiceSubType>totp</NextServiceSubType>") {
		log.Print("TOTP Authnication required.")
		return twfId, ERR_NEXT_AUTH_TOTP
	}

	if strings.Contains(string(buf[:n]), "<NextAuth>-1</NextAuth>") || !strings.Contains(string(buf[:n]), "<NextAuth>") {
		log.Print("No NextAuth found.")
	} else {
		debug.PrintStack()
		return "", errors.New("Not implemented auth: " + string(buf[:n]))
	}

	if !strings.Contains(string(buf[:n]), "<Result>1</Result>") {
		debug.PrintStack()
		return "", errors.New("Login FAILED: " + string(buf[:n]))
	}

	twfIdMatch := regexp.MustCompile(`<TwfID>(.*)</TwfID>`).FindSubmatch(buf[:n])
	if twfIdMatch != nil {
		twfId = string(twfIdMatch[1])
		log.Printf("Update twfId: %s", twfId)
	}

	log.Printf("Web Login process done.")

	return twfId, nil
}

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

```
