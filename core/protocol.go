package core

import (
	"EasierConnect/utils"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"

	tls "github.com/refraction-networking/utls"
)

func DumpHex(buf []byte) {
	stdoutDumper := hex.Dumper(os.Stdout)
	defer stdoutDumper.Close()
	stdoutDumper.Write(buf)
}

func TLSConn(server string, insecureSkipVerify bool) (*tls.UConn, error) {
	// dial vpn server
	dialConn, err := net.Dial("tcp", server)
	if err != nil {
		return nil, err
	}
	log.Println("socket: connected to: ", dialConn.RemoteAddr())

	// using uTLS to construct a weird TLS Client Hello (required by Sangfor)
	// The VPN and HTTP Server share port 443, Sangfor uses a special SessionId to distinguish them. (which is very stupid...)
	// InsecureSkipVerify must is true
	conn := tls.UClient(dialConn, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)

	random := make([]byte, 32)
	rand.Read(random) // Ignore the err
	conn.SetClientRandom(random)
	conn.SetTLSVers(tls.VersionTLS11, tls.VersionTLS11, []tls.TLSExtension{})
	conn.HandshakeState.Hello.Vers = tls.VersionTLS11
	conn.HandshakeState.Hello.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
	conn.HandshakeState.Hello.CompressionMethods = []uint8{0}
	conn.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	log.Println("tls: connected to: ", conn.RemoteAddr())

	return conn, nil
}

func QueryIp(server string, token *[48]byte, insecureSkipVerify bool) ([]byte, *tls.UConn, error) {
	conn, err := TLSConn(server, insecureSkipVerify)
	if err != nil {
		debug.PrintStack()
		return nil, nil, err
	}
	// defer conn.Close()
	// Query IP conn CAN NOT be closed, otherwise tx/rx handshake will fail

	// QUERY IP PACKET
	message := []byte{0x00, 0x00, 0x00, 0x00}
	message = append(message, token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}...)

	n, err := conn.Write(message)
	if err != nil {
		debug.PrintStack()
		return nil, nil, err
	}

	log.Printf("query ip: wrote %d bytes", n)
	DumpHex(message[:n])

	reply := make([]byte, 0x80)
	n, err = conn.Read(reply)
	if err != nil {
		debug.PrintStack()
		return nil, nil, err
	}

	log.Printf("query ip: read %d bytes", n)
	DumpHex(reply[:n])

	if reply[0] != 0x00 {
		debug.PrintStack()
		return nil, nil, errors.New("unexpected query ip reply")
	}

	return reply[4:8], conn, nil
}

func BlockRXStream(server string, token *[48]byte, ipRev *[4]byte, ep *EasyConnectEndpoint, debug bool, ctx context.Context, insecureSkipVerify bool) error {
	conn, err := TLSConn(server, insecureSkipVerify)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// RECV STREAM START
	message := []byte{0x06, 0x00, 0x00, 0x00}
	message = append(message, token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	message = append(message, ipRev[:]...)

	n, err := conn.Write(message)
	if err != nil {
		return err
	}
	log.Printf("recv handshake: wrote %d bytes", n)
	DumpHex(message[:n])

	reply := make([]byte, 1500)
	n, err = conn.Read(reply)
	if err != nil {
		return err
	}
	log.Printf("recv handshake: read %d bytes", n)
	DumpHex(reply[:n])

	if reply[0] != 0x01 {
		return errors.New("unexpected recv handshake reply")
	}

	for {
		select {
		case <-ctx.Done():
			conn.Close()
			break
		default:
			n, err = conn.Read(reply)

			if err != nil {
				return err
			}

			ep.WriteTo(reply[:n])

			if debug {
				log.Printf("recv: read %d bytes", n)
				DumpHex(reply[:n])
			}
		}

	}
}

func BlockTXStream(server string, token *[48]byte, ipRev *[4]byte, ep *EasyConnectEndpoint, debug bool, ctx context.Context, insecureSkipVerify bool) error {
	conn, err := TLSConn(server, insecureSkipVerify)
	if err != nil {
		return err
	}
	defer conn.Close()

	// SEND STREAM START
	message := []byte{0x05, 0x00, 0x00, 0x00}
	message = append(message, token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	message = append(message, ipRev[:]...)

	n, err := conn.Write(message)
	if err != nil {
		return err
	}
	log.Printf("send handshake: wrote %d bytes", n)
	DumpHex(message[:n])

	reply := make([]byte, 1500)
	n, err = conn.Read(reply)
	if err != nil {
		return err
	}
	log.Printf("send handshake: read %d bytes", n)
	DumpHex(reply[:n])

	if reply[0] != 0x02 {
		return errors.New("unexpected send handshake reply")
	}

	errCh := make(chan error)

	ep.OnRecv = func(buf []byte) {
		select {
		case <-ctx.Done():
			conn.Close()
			break
		default:
			var n, err = conn.Write(buf)
			if err != nil {
				errCh <- err
				return
			}

			if debug {
				log.Printf("send: wrote %d bytes", n)
				DumpHex([]byte(buf[:n]))
			}
		}
	}

	return <-errCh
}

func StartProtocol(endpoint *EasyConnectEndpoint, server string, token *[48]byte, ipRev1 []byte, debug bool, ctx context.Context, insecureSkipVerify bool) {
	ipRev := (*[4]byte)(utils.ReversedSlices(ipRev1))

	// 创建一个可取消的 context
	ctx, cancel := context.WithCancel(ctx)
	defer cancel() // 确保在函数退出时取消 context

	// 接收协程
	rx := func() {
		counter := 0
		for counter < 1 {
			select {
			case <-ctx.Done():
				return
			default:
				err := BlockRXStream(server, token, ipRev, endpoint, debug, ctx, insecureSkipVerify)
				if err != nil {
					if err == io.EOF {
						log.Println("接收到 EOF，关闭协程")
						cancel() // 取消 context，通知其他协程退出
						return
					}
					log.Printf("接收错误: %v，重试中...", err)
					counter++
				}
			}
		}
		log.Println("接收重试次数耗尽")
		return
	}

	// 发送协程
	tx := func() {
		counter := 0
		for counter < 1 {
			select {
			case <-ctx.Done():
				return
			default:
				err := BlockTXStream(server, token, ipRev, endpoint, debug, ctx, insecureSkipVerify)
				if err != nil {
					if err == io.EOF {
						log.Println("发送到 EOF，关闭协程")
						cancel() // 取消 context，通知其他协程退出
						return
					}
					log.Printf("发送错误: %v，重试中...", err)
					counter++
				}
			}
		}
		log.Println("发送重试次数耗尽")
		return
	}

	go rx()
	go tx()

	// 等待 context 被取消
	<-ctx.Done()
	log.Println("所有协程已退出")
}
