package main

import (
	"EasierConnect/core"
	"flag"
	"fmt"
	"log"
	"net/url"
	"runtime"
	"strings"
)

func main() {
	// CLI args
	vpnUrlRaw, username, password, socksBind, twfId, totpKey, skipSsl, mode := "", "", "", "", "", "", false, ""
	flag.StringVar(&vpnUrlRaw, "vpn-url", "", "EasyConnect vpn server url (e.g. https://vpn.nju.edu.cn, https://sslvpn.sysu.edu.cn:443)")
	flag.StringVar(&username, "username", "", "Your username")
	flag.StringVar(&password, "password", "", "Your password")
	flag.BoolVar(&skipSsl, "skip-ssl", false, "Skip SSL verification, default: false")
	flag.StringVar(&totpKey, "totp-key", "", "If provided, this program will automatically generate TOTP code using this key and and input it, instead of asking user.")
	flag.StringVar(&socksBind, "socks-bind", ":1080", "The addr socks5 server listens on (e.g. 0.0.0.0:1080)")
	flag.StringVar(&twfId, "twf-id", "", "Login using twfID captured (mostly for debug usage)")
	flag.StringVar(&mode, "mode", "1", "socks run mode")
	debugDump := false
	flag.BoolVar(&debugDump, "debug-dump", false, "Enable traffic debug dump (only for debug usage)")
	flag.Parse()

	port := strings.Split(socksBind, ":")[1]

	user := fmt.Sprintf("v=%s&u=%s", url.QueryEscape(vpnUrlRaw), url.QueryEscape(username))
	fmt.Printf("socks5://%s:%s@localhost:%s\n", url.QueryEscape(user), password, port)
	if mode == "2" {
		core.ServeSocks5Mode2(socksBind)
		return
	}

	if vpnUrlRaw == "" || ((username == "" || password == "") && twfId == "") {
		log.Fatal("Missing required cli args, refer to `EasierConnect --help`.")
	}

	vpnUrl, err := url.Parse(vpnUrlRaw)
	if err != nil {
		log.Fatal("vpn_url is invalid: ", vpnUrlRaw, err)
	}
	client, err := core.NewEasyConnectClientByLogin(vpnUrl, username, password, twfId, totpKey, skipSsl)

	if err != nil {
		log.Fatal("NewEasyConnectClientByLogin: ", err)
	}
	client.ServeSocks5(socksBind, debugDump)

	runtime.KeepAlive(client)
}
