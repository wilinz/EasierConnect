package main

import (
	"EasierConnect/core"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/url"
	"runtime"
	"time"

	"github.com/pquerna/otp/totp"
)

func main() {
	// CLI args
	vpnUrlRaw, username, password, socksBind, twfId, totpKey, skipSsl := "", "", "", "", "", "", false
	flag.StringVar(&vpnUrlRaw, "vpn-url", "", "EasyConnect vpn server url (e.g. https://vpn.nju.edu.cn, https://sslvpn.sysu.edu.cn:443)")
	flag.StringVar(&username, "username", "", "Your username")
	flag.StringVar(&password, "password", "", "Your password")
	flag.BoolVar(&skipSsl, "skip-ssl", false, "Skip SSL verification, default: false")
	flag.StringVar(&totpKey, "totp-key", "", "If provided, this program will automatically generate TOTP code using this key and and input it, instead of asking user.")
	flag.StringVar(&socksBind, "socks-bind", ":1080", "The addr socks5 server listens on (e.g. 0.0.0.0:1080)")
	flag.StringVar(&twfId, "twf-id", "", "Login using twfID captured (mostly for debug usage)")
	debugDump := false
	flag.BoolVar(&debugDump, "debug-dump", false, "Enable traffic debug dump (only for debug usage)")
	flag.Parse()

	if vpnUrlRaw == "" || ((username == "" || password == "") && twfId == "") {
		log.Fatal("Missing required cli args, refer to `EasierConnect --help`.")
	}

	vpnUrl, err := url.Parse(vpnUrlRaw)
	if err != nil {
		log.Fatal("vpn_url is invalid: ", vpnUrlRaw, err)
	}
	client := core.NewEasyConnectClient(vpnUrl, skipSsl)

	var ip []byte
	if twfId != "" {
		if len(twfId) != 16 {
			panic("len(twfid) should be 16!")
		}
		ip, err = client.LoginByTwfId(twfId)
	} else {
		ip, err = client.Login(username, password)
		if errors.Is(err, core.ERR_NEXT_AUTH_SMS) {
			fmt.Print(">>>Please enter your sms code<<<:")
			smsCode := ""
			fmt.Scan(&smsCode)

			ip, err = client.AuthSMSCode(smsCode)
		} else if errors.Is(err, core.ERR_NEXT_AUTH_TOTP) {
			TOTPCode := ""

			if totpKey == "" {
				fmt.Print(">>>Please enter your TOTP Auth code<<<:")
				fmt.Scan(&TOTPCode)
			} else {
				TOTPCode, err = totp.GenerateCode(totpKey, time.Now())
				if err != nil {
					panic(err)
				}
				log.Printf("Generated TOTP code %s", TOTPCode)
			}

			ip, err = client.AuthTOTP(TOTPCode)
		}
	}

	if err != nil {
		log.Fatal(err.Error())
	}
	log.Printf("Login success, your IP: %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])

	client.ServeSocks5(socksBind, debugDump)

	runtime.KeepAlive(client)
}
