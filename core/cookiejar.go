package core

import (
	"net/http"
	"net/url"
	"sync"
	"time"
)

// MemoryCookieJar 是基于内存的线程安全的 CookieJar 实现
type MemoryCookieJar struct {
	cookies map[string][]*http.Cookie
	lock    sync.RWMutex
}

// NewMemoryCookieJar 创建一个新的 MemoryCookieJar 实例
func NewMemoryCookieJar() *MemoryCookieJar {
	return &MemoryCookieJar{
		cookies: make(map[string][]*http.Cookie),
	}
}

// SetCookies 设置指定 URL 的 Cookies
func (jar *MemoryCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	jar.lock.Lock()
	defer jar.lock.Unlock()

	domain := u.Host
	existing := jar.cookies[domain]
	var validCookies []*http.Cookie

	// 过滤已过期的旧 Cookie
	for _, c := range existing {
		if !isExpired(c) {
			validCookies = append(validCookies, c)
		}
	}

	// 添加新的 Cookies，同时避免重复同名 Cookie
	for _, c := range cookies {
		if !isExpired(c) {
			found := false
			// 检查是否存在同名 Cookie，若存在则覆盖更新
			for i, existingCookie := range validCookies {
				if existingCookie.Name == c.Name {
					validCookies[i] = c
					found = true
					break
				}
			}
			// 如果没有找到同名的 Cookie，则追加新的 Cookie
			if !found {
				validCookies = append(validCookies, c)
			}
		}
	}

	jar.cookies[domain] = validCookies
}

// Cookies 获取指定 URL 的所有有效 Cookies
func (jar *MemoryCookieJar) Cookies(u *url.URL) []*http.Cookie {
	jar.lock.RLock()
	defer jar.lock.RUnlock()

	domain := u.Host
	cookies := jar.cookies[domain]
	var validCookies []*http.Cookie

	// 过滤已过期的 Cookies
	for _, c := range cookies {
		if !isExpired(c) {
			validCookies = append(validCookies, c)
		}
	}

	return validCookies
}

// isExpired 检查 Cookie 是否已过期
func isExpired(c *http.Cookie) bool {
	if c.Expires.IsZero() {
		return false
	}
	return time.Now().After(c.Expires)
}
