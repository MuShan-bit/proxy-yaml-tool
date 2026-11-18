package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

var countryNames = map[string]string{"US": "美国", "JP": "日本", "SG": "新加坡", "HK": "中国香港", "TW": "中国台湾", "CN": "中国", "MO": "中国澳门", "KR": "韩国", "GB": "英国", "DE": "德国", "FR": "法国", "CA": "加拿大", "AU": "澳大利亚", "NL": "荷兰", "RU": "俄罗斯", "IN": "印度", "TH": "泰国", "VN": "越南", "MY": "马来西亚", "PH": "菲律宾", "ID": "印度尼西亚", "NZ": "新西兰", "CH": "瑞士", "SE": "瑞典", "FI": "芬兰", "NO": "挪威", "IT": "意大利", "ES": "西班牙", "TR": "土耳其", "BR": "巴西", "ZA": "南非", "PL": "波兰", "AE": "阿联酋"}

type CountryLookup struct {
	cache    map[string]string
	Warnings []string
	client   *http.Client
	baseURL  string
}

func NewCountryLookup() *CountryLookup {
	return &CountryLookup{cache: map[string]string{}, client: &http.Client{Timeout: 3 * time.Second}, baseURL: "https://ipwho.is/"}
}
func publicIP(ip netip.Addr) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	return true
}
func (c *CountryLookup) Label(ctx context.Context, name, server string) string {
	ip, err := netip.ParseAddr(strings.Trim(server, "[]"))
	if err != nil {
		return name
	}
	ip = ip.Unmap()
	if !publicIP(ip) {
		return name
	}
	key := ip.String()
	prefix, ok := c.cache[key]
	if !ok {
		prefix, err = c.lookup(ctx, ip)
		if err != nil {
			c.Warnings = append(c.Warnings, key+"：国家查询失败，已保留原名")
		}
		c.cache[key] = prefix
	}
	if prefix == "" {
		return name
	}
	return prefix + " | " + countryPrefix.ReplaceAllString(name, "")
}
func (c *CountryLookup) lookup(ctx context.Context, ip netip.Addr) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+ip.String(), nil)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var data struct {
		IP      string `json:"ip"`
		Success bool   `json:"success"`
		Code    string `json:"country_code"`
		Country string `json:"country"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&data); err != nil {
		return "", err
	}
	code := strings.ToUpper(data.Code)
	returnedIP, _ := netip.ParseAddr(data.IP)
	if !data.Success || returnedIP.Unmap() != ip || len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' || code == "ZZ" || code == "XX" {
		return "", fmt.Errorf("无效归属地")
	}
	name := first(countryNames[code], strings.TrimSpace(strings.NewReplacer("\n", " ", "\r", " ", "|", " ").Replace(data.Country)))
	if name == "" {
		return "", fmt.Errorf("国家名称为空")
	}
	flag := string([]rune{rune(code[0]) + 127397, rune(code[1]) + 127397})
	return flag + " " + name, nil
}
