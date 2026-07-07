package gorules

import (
	"errors"
	"github.com/oschwald/geoip2-golang"
	"net"
	"os"
	"strings"
)

func isExistsPath(p string) bool {
	if _, err := os.Stat(p); err != nil {
		return os.IsExist(err)
	}
	return true
}

func FromGeoIP(name string) (db *geoip2.Reader, err error) {
	if ok := isExistsPath(name); !ok {
		err = errors.New("load GeoIP file failed")
		return nil, err
	}
	return geoip2.Open(name)
}

func (c *Filter) GeoIPString(ipaddr string) string {
	if c.geoDB == nil {
		return ""
	}
	ip := net.ParseIP(ipaddr)
	return c.GeoIP(ip)
}

func (c *Filter) GeoIPs(ips []net.IP) string {
	if c.geoDB == nil {
		return ""
	}
	for _, ip := range ips {
		return c.GeoIP(ip)
	}
	return ""
}

// Return Country code
func (c *Filter) GeoIP(ip net.IP) string {
	// log.Println("Lookup GEO IP", ip)
	if c.geoDB == nil {
		return ""
	}
	country, err := c.geoDB.Country(ip)
	if err != nil {
		return ""
	}
	return country.Country.IsoCode
}

func resolveRequestIPAddr(host string) []net.IP {
	var (
		ips []net.IP
		err error
	)
	ip := net.ParseIP(host)
	if nil == ip {
		ips, err = net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return nil
		}
	} else {
		ips = []net.IP{ip}
	}
	return ips
}

func (c *Filter) AddGeoIP(match, adapter string) {
	c.ruleGeoIP = append(c.ruleGeoIP, &Rule{ruleType: RuleTypeGeoIP, word: strings.ToUpper(match), adapter: strings.ToUpper(adapter)})
}

func (c *Filter) SetGeoIP(match, adapter string) {
	rule := &Rule{ruleType: RuleTypeGeoIP, word: strings.ToUpper(match), adapter: strings.ToUpper(adapter)}
	if c.ruleGeoIP != nil {
		for i := 0; i < len(c.ruleGeoIP); i++ {
			if c.ruleGeoIP[i].word == match {
				c.ruleGeoIP[i] = rule
				return
			}
		}
	}
	c.ruleGeoIP = append(c.ruleGeoIP, rule)
}
