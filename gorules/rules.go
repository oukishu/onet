package gorules

import (
	"net"
	"strings"
)

func readArrayLine(source string) []string {
	out := strings.Split(source, ",")
	for i, str := range out {
		out[i] = strings.TrimSpace(str)
	}
	return out
}

func (c *Filter) FromRules(b []byte) {
	str := strings.ReplaceAll(string(b), "\r", "")
	lines := strings.Split(str, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "skip-proxy") || strings.HasPrefix(strings.ToLower(line), "bypass-tun") {
			items := strings.Split(line, "=")
			c.systemBypass = append(c.systemBypass, readArrayLine(items[1])...)
			continue
		}
		items := readArrayLine(line)
		ruleName := strings.ToLower(items[0])
		switch ruleName {
		case "user-agent":
			c.ruleUserAgent = append(c.ruleUserAgent, &Rule{ruleType: RuleTypeUserAgent, word: strings.ToLower(items[1]), adapter: strings.ToUpper(items[2])})
		case "domain":
			c.ruleDomains.Put(strings.ToLower(items[1]), &Rule{ruleType: RuleTypeSuffixDomains, word: strings.ToLower(items[1]), adapter: strings.ToUpper(items[2])})
		case "domain-suffix":
			c.ruleSuffixDomains.Put(strings.ToLower(items[1]), &Rule{ruleType: RuleTypeSuffixDomains, word: strings.ToLower(items[1]), adapter: strings.ToUpper(items[2])})
		case "domain-keyword":
			c.ruleKeywordDomains = append(c.ruleKeywordDomains, &Rule{ruleType: RuleTypeKeywordDomains, word: strings.ToLower(items[1]), adapter: strings.ToUpper(items[2])})
		case "ip-cidr":
			_, cidr, err := net.ParseCIDR(items[1])
			if err != nil {
				continue
			}
			c.ruleIPCIDR.AddCIDR(cidr, strings.ToUpper(items[2]))
		case "geoip":
			c.ruleGeoIP = append(c.ruleGeoIP, &Rule{ruleType: RuleTypeGeoIP, word: strings.ToUpper(items[1]), adapter: strings.ToUpper(items[2])})
		case "final":
			c.ruleFinal = &Rule{ruleType: RuleTypeMATCH, word: "match", adapter: strings.ToUpper(items[1])}
		case "match":
			c.ruleFinal = &Rule{ruleType: RuleTypeMATCH, word: "match", adapter: strings.ToUpper(items[1])}
		}
	}

	c.bypassDomains = make([]interface{}, len(c.systemBypass))
	for i, v := range c.systemBypass {
		ip := net.ParseIP(v)
		if nil != ip {
			c.bypassDomains[i] = ip
		} else if _, n, err := net.ParseCIDR(v); err == nil {
			c.bypassDomains[i] = n
		} else {
			c.bypassDomains[i] = v
		}
	}

	if c.ruleIPCIDR != nil {
		c.ruleIPCIDR.Optimize()
	}

	return
}

func (c *Filter) matchDomain(host string) *Rule {
	if v, ok := c.ruleDomains.Get(host); ok {
		return v.(*Rule)
	}
	suffix := domainSuffix(host)
	if v, ok := c.ruleSuffixDomains.Get(suffix); ok {
		return v.(*Rule)
	}
	keyword := domainKeyword(host)
	for _, v := range c.ruleKeywordDomains {
		if v.word == keyword {
			return v
		}
	}
	country := domainCountry(host)
	if v, ok := c.ruleSuffixDomains.Get(country); ok {
		return v.(*Rule)
	}

	return nil
}

// addr = host/not port
func (c *Filter) matchIpRule(addr string) *Rule {
	ips := resolveRequestIPAddr(addr) //  convert []net.IP
	adapter := c.matchIPCIDR(ips)
	if adapter != "" {
		return &Rule{
			ruleType: RuleTypeIPCIDR,
			word:     addr,
			adapter:  adapter,
		}
	}
	if nil != ips { // GEOIP rule
		country := c.GeoIPs(ips) // return country
		if c.ruleGeoIP != nil {
			for _, v := range c.ruleGeoIP {
				if v.word == country {
					return v
				}
			}
		}
	}
	return nil
}

func (c *Filter) matchIPCIDR(ips []net.IP) string {
	if c.ruleIPCIDR == nil {
		return ""
	}
	for _, addr := range ips {
		if adapter, found := c.ruleIPCIDR.Search(addr); found {
			return adapter
		}
	}
	return ""
}
