package gorules

import (
	"net"
	"strings"
	"sync"

	"github.com/oukishu/onet/internal/redblacktree"
	"github.com/oschwald/geoip2-golang"
)

const (
	AddrTypeIPv4       byte = 0x01
	AddrTypeDomainName byte = 0x03
	AddrTypeIPv6       byte = 0x04

	ActionAccept = "ACCEPT"
	ActionProxy  = "PROXY"
	ActionReject = "REJECT"
	ActionDirect = "DIRECT"

	RuleTypeBypass         byte = 0x01
	RuleTypeHosts          byte = 0x02
	RuleTypeDomains        byte = 0x03
	RuleTypeSuffixDomains  byte = 0x04
	RuleTypeKeywordDomains byte = 0x05
	RuleTypeUserAgent      byte = 0x06
	RuleTypeIPCIDR         byte = 0x07
	RuleTypeGeoIP          byte = 0x08
	RuleTypePort           byte = 0x09
	RuleTypeFinal          byte = 0x0A
	RuleTypeMATCH          byte = 0x0B
)

type Metadata interface {
	AddrType() byte
	Port() string
	Host() string
	String() string
}

type Rules interface {
	RuleType() byte
	Adapter() string
	String() string
}

type Match interface {
	MatchBypass(string) bool
	MatchHosts(string) string
	MatchPort(string) bool
	MatchRule(Metadata) Rules
}

type Filter struct {
	sync.RWMutex
	useGeoIP bool
	useHosts bool

	geoDB *geoip2.Reader // GeoIP

	bypassDomains      []interface{}
	systemBypass       []string
	ruleHosts          []*RuleHost // local hosts
	rulePort           *redblacktree.Tree
	ruleDomains        *redblacktree.Tree
	ruleSuffixDomains  *redblacktree.Tree
	ruleKeywordDomains []*Rule
	ruleUserAgent      []*Rule
	ruleIPCIDR         *IPSearcher
	ruleGeoIP          []*Rule
	ruleFinal          *Rule
}

type Rule struct {
	ruleType byte
	word     string
	adapter  string
}

type RuleIPCIDR struct {
	cidr    *net.IPNet
	adapter string
}

type RuleHost struct {
	Addr string
	Host string
}

func (r *Rule) RuleType() byte {
	return r.ruleType
}

func (r *Rule) Adapter() string {
	return r.adapter
}

func (r *Rule) String() string {
	return RuleType(r.ruleType)
}

func New(rules []byte) (element *Filter) {
	element = &Filter{
		useGeoIP:          false,
		useHosts:          false,
		rulePort:          redblacktree.NewWithStringComparator(),
		ruleDomains:       redblacktree.NewWithStringComparator(),
		ruleSuffixDomains: redblacktree.NewWithStringComparator(),
		ruleIPCIDR:        NewIPSearcher(),
	}
	element.FromRules(rules)

	return
}

func (c *Filter) FromGeoIP(name string) (err error) {
	db, err := FromGeoIP(name)
	if err != nil {
		return
	}
	c.useGeoIP = true
	c.geoDB = db

	return
}

func (c *Filter) FromHosts() {
	hosts := FromHosts()
	if hosts != nil {
		c.useHosts = true
		c.ruleHosts = hosts
	}

	return
}

func (c *Filter) FromPort(elements ...string) {
	for _, v := range elements {
		c.rulePort.Put(strings.ToLower(v), &Rule{ruleType: RuleTypePort, word: strings.ToLower(v), adapter: ActionAccept})
	}
}

func (c *Filter) FromFinal(adapter string) {
	c.ruleFinal = &Rule{ruleType: RuleTypeMATCH, word: "match", adapter: strings.ToUpper(adapter)}
}

func RuleType(rt byte) string {
	switch rt {
	case RuleTypeBypass:
		return "bypass"
	case RuleTypeHosts:
		return "hosts"
	case RuleTypeDomains:
		return "domain"
	case RuleTypeSuffixDomains:
		return "domain-suffix"
	case RuleTypeKeywordDomains:
		return "domain-keyword"
	case RuleTypeUserAgent:
		return "user-agent"
	case RuleTypeIPCIDR:
		return "ip-cidr"
	case RuleTypeGeoIP:
		return "geoip"
	case RuleTypePort:
		return "port"
	case RuleTypeFinal:
		return "final"
	case RuleTypeMATCH:
		return "match"
	default:
		return "Unknown"
	}
}
