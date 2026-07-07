package gorules

import (
	"bytes"
	"errors"
	"io/ioutil"
	"os"
	"path"
	"runtime"
	"strings"
)

var (
	errHostsTooShort = errors.New("hosts item too short")
	errHostsIsNull   = errors.New("hosts item is null")
)

func hostsDir() string {
	switch strings.ToLower(runtime.GOOS) {
	case "windows":
		home := strings.Replace(os.Getenv("windir"), "\\", "/", -1)
		return path.Join(home, "/System32/drivers/etc/hosts")
	default:
		return "/etc/hosts"
	}
}

func (c *Filter) AddHosts(addr, host string) {
	c.ruleHosts = append(c.ruleHosts, &RuleHost{Addr: addr, Host: host})
}

func (c *Filter) SetHosts(addr, host string) {
	if c.ruleHosts != nil {
		for i := 0; i < len(c.ruleHosts); i++ {
			if c.ruleHosts[i].Host == host {
				c.ruleHosts[i] = &RuleHost{Addr: addr, Host: host}
				return
			}
		}
	}
	c.ruleHosts = append(c.ruleHosts, &RuleHost{Addr: addr, Host: host})
}

func FromHosts() (hosts []*RuleHost) {
	f := hostsDir()
	b, err := ioutil.ReadFile(f)
	if err != nil {
		return
	}

	buf := bytes.NewBuffer(b)

	for {
		line, err := buf.ReadString('\n')
		if err != nil {
			break
		}
		if strings.HasPrefix(line, "#") {
			continue
		}
		addr, host, err := readHostsLine(line)
		if err != nil {
			continue
		}
		hosts = append(hosts, &RuleHost{Addr: addr, Host: host})
	}
	return
}

func readHostsLine(str string) (addr, host string, err error) {
	item := strings.Split(str, " ")
	if len(item) < 2 {
		err = errHostsTooShort
		return
	}
	addr = ip4ExpMustCompile.FindString(item[0])
	host = domainExpMustCompile.FindString(item[1])
	if host == "" {
		host = ip4ExpMustCompile.FindString(item[1])
	}
	if addr == "" || host == "" {
		err = errHostsIsNull
		return
	}
	return
}
