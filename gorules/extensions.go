package gorules

import (
	"strings"
)

func (c *Filter) FromExtensions(b []byte) {
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "#") {
			continue
		}
		items := readArrayLine(line)
		ruleName := strings.ToLower(items[0])
		switch ruleName {
		case "domain":
			c.ruleDomains.Put(strings.ToLower(items[1]), &Rule{ruleType: RuleTypeDomains, word: strings.ToLower(items[1]), adapter: strings.ToUpper(items[2])})
		case "domain-suffix":
			c.ruleSuffixDomains.Put(strings.ToLower(items[1]), &Rule{ruleType: RuleTypeSuffixDomains, word: strings.ToLower(items[1]), adapter: strings.ToUpper(items[2])})
		case "dst-port": // port white list
			c.rulePort.Put(strings.ToLower(items[1]), &Rule{ruleType: RuleTypePort, word: strings.ToLower(items[1]), adapter: strings.ToUpper(items[2])})
		}
	}
	return
}
