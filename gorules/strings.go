package gorules

import "regexp"

var (
	ip4ExpCompile        = regexp.MustCompile(`^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$`)
	domainExpCompile     = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9_-]{0,62})*(\.[a-zA-Z][a-zA-Z0-9]{0,10}){1}$`)
	ip4ExpMustCompile    = regexp.MustCompile(`((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)`)
	domainExpMustCompile = regexp.MustCompile(`[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9_-]{0,62})*(\.[a-zA-Z][a-zA-Z0-9]{0,10}){1}`)
)

func domainSuffix(s string) string {
	i := len(s)
	count := 0
	end := 0
	for ; i != 0; i-- {
		if s[i-1] == '.' {
			if (i - 1) == 0 {
				return s
			}
			count += 1
			switch count {
			case 1:
				end = i - 1
			case 2:
				switch s[i:end] {
				case "com", "co", "gov", "edu", "org", "net":
					end = i - 1
				default:
					return s[i:]
				}
			default:
				return s[i:]
			}
		}
	}
	if count == 0 {
		return ""
	}

	return s
}

func domainKeyword(s string) string {
	i := len(s)
	count := 0
	end := i
	for ; i != 0; i-- {
		if s[i-1] == '.' {
			if (i - 1) == 0 {
				return s[:end]
			}
			count += 1
			switch count {
			case 1:
				end = i - 1
			case 2:
				switch s[i:end] {
				case "com", "co", "gov", "edu", "org", "net":
					end = i - 1
				default:
					return s[i:end]
				}
			default:
				return s[i:end]
			}
		}
	}
	if count == 0 {
		return ""
	}

	return s[i:end]
}

func domainCountry(s string) string {
	i := len(s)
	for ; i != 0; i-- {
		if s[i-1] == '.' {
			return s[i-1:]
		}
	}
	return s
}
