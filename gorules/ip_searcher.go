package gorules

import (
	"encoding/binary"
	"net"
	"sort"
)

// IPRange flattens a CIDR into a continuous closed interval
type IPRange struct {
	Start   uint32 // Interval start IP (uint32)
	End     uint32 // Interval end IP (uint32)
	Adapter string // Outbound strategy, e.g., "PROXY"
}

type IPSearcher struct {
	ranges []IPRange
}

func NewIPSearcher() *IPSearcher {
	return &IPSearcher{ranges: make([]IPRange, 0, 1024)}
}

// AddCIDR called during initialization: appends raw CIDR rules to the array
func (s *IPSearcher) AddCIDR(cidr *net.IPNet, adapter string) {
	ipv4 := cidr.IP.To4()
	if ipv4 == nil {
		return
	}
	ipNum := binary.BigEndian.Uint32(ipv4)

	ones, _ := cidr.Mask.Size()
	var mask uint32 = 0xFFFFFFFF
	if ones < 32 {
		mask = ^(0xFFFFFFFF >> ones)
	}

	start := ipNum & mask
	end := ipNum | ^mask

	s.ranges = append(s.ranges, IPRange{
		Start:   start,
		End:     end,
		Adapter: adapter,
	})
}

// Optimize called once after initial loading completes: performs sorting and overlapping interval merging (similar to sing-box's rule compilation effect)
func (s *IPSearcher) Optimize() {
	if len(s.ranges) <= 1 {
		return
	}

	// 1. Sort by start IP in ascending order
	sort.Slice(s.ranges, func(i, j int) bool {
		if s.ranges[i].Start == s.ranges[j].Start {
			return s.ranges[i].End < s.ranges[j].End
		}
		return s.ranges[i].Start < s.ranges[j].Start
	})

	// 2. In-place merge of overlapping intervals (de-duplication to further squeeze and reduce the binary search array length)
	merged := make([]IPRange, 0, len(s.ranges))
	merged = append(merged, s.ranges[0])

	for i := 1; i < len(s.ranges); i++ {
		lastIdx := len(merged) - 1
		curr := s.ranges[i]

		// If the current strategy matches the previous one, and the intervals are continuous or overlapping, perform a lossless merge
		if merged[lastIdx].Adapter == curr.Adapter && curr.Start <= merged[lastIdx].End+1 {
			if curr.End > merged[lastIdx].End {
				merged[lastIdx].End = curr.End
			}
		} else {
			merged = append(merged, curr)
		}
	}
	s.ranges = merged
}

// Search longest prefix binary search (Runtime: $O(\log N)$)
func (s *IPSearcher) Search(ip net.IP) (string, bool) {
	ipv4 := ip.To4()
	if ipv4 == nil {
		return "", false
	}
	ipNum := binary.BigEndian.Uint32(ipv4)

	n := len(s.ranges)
	// Use binary search to quickly locate the first index where Start > ipNum
	idx := sort.Search(n, func(i int) bool {
		return s.ranges[i].Start > ipNum
	})

	// The target IP can only exist within the interval at idx-1
	if idx > 0 {
		targetRange := s.ranges[idx-1]
		if ipNum >= targetRange.Start && ipNum <= targetRange.End {
			return targetRange.Adapter, true
		}
	}

	return "", false
}
