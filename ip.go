package inetdata

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strings"
)

// MatchIPv6 is a regular expression for validating IPv6 addresses
var MatchIPv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

// MatchIPv4 is a regular expression for validating IPv4 addresses
var MatchIPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

//IPv4Masks is a precalculated lookup table for IPv4 CIDR
var IPv4Masks = map[uint32]uint32{
	1:          32,
	2:          31,
	4:          30,
	8:          29,
	16:         28,
	32:         27,
	64:         26,
	128:        25,
	256:        24,
	512:        23,
	1024:       22,
	2048:       21,
	4096:       20,
	8192:       19,
	16384:      18,
	32768:      17,
	65536:      16,
	131072:     15,
	262144:     14,
	524288:     13,
	1048576:    12,
	2097152:    11,
	4194304:    10,
	8388608:    9,
	16777216:   8,
	33554432:   7,
	67108864:   6,
	134217728:  5,
	268435456:  4,
	536870912:  3,
	1073741824: 2,
	2147483648: 1,
}

//IPv4MaskSizes is a precalculated lookup table for IPv4 CIDR mask sizes
var IPv4MaskSizes = []uint32{
	2147483648,
	1073741824,
	536870912,
	268435456,
	134217728,
	67108864,
	33554432,
	16777216,
	8388608,
	4194304,
	2097152,
	1048576,
	524288,
	262144,
	131072,
	65536,
	32768,
	16384,
	8192,
	4096,
	2048,
	1024,
	512,
	256,
	128,
	64,
	32,
	16,
	8,
	4,
	2,
	1,
}

// IPv42UInt converts IPv4 addresses to unsigned integers
func IPv42UInt(ips string) (uint32, error) {
	ip := net.ParseIP(ips)
	if ip == nil {
		return 0, errors.New("Invalid IPv4 address")
	}
	ip = ip.To4()
	return binary.BigEndian.Uint32(ip), nil
}

// UInt2IPv4 converts unsigned integers to IPv4 addresses
func UInt2IPv4(ipi uint32) string {
	ipb := make([]byte, 4)
	binary.BigEndian.PutUint32(ipb, ipi)
	ip := net.IP(ipb)
	return ip.String()
}

// IPv4Range2CIDRs converts a start and stop IPv4 range to a list of CIDRs
func IPv4Range2CIDRs(sIP string, eIP string) ([]string, error) {

	sI, sE := IPv42UInt(sIP)
	if sE != nil {
		return []string{}, sE
	}

	eI, eE := IPv42UInt(eIP)
	if eE != nil {
		return []string{}, eE
	}

	if sI > eI {
		return []string{}, errors.New("Start address is bigger than end address")
	}

	return IPv4UIntRange2CIDRs(sI, eI), nil
}

// IPv4UIntRange2CIDRs converts a range of insigned integers into IPv4 CIDRs
func IPv4UIntRange2CIDRs(sI uint32, eI uint32) []string {
	cidrs := []string{}

	// Ranges are inclusive
	size := eI - sI + 1

	if size == 0 {
		return cidrs
	}

	for i := range IPv4MaskSizes {

		maskSize := IPv4MaskSizes[i]

		if maskSize > size {
			continue
		}

		// Exact match of the block size
		if maskSize == size {
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", UInt2IPv4(sI), IPv4Masks[maskSize]))
			break
		}

		// Chop off the biggest block that fits
		cidrs = append(cidrs, fmt.Sprintf("%s/%d", UInt2IPv4(sI), IPv4Masks[maskSize]))
		sI = sI + maskSize

		// Look for additional blocks
		newCidrs := IPv4UIntRange2CIDRs(sI, eI)

		// Merge those blocks into out results
		for x := range newCidrs {
			cidrs = append(cidrs, newCidrs[x])
		}
		break

	}
	return cidrs
}

//AddressesFromCIDR parses a CIDR and writes individual IPs to a channel
func AddressesFromCIDR(cidr string, o chan<- string) {
	if len(cidr) == 0 {
		return
	}

	// We may receive bare IP addresses, not CIDRs sometimes
	if !strings.Contains(cidr, "/") {
		if strings.Contains(cidr, ":") {
			cidr = cidr + "/128"
		} else {
			cidr = cidr + "/32"
		}
	}

	// Parse CIDR into base address + mask
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid CIDR %s: %s\n", cidr, err.Error())
		return
	}

	// Verify IPv4 for now
	ip4 := net.IP.To4()
	if ip4 == nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 CIDR %s\n", cidr)
		return
	}

	netBase, err := IPv42UInt(net.IP.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 Address %s: %s\n", ip.String(), err.Error())
		return
	}

	maskOnes, maskTotal := net.Mask.Size()

	// Does not work for IPv6 due to cast to uint32
	netSize := uint32(math.Pow(2, float64(maskTotal-maskOnes)))

	curBase := netBase
	endBase := netBase + netSize
	curAddr := curBase

	for curAddr = curBase; curAddr < endBase; curAddr++ {
		o <- UInt2IPv4(curAddr)
	}

	return
}
