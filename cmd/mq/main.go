package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hdm/golang-mtbl"
	"github.com/hdm/inetdata-parsers"
	"io/ioutil"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
)

var key_only *bool
var val_only *bool
var prefix *string
var rev_prefix *string
var rev_key *bool
var no_quotes *bool
var as_json *bool
var version *bool
var domain *string
var cidr *string

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options] <mtbl> ... <mtbl>")
	fmt.Println("")
	fmt.Println("Queries one or more MTBL databases")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func findPaths(args []string) []string {
	var paths []string
	for i := range args {
		path := args[i]
		info, e := os.Stat(path)
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error: Path %s : %v\n", path, e)
			os.Exit(1)
		}

		if info.Mode().IsRegular() {
			paths = append(paths, path)
			continue
		}

		if info.Mode().IsDir() {
			if files, e := ioutil.ReadDir(path); e == nil {
				for _, f := range files {
					if f.Mode().IsRegular() {
						npath := path + string(os.PathSeparator) + f.Name()
						paths = append(paths, npath)
					}
				}
			}
		}
	}
	return paths
}

func writeOutput(key_bytes []byte, val_bytes []byte) {

	key := string(key_bytes)
	val := string(val_bytes)

	if *rev_key {
		key = inetdata.ReverseKey(key)
	}

	if *as_json {
		o := make(map[string]interface{})
		v := make([][]string, 1)

		if de := json.Unmarshal([]byte(val), &v); de != nil {
			fmt.Fprintf(os.Stderr, "Could not unmarshal %s -> %s as json: %s\n", key, val, de)
			return
		}

		o["key"] = string(key)
		o["val"] = v

		b, je := json.Marshal(o)
		if je != nil {
			fmt.Fprintf(os.Stderr, "Could not marshal %s -> %s as json: %s\n", key, val, je)
			return
		}
		fmt.Println(string(b))

	} else if *key_only {
		fmt.Printf("%s\n", key)
	} else if *val_only {
		if *no_quotes {
			fmt.Printf("%s\n", val)
		} else {
			fmt.Printf("%q\n", val)
		}
	} else {
		if *no_quotes {
			fmt.Printf("%s\t%s\n", key, val)
		} else {
			fmt.Printf("%s\t%q\n", key, val)
		}
	}
}

func searchPrefix(r *mtbl.Reader, prefix string) {
	it := mtbl.IterPrefix(r, []byte(prefix))
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}
		writeOutput(key_bytes, val_bytes)
	}
}

func searchAll(r *mtbl.Reader) {
	it := mtbl.IterAll(r)
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}
		writeOutput(key_bytes, val_bytes)
	}
}

func searchDomain(r *mtbl.Reader, domain string) {
	rdomain := []byte(inetdata.ReverseKey(domain))

	// Domain searches always use reversed keys
	*rev_key = true

	dot_rdomain := append(rdomain, '.')
	it := mtbl.IterPrefix(r, rdomain)
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}

		if bytes.Compare(key_bytes, rdomain) == 0 ||
			bytes.Compare(key_bytes[0:len(dot_rdomain)], dot_rdomain) == 0 {
			writeOutput(key_bytes, val_bytes)
		}
	}
}

func searchPrefixIPv4(r *mtbl.Reader, prefix string) {
	it := mtbl.IterPrefix(r, []byte(prefix))
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}

		if inetdata.Match_IPv4.Match(key_bytes) {
			writeOutput(key_bytes, val_bytes)
		}
	}
}

func searchCIDR(r *mtbl.Reader, cidr string) {

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

	net_base, err := inetdata.IPv4_to_UInt(net.IP.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 Address %s: %s\n", ip.String(), err.Error())
		return
	}

	mask_ones, mask_total := net.Mask.Size()

	// Does not work for IPv6 due to cast to uint32
	net_size := uint32(math.Pow(2, float64(mask_total-mask_ones)))

	cur_base := net_base
	end_base := net_base + net_size

	var ndots uint32 = 3
	var block_size uint32 = 256

	// Handle massive network blocks
	if mask_ones <= 8 {
		ndots = 1
		block_size = 256 * 256 * 256
	} else if mask_ones <= 16 {
		ndots = 2
		block_size = 256 * 256
	}

	// Iterate by block size
	for ; end_base-cur_base >= block_size; cur_base += block_size {
		ip_prefix := strings.Join(strings.SplitN(inetdata.UInt_to_IPv4(cur_base), ".", 4)[0:ndots], ".") + "."
		searchPrefixIPv4(r, ip_prefix)
	}

	if end_base-cur_base == 0 {
		return
	}

	// Handle any leftovers by looking up a full /24 and ignoring stuff outside our range
	ip_prefix := strings.Join(strings.SplitN(inetdata.UInt_to_IPv4(cur_base), ".", 4)[0:3], ".") + "."

	it := mtbl.IterPrefix(r, []byte(ip_prefix))
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}

		// Only print results that are valid IPV4 addresses within our CIDR range
		cur_val, _ := inetdata.IPv4_to_UInt(string(key_bytes))
		if cur_val >= cur_base && cur_val <= end_base {
			if inetdata.Match_IPv4.Match(key_bytes) {
				writeOutput(key_bytes, val_bytes)
			}
		}
	}
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }

	key_only = flag.Bool("k", false, "Display key names only")
	val_only = flag.Bool("v", false, "Display values only")
	prefix = flag.String("p", "", "Only return keys with this prefix")
	rev_prefix = flag.String("r", "", "Only return keys with this prefix in reverse form")
	rev_key = flag.Bool("R", false, "Display matches with the key in reverse form")
	no_quotes = flag.Bool("n", false, "Print raw values, not quoted values")
	as_json = flag.Bool("j", false, "Print each record as a single line of JSON")
	version = flag.Bool("version", false, "Show the version and build timestamp")
	domain = flag.String("domain", "", "Search for all matches for a specified domain")
	cidr = flag.String("cidr", "", "Search for all matches for the specified CIDR")

	flag.Parse()

	if *version {
		inetdata.PrintVersion("mq")
		os.Exit(0)
	}

	if len(flag.Args()) == 0 {
		usage()
		os.Exit(1)
	}

	if *key_only && *val_only {
		fmt.Fprintf(os.Stderr, "Error: Only one of -k or -v can be specified\n")
		usage()
		os.Exit(1)
	}

	if len(*prefix) > 0 && len(*rev_prefix) > 0 {
		fmt.Fprintf(os.Stderr, "Error: Only one of -p or -r can be specified\n")
		usage()
		os.Exit(1)
	}

	if len(*domain) > 0 && (len(*prefix) > 0 || len(*rev_prefix) > 0 || len(*cidr) > 0) {
		fmt.Fprintf(os.Stderr, "Error: Only one of -p, -r, -domain, or -cidr can be specified\n")
		usage()
		os.Exit(1)
	}

	if len(*cidr) > 0 && (len(*prefix) > 0 || len(*rev_prefix) > 0 || len(*domain) > 0) {
		fmt.Fprintf(os.Stderr, "Error: Only one of -p, -r, -domain, or -cidr can be specified\n")
		usage()
		os.Exit(1)
	}

	paths := findPaths(flag.Args())

	exit_code := 0

	for i := range paths {

		path := paths[i]

		r, e := mtbl.ReaderInit(path, &mtbl.ReaderOptions{VerifyChecksums: true})
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %s\n", path, e)
			exit_code = 1
			continue
		}

		defer r.Destroy()

		if len(*domain) > 0 {
			searchDomain(r, *domain)
			continue
		}

		if len(*cidr) > 0 {
			searchCIDR(r, *cidr)
			continue
		}

		if len(*prefix) > 0 {
			searchPrefix(r, *prefix)
			continue
		}

		if len(*rev_prefix) > 0 {
			p := inetdata.ReverseKey(*rev_prefix)
			searchPrefix(r, p)
			continue
		}

		searchAll(r)
	}

	os.Exit(exit_code)
}
