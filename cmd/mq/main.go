package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/edmonds/golang-mtbl"
	"github.com/hdm/inetdata-parsers/utils"
	"github.com/peterbourgon/mergemap"
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

// TODO: Rework to handle [][]string merges
func mergeFunc(key []byte, val0 []byte, val1 []byte) (mergedVal []byte) {
	var v0, v1 map[string]interface{}

	if e := json.Unmarshal(val0, &v0); e != nil {
		return val1
	}

	if e := json.Unmarshal(val1, &v1); e != nil {
		return val0
	}

	m := mergemap.Merge(v0, v1)
	d, e := json.Marshal(m)
	if e != nil {
		fmt.Fprintf(os.Stderr, "JSON merge error: %v -> %v + %v\n", e, val0, val1)
		return val0
	}

	return d
}

func writeOutput(key_bytes []byte, val_bytes []byte) {

	key := string(key_bytes)
	val := string(val_bytes)

	if *rev_key {
		key = utils.ReverseKey(key)
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

func searchPrefix(m *mtbl.Merger, prefix string) {
	it := mtbl.IterPrefix(m, []byte(prefix))
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}
		writeOutput(key_bytes, val_bytes)
	}
}

func searchAll(m *mtbl.Merger) {
	it := mtbl.IterAll(m)
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}
		writeOutput(key_bytes, val_bytes)
	}
}

func searchDomain(m *mtbl.Merger, domain string) {
	rdomain := []byte(utils.ReverseKey(domain))

	// Domain searches always use reversed keys
	*rev_key = true

	// Exact match: "example.com"
	exact, found := mtbl.Get(m, rdomain)
	if found {
		writeOutput([]byte(rdomain), exact)
	}

	// Subdomain matches: ".example.com"
	dot_domain := append(rdomain, '.')
	it := mtbl.IterPrefix(m, dot_domain)
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}
		writeOutput(key_bytes, val_bytes)
	}
}

func searchCIDR(m *mtbl.Merger, cidr string) {

	// Parse CIDR into base address + mask
	ip, net, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid CIDR %s: %s", cidr, err.Error())
		return
	}

	// Verify IPv4 for now
	ip4 := net.IP.To4()
	if ip4 == nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 CIDR %s: %s", cidr, err.Error())
		return
	}

	net_base, ip_err := utils.IPv4_to_UInt(net.IP.String())
	if ip_err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 Address %s: %s", ip.String(), err.Error())
		return
	}

	mask_ones, mask_total := net.Mask.Size()

	// Does not work for IPv6 due to cast to uint32
	net_size := uint32(math.Pow(2, float64(mask_total-mask_ones)))

	cur_base := net_base
	end_base := net_base + net_size

	// TODO: Special case /16s to speed up
	if mask_ones == 16 {
		ip_prefix := strings.Join(strings.SplitN(utils.UInt_to_IPv4(cur_base), ".", 4)[0:2], ".") + "."
		searchPrefix(m, ip_prefix)
		return
	}

	for ; end_base-cur_base >= 256; cur_base += 256 {
		ip_prefix := strings.Join(strings.SplitN(utils.UInt_to_IPv4(cur_base), ".", 4)[0:3], ".") + "."
		searchPrefix(m, ip_prefix)
	}

	if end_base-cur_base == 0 {
		return
	}

	// One final prefix search
	ip_prefix := strings.Join(strings.SplitN(utils.UInt_to_IPv4(cur_base), ".", 4)[0:3], ".") + "."

	it := mtbl.IterPrefix(m, []byte(ip_prefix))
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}

		// Only print values in our CIDR
		cur_val, _ := utils.IPv4_to_UInt(string(key_bytes))
		if cur_val >= cur_base && cur_val <= end_base {
			writeOutput(key_bytes, val_bytes)
		}
	}

	fmt.Fprintf(os.Stderr, "Final: [%s] %s\n", cidr, ip_prefix)
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
		utils.PrintVersion()
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

	m := mtbl.MergerInit(&mtbl.MergerOptions{Merge: mergeFunc})
	defer m.Destroy()

	for i := range paths {
		path := paths[i]

		r, e := mtbl.ReaderInit(path, &mtbl.ReaderOptions{VerifyChecksums: true})
		defer r.Destroy()
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %s\n", path, e)
			os.Exit(1)
		}
		m.AddSource(r)
	}

	if len(*domain) > 0 {
		searchDomain(m, *domain)
		return
	}

	if len(*cidr) > 0 {
		searchCIDR(m, *cidr)
		return
	}

	if len(*prefix) > 0 {
		searchPrefix(m, *prefix)
		return
	}

	if len(*rev_prefix) > 0 {
		p := utils.ReverseKey(*rev_prefix)
		searchPrefix(m, p)
		return
	}

	searchAll(m)
}
