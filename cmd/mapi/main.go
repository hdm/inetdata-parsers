package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/hdm/golang-mtbl"
	"github.com/hdm/inetdata-parsers"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	s "strings"
)

var prefix *string
var domain *string
var cidr *string

func findPaths() []string {
	pathS, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	var paths []string

	filepath.Walk(pathS, func(path string, f os.FileInfo, _ error) error {
		if !f.IsDir() && s.HasSuffix(f.Name(), ".mtbl") {
			paths = append(paths, path)
		}
		return nil
	})
	return paths
}

var paths = findPaths()

func writeOutputR(key_bytes []byte, val_bytes []byte, w http.ResponseWriter) {

	key := string(key_bytes)
	val := string(val_bytes)

	key = inetdata.ReverseKey(key)

	o := make(map[string]interface{})
	v := make([][]string, 1)

	if de := json.Unmarshal([]byte(val), &v); de != nil {
		fmt.Fprintf(os.Stderr, "Could not unmarshal %s -> %s as json: %s\n", key, val, de)
		o["key"] = string(key)
		o["val"] = string(val)
		json.NewEncoder(w).Encode(o)
		return
	}

	o["key"] = string(key)
	o["val"] = v

	json.NewEncoder(w).Encode(o)
}

func writeOutput(key_bytes []byte, val_bytes []byte, w http.ResponseWriter) {

	key := string(key_bytes)
	val := string(val_bytes)

	o := make(map[string]interface{})
	v := make([][]string, 1)

	if de := json.Unmarshal([]byte(val), &v); de != nil {
		fmt.Fprintf(w, "%s\n", val)
		return
	}

	o["key"] = string(key)
	o["val"] = v

	json.NewEncoder(w).Encode(o)
}

func searchDomain(w http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)
	rdomain := []byte(inetdata.ReverseKey(params["id"]))

	for i := range paths {

		path := paths[i]

		r, e := mtbl.ReaderInit(path, &mtbl.ReaderOptions{VerifyChecksums: true})
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %s\n", path, e)
			continue
		}
		defer r.Destroy()

		dot_rdomain := append(rdomain, '.')
		it := mtbl.IterPrefix(r, rdomain)
		for {
			key_bytes, val_bytes, ok := it.Next()
			if !ok {
				break
			}

			if bytes.Compare(key_bytes, rdomain) == 0 ||
				bytes.Compare(key_bytes[0:len(dot_rdomain)], dot_rdomain) == 0 {
				writeOutputR(key_bytes, val_bytes, w)
			}
		}
	}
}

func searchPrefixIPv4(w http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)
	prefix := []byte(params["ip"])

	for i := range paths {

		path := paths[i]

		r, e := mtbl.ReaderInit(path, &mtbl.ReaderOptions{VerifyChecksums: true})
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %s\n", path, e)
			continue
		}
		defer r.Destroy()

		it := mtbl.IterPrefix(r, []byte(prefix))
		for {
			key_bytes, val_bytes, ok := it.Next()
			if !ok {
				break
			}
			writeOutput(key_bytes, val_bytes, w)
		}
	}
}

func cidrPrefixIPv4(r *mtbl.Reader, prefix string, w http.ResponseWriter) {
	it := mtbl.IterPrefix(r, []byte(prefix))
	for {
		key_bytes, val_bytes, ok := it.Next()
		if !ok {
			break
		}

		if inetdata.MatchIPv4.Match(key_bytes) {
			writeOutput(key_bytes, val_bytes, w)
		}
	}
}

func searchCIDR(w http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)
	ip := string(params["ip"])
	cidr := string(params["id"])
	cidr = ip + "/" + cidr

	// Parse CIDR into base address + mask
	ip2, net2, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid CIDR %s: %s\n", cidr, err.Error())
		return
	}

	// Verify IPv4 for now
	ip4 := net2.IP.To4()
	if ip4 == nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 CIDR %s\n", cidr)
		return
	}

	net_base, err := inetdata.IPv42UInt(net2.IP.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid IPv4 Address %s: %s\n", ip2.String(), err.Error())
		return
	}

	mask_ones, mask_total := net2.Mask.Size()

	// Does not work for IPv6 due to cast to uint32
	net_size := uint32(math.Pow(2, float64(mask_total-mask_ones)))

	cur_base := net_base
	end_base := net_base + net_size - 1

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

	for i := range paths {

		path := paths[i]
		r, e := mtbl.ReaderInit(path, &mtbl.ReaderOptions{VerifyChecksums: true})
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %s\n", path, e)
			continue
		}
		defer r.Destroy()
		// Iterate by block size
		for ; (end_base - cur_base + 1) >= block_size; cur_base += block_size {
			ip_prefix := strings.Join(strings.SplitN(inetdata.UInt2IPv4(cur_base), ".", 4)[0:ndots], ".") + "."
			cidrPrefixIPv4(r, ip_prefix, w)
		}

		// Handle any leftovers by looking up a full /24 and ignoring stuff outside our range
		ip_prefix := strings.Join(strings.SplitN(inetdata.UInt2IPv4(cur_base), ".", 4)[0:3], ".") + "."

		it := mtbl.IterPrefix(r, []byte(ip_prefix))
		for {
			key_bytes, val_bytes, ok := it.Next()
			if !ok {
				break
			}

			// Only print results that are valid IPV4 addresses within our CIDR range
			cur_val, _ := inetdata.IPv42UInt(string(key_bytes))
			if cur_val >= cur_base && cur_val <= end_base {
				if inetdata.MatchIPv4.Match(key_bytes) {
					writeOutput(key_bytes, val_bytes, w)
				}
			}
		}
	}
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	router := mux.NewRouter()
	router.HandleFunc("/domain/{id}", searchDomain).Methods("GET")
	router.HandleFunc("/ip/{ip}", searchPrefixIPv4).Methods("GET")
	router.HandleFunc("/ip/{ip}/{id}", searchCIDR).Methods("GET")
	// TODO: router.HandleFunc("/whois/{id}", searchAll).Methods("GET")
	log.Fatal(http.ListenAndServe(":8091", router))
}
