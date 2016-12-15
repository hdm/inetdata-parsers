package main

import (
	"flag"
	"fmt"
	"github.com/hdm/inetdata-parsers/utils"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const ZONE_MODE_UNKNOWN = 0
const ZONE_MODE_COM = 1 // Also NET, ORG, INFO, MOBI
const ZONE_MODE_BIZ = 2 // Also XXX
const ZONE_MODE_SK = 3
const ZONE_MODE_US = 4
const ZONE_MODE_CZDS = 5

var zone_mode = 0
var zone_name = ""
var zone_matched = false

var match_ipv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

var match_ipv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

var split_ws = regexp.MustCompile(`\s+`)

var output_count int64 = 0
var input_count int64 = 0
var stdout_lock sync.Mutex
var wg sync.WaitGroup

type OutputKey struct {
	Key  string
	Vals []string
}

type OutputChannels struct {
	IP4          chan string
	IP6          chan string
	InverseNames chan string
	Names        chan string
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Reads a zone file from stdin, generates CSV files keyed off domain names, including ")
	fmt.Println("forward, inverse, and glue addresses for IPv4 and IPv6.")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func showProgress(quit chan int) {
	start := time.Now()
	for {
		select {
		case <-quit:
			fmt.Fprintf(os.Stderr, "[*] Complete\n")
			return
		case <-time.After(time.Second * 1):
			icount := atomic.LoadInt64(&input_count)
			ocount := atomic.LoadInt64(&output_count)

			if icount == 0 && ocount == 0 {
				// Reset start, so that we show stats only from our first input
				start = time.Now()
				continue
			}
			elapsed := time.Since(start)
			if elapsed.Seconds() > 1.0 {
				fmt.Fprintf(os.Stderr, "[*] [inetdata-zone2csv] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out)\n",
					icount,
					ocount,
					int(elapsed.Seconds()),
					int(float64(icount)/elapsed.Seconds()),
					int(float64(ocount)/elapsed.Seconds()))
			}
		}
	}
}

func outputWriter(fd *os.File, c chan string) {
	for r := range c {
		fd.Write([]byte(r))
		atomic.AddInt64(&output_count, 1)
	}
	wg.Done()
}

func writeRecord(c_names chan string, name string, rtype string, value string) {
	switch rtype {
	case "ns":
		c_names <- fmt.Sprintf("%s,%s,%s\n", name, rtype, value)

	case "a":
		if match_ipv4.Match([]byte(value)) {
			c_names <- fmt.Sprintf("%s,%s,%s\n", name, rtype, value)
		}

	case "aaaa":
		if match_ipv6.Match([]byte(value)) {
			c_names <- fmt.Sprintf("%s,%s,%s\n", name, rtype, value)
		}
	}
}

func normalizeName(name string) string {
	// Leave empty names alone
	if len(name) == 0 {
		return name
	}

	// Leave IP addresses alone
	if match_ipv4.Match([]byte(name)) || match_ipv6.Match([]byte(name)) {
		return name
	}

	if name[len(name)-1:] == "." {
		// Remove the trailing dot
		name = name[:len(name)-1]
	} else {
		// Add the domain to complete the name
		name = fmt.Sprintf("%s.%s", name, zone_name)
	}
	return name
}

func parseZoneCOM(raw string, c_names chan string) {
	bits := split_ws.Split(strings.ToLower(raw), -1)
	if len(bits) != 3 {
		return
	}

	name, rtype, value := normalizeName(bits[0]), bits[1], normalizeName(bits[2])
	writeRecord(c_names, name, rtype, value)
}

func parseZoneBIZ(raw string, c_names chan string) {
	bits := split_ws.Split(strings.ToLower(raw), -1)
	if len(bits) != 5 {
		return
	}

	name, rtype, value := normalizeName(bits[0]), bits[3], normalizeName(bits[4])
	writeRecord(c_names, name, rtype, value)
}

func parseZoneUS(raw string, c_names chan string) {
	bits := split_ws.Split(strings.ToLower(raw), -1)
	if len(bits) != 4 {
		return
	}

	name, rtype, value := normalizeName(bits[0]), bits[2], normalizeName(bits[3])
	writeRecord(c_names, name, rtype, value)
}

func parseZoneSK(raw string, c_names chan string) {
	bits := strings.SplitN(strings.ToLower(raw), ";", -1)
	if len(bits) < 5 {
		return
	}

	name := normalizeName(bits[0])
	if len(name) == 0 {
		return
	}

	ns1, ns2, ns3, ns4 := normalizeName(bits[5]), normalizeName(bits[6]), normalizeName(bits[7]), normalizeName(bits[8])

	if len(ns1) > 0 {
		writeRecord(c_names, name, "ns", ns1)
	}

	if len(ns2) > 0 {
		writeRecord(c_names, name, "ns", ns2)
	}

	if len(ns3) > 0 {
		writeRecord(c_names, name, "ns", ns3)
	}

	if len(ns4) > 0 {
		writeRecord(c_names, name, "ns", ns4)
	}
}

func parseZoneCZDS(raw string, c_names chan string) {
	bits := split_ws.Split(strings.ToLower(raw), -1)
	if len(bits) != 5 {
		return
	}

	name, rtype, value := normalizeName(bits[0]), bits[3], normalizeName(bits[4])
	writeRecord(c_names, name, rtype, value)
}

func inputParser(c chan string, c_names chan string) {

	lines_read := 0
	for r := range c {

		raw := strings.TrimSpace(r)

		if len(raw) == 0 {
			continue
		}

		atomic.AddInt64(&input_count, 1)

		if zone_mode != ZONE_MODE_UNKNOWN && zone_matched == false {
			zone_matched = true

			// Spawn more parsers
			for i := 0; i < runtime.NumCPU()-1; i++ {
				go inputParser(c, c_names)
				wg.Add(1)
			}
		}

		switch zone_mode {
		case ZONE_MODE_UNKNOWN:

			// Versign Zone Format
			if strings.Contains(raw, "$ORIGIN COM.") {
				zone_mode = ZONE_MODE_COM
				zone_name = "com"
				continue
			}

			if strings.Contains(raw, "$ORIGIN INFO.") {
				zone_mode = ZONE_MODE_COM
				zone_name = "info"
				continue
			}

			if strings.Contains(raw, "$ORIGIN MOBI.") {
				zone_mode = ZONE_MODE_COM
				zone_name = "mobi"
				continue
			}

			if strings.Contains(raw, "$ORIGIN NET.") {
				zone_mode = ZONE_MODE_COM
				zone_name = "net"
				continue
			}

			if strings.Contains(raw, "$ORIGIN org.") {
				zone_mode = ZONE_MODE_COM
				zone_name = "org"
				continue
			}

			// US zone format
			if strings.Contains(raw, "US. IN SOA A.CCTLD.US HOSTMASTER.NEUSTAR.US") {
				zone_mode = ZONE_MODE_US
				zone_name = "us"
				continue
			}

			// BIZ/XXX zone format
			if strings.Contains(raw, "BIZ.			900	IN	SOA	A.GTLD.BIZ.") {
				zone_mode = ZONE_MODE_BIZ
				zone_name = "biz"
				continue
			}

			if strings.Contains(raw, "xxx.	86400	in	soa	a0.xxx.afilias-nst.info.") {
				zone_mode = ZONE_MODE_BIZ
				zone_name = "xxx"
				continue
			}

			// SK static zone
			if strings.Contains(raw, "domena;ID reg;ID drzitela;NEW") {
				zone_mode = ZONE_MODE_SK
				zone_name = "sk"
				continue
			}

			// CZDS
			if matched, _ := regexp.Match(`^[a-zA-Z0-9\-]+\.\s+\d+\s+in\s+soa\s+`, []byte(raw)); matched {
				zone_mode = ZONE_MODE_CZDS
				zone_name = ""
				continue
			}

			lines_read++

			if lines_read > 100 {
				fmt.Fprintf(os.Stderr, "[-] Could not determine zone format, giving up: %s\n", raw)
				os.Exit(1)
			}

		case ZONE_MODE_COM:
			parseZoneCOM(raw, c_names)

		case ZONE_MODE_BIZ:
			parseZoneBIZ(raw, c_names)

		case ZONE_MODE_SK:
			parseZoneSK(raw, c_names)

		case ZONE_MODE_US:
			parseZoneUS(raw, c_names)

		case ZONE_MODE_CZDS:
			parseZoneCZDS(raw, c_names)

		default:
			panic("Unknown zone mode")
		}
	}

	wg.Done()
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	flag.Parse()

	// Progress tracker
	quit := make(chan int)
	go showProgress(quit)

	// Write output
	c_names := make(chan string, 1000)
	go outputWriter(os.Stdout, c_names)

	// Read input
	c_inp := make(chan string, 1000)
	go inputParser(c_inp, c_names)
	wg.Add(1)

	// Reader closers c_inp on completion
	e := utils.ReadLines(os.Stdin, c_inp)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %s\n", e)
	}

	// Wait for the input parser to finish
	wg.Wait()

	// Close the output channel
	close(c_names)

	// Wait for the channel writers to finish
	wg.Add(1)
	wg.Wait()

	// Stop the main process monitoring
	quit <- 0
}
