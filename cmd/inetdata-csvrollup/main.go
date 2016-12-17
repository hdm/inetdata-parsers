package main

import (
	"flag"
	"fmt"
	"github.com/hdm/inetdata-parsers/utils"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var output_count int64 = 0
var input_count int64 = 0
var stdout_lock sync.Mutex
var wg sync.WaitGroup

type OutputKey struct {
	Key  string
	Vals []string
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Reads a pre-sorted (-u -t , -k 1) CSV from stdin, treats all bytes after the first comma")
	fmt.Println("as the value, merges values with the same key using a null byte, outputs an unsorted")
	fmt.Println("merged CSV as output.")
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
				fmt.Fprintf(os.Stderr, "[*] [inetdata-csvrollup] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out)\n",
					icount,
					ocount,
					int(elapsed.Seconds()),
					int(float64(icount)/elapsed.Seconds()),
					int(float64(ocount)/elapsed.Seconds()))
			}
		}
	}
}

func writeOutput(o chan string, q chan bool) {
	for r := range o {
		os.Stdout.Write([]byte(r))
	}
	q <- true
}

func mergeAndEmit(c chan OutputKey, o chan string) {

	for r := range c {

		unique := map[string]bool{}

		for i := range r.Vals {
			vals := strings.SplitN(r.Vals[i], "\x00", -1)
			for v := range vals {
				unique[vals[v]] = true
			}
		}

		out := make([]string, len(unique))
		i := 0
		for v := range unique {
			out[i] = v
			i++
		}
		atomic.AddInt64(&output_count, 1)
		o <- fmt.Sprintf("%s,%s\n", r.Key, strings.Join(out, "\x00"))
	}

	wg.Done()
}

func inputParser(c <-chan string, outc chan<- OutputKey) {

	// Track current key and value array
	ckey := ""
	cval := []string{}

	for r := range c {

		raw := strings.TrimSpace(r)
		if len(raw) == 0 {
			continue
		}

		bits := strings.SplitN(raw, ",", 2)

		if len(bits) < 2 || len(bits[0]) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Invalid line: %q\n", raw)
			continue
		}

		// Tons of records with a blank (".") DNS response, just ignore
		if len(bits[1]) == 0 {
			continue
		}

		atomic.AddInt64(&input_count, 1)

		key := bits[0]
		val := bits[1]

		// First key hit
		if ckey == "" {
			ckey = key
		}

		// Next key hit
		if ckey != key {
			outc <- OutputKey{Key: ckey, Vals: cval}
			ckey = key
			cval = []string{}
		}

		// Cleanup common scan artifacts, not comprehensive

		// Ignore any records where key is empty or identical to the value (except NS)
		if len(val) >= len(key) {
			parts := strings.SplitN(val, ",", 2)
			if len(parts) == 2 && parts[0] != "ns" {
				if len(parts[1]) == 0 || key == parts[1] {
					continue
				}
			}
		}

		// TXT records start with an erroneous pipe character
		if len(val) > 5 && val[0:5] == "txt,|" {
			val = "txt," + val[5:]
		}

		// DNSSEC-related TXT records often have trailing bytes
		if len(val) >= 38 && (val[0:6] == "txt,31" || val[0:6] == "txt,00" || val[0:6] == "txt,aa") {
			val = val[0:38]
		}

		// Mangled TXT value, ignore
		if len(val) >= 5 && len(val) <= 10 && val[0:5] == "txt,~" {
			continue
		}

		// New data value
		cval = append(cval, val)
	}

	if len(ckey) > 0 && len(cval) > 0 {
		outc <- OutputKey{Key: ckey, Vals: cval}
	}

	close(outc)
	wg.Done()
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	version := flag.Bool("version", false, "Show the version and build timestamp")

	flag.Parse()

	if *version {
		utils.PrintVersion()
		os.Exit(0)
	}

	// Progress tracker
	quit := make(chan int)
	go showProgress(quit)

	// Output merger and writer
	outc := make(chan OutputKey, 1000)
	outl := make(chan string, 1000)
	outq := make(chan bool, 1)

	for i := 0; i < runtime.NumCPU(); i++ {
		go mergeAndEmit(outc, outl)
		wg.Add(1)
	}

	// Not covered by the waitgroup
	go writeOutput(outl, outq)

	// Parse stdin
	c_inp := make(chan string, 1000)

	// Only one parser allowed given the rollup use case
	go inputParser(c_inp, outc)
	wg.Add(1)

	// Reader closers c_inp on completion
	e := utils.ReadLines(os.Stdin, c_inp)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %s\n", e)
	}

	wg.Wait()

	close(outl)

	<-outq
	close(outq)

	quit <- 0

}
