package main

import (
	"bufio"
	"flag"
	"fmt"
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
			if input_count == 0 && output_count == 0 {
				// Reset start, so that we show stats only from our first input
				start = time.Now()
				continue
			}
			elapsed := time.Since(start)
			if elapsed.Seconds() > 1.0 {
				fmt.Fprintf(os.Stderr, "[*] [sonar-csvrollup] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out)\n",
					input_count,
					output_count,
					int(elapsed.Seconds()),
					int(float64(input_count)/elapsed.Seconds()),
					int(float64(output_count)/elapsed.Seconds()))
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

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Usage = func() { usage() }
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)

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

	// Track current key and value array
	ckey := ""
	cval := []string{}

	// Support extremely long lines
	buf := make([]byte, 0, 1024*1024*64)
	scanner.Buffer(buf, 1024*1024*64)

	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if len(raw) == 0 {
			continue
		}

		bits := strings.SplitN(raw, ",", 2)

		if len(bits) < 2 || len(bits[0]) == 0 || len(bits[1]) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Invalid line: %s\n", raw)
			continue
		}

		input_count++

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

		// New data value
		cval = append(cval, val)
	}

	if len(ckey) > 0 && len(cval) > 0 {
		outc <- OutputKey{Key: ckey, Vals: cval}
	}

	close(outc)
	wg.Wait()

	close(outl)

	<-outq
	close(outq)

	quit <- 0

}
