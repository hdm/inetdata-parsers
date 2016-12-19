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
var wg sync.WaitGroup

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Reads a list of hostnames from stdin and generates a list of all domain names")
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
				fmt.Fprintf(os.Stderr, "[*] [inetdata-hostnames2domains] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out)\n",
					icount,
					ocount,
					int(elapsed.Seconds()),
					int(float64(icount)/elapsed.Seconds()),
					int(float64(ocount)/elapsed.Seconds()))
			}
		}
	}
}

func inputParser(c <-chan string) {

	for r := range c {

		raw := strings.TrimSpace(r)
		if len(raw) == 0 {
			continue
		}

		bits := strings.SplitN(raw, ".", -1)
		if len(bits) < 2 {
			continue
		}

		atomic.AddInt64(&input_count, 1)

		if len(bits) == 2 {
			fmt.Println(raw)
		}

		for i := 1; i < len(bits)-1; i++ {
			name := strings.Join(bits[i:], ".")
			fmt.Println(name)
			atomic.AddInt64(&output_count, 1)
		}
	}
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

	// Parse stdin
	c_inp := make(chan string)

	// Only one parser allowed given the rollup use case
	go inputParser(c_inp)
	wg.Add(1)

	// Reader closers c_inp on completion
	e := utils.ReadLines(os.Stdin, c_inp)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %s\n", e)
	}

	wg.Wait()
	quit <- 0

}
