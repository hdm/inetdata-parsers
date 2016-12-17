package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/edmonds/golang-mtbl"
	"github.com/hdm/inetdata-parsers/utils"
	"os"
	"runtime"
	"time"
)

var merge_count int64 = 0
var input_count int64 = 0

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Creates a MTBL database from a CSV input.")
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
			elapsed := time.Since(start)
			if elapsed.Seconds() > 1.0 {
				fmt.Fprintf(os.Stderr, "[*] Processed %d records in %d seconds (%d/s) (merged: %d)\n",
					input_count,
					int(elapsed.Seconds()),
					int(float64(input_count)/elapsed.Seconds()),
					merge_count)
			}
		}
	}
}

func mergeFunc(key []byte, val0 []byte, val1 []byte) (mergedVal []byte) {
	merge_count++
	return val0
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }

	reverse_key := flag.Bool("r", false, "Store the key in reverse order")
	compression := flag.String("c", "snappy", "The compression type to use (none, snappy, zlib, lz4, lz4hc)")
	sort_skip := flag.Bool("S", false, "Skip the sorting phase and assume keys are in pre-sorted order")
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1, "The maximum amount of memory to use, in gigabytes, for the sorting phase")
	version := flag.Bool("version", false, "Show the version and build timestamp")

	flag.Parse()

	if *version {
		utils.PrintVersion()
		os.Exit(0)
	}

	if len(flag.Args()) != 1 {
		usage()
		os.Exit(1)
	}

	fname := flag.Args()[0]

	sort_opt := mtbl.SorterOptions{Merge: mergeFunc, MaxMemory: 1000000000}
	sort_opt.MaxMemory *= *sort_mem
	if len(*sort_tmp) > 0 {
		sort_opt.TempDir = *sort_tmp
	}

	compression_alg, ok := utils.MTBLCompressionTypes[*compression]
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid compression algorithm: %s\n", *compression)
		os.Exit(1)
	}

	s := mtbl.SorterInit(&sort_opt)
	defer s.Destroy()

	w, we := mtbl.WriterInit(fname, &mtbl.WriterOptions{Compression: compression_alg})
	defer w.Destroy()

	if we != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", we)
		os.Exit(1)
	}

	quit := make(chan int)
	go showProgress(quit)

	vstr := "1"
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		kstr := scanner.Text()

		input_count++
		if len(kstr) == 0 {
			continue
		}

		if *reverse_key {
			kstr = utils.ReverseKey(kstr)
		}

		if *sort_skip {
			if e := w.Add([]byte(kstr), []byte(vstr)); e != nil {
				fmt.Printf("Failed to add %v -> %v: %v\n", kstr, vstr, e)
			}
		} else {
			if e := s.Add([]byte(kstr), []byte(vstr)); e != nil {
				fmt.Printf("Failed to add %v -> %v: %v\n", kstr, vstr, e)
			}
		}
	}

	if !*sort_skip {
		if e := s.Write(w); e != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", e)
			os.Exit(1)
		}
	}

	quit <- 1
}
