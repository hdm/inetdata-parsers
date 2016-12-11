package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/edmonds/golang-mtbl"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const MERGE_MODE_COMBINE = 0
const MERGE_MODE_FIRST = 1
const MERGE_MODE_LAST = 2

var merge_mode = MERGE_MODE_COMBINE

var compression_types = map[string]int{
	"none":   mtbl.COMPRESSION_NONE,
	"snappy": mtbl.COMPRESSION_SNAPPY,
	"zlib":   mtbl.COMPRESSION_ZLIB,
	"lz4":    mtbl.COMPRESSION_LZ4,
	"lz4hc":  mtbl.COMPRESSION_LZ4HC,
}

var merge_count int64 = 0
var input_count int64 = 0

type NewRecord struct {
	Key []byte
	Val []byte
}

var wg sync.WaitGroup

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Creates a MTBL database from a Sonar FDNS pre-sorted and pre-merged CSV input")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func mergeFunc(key []byte, val0 []byte, val1 []byte) (mergedVal []byte) {

	atomic.AddInt64(&merge_count, 1)

	if merge_mode == MERGE_MODE_FIRST {
		return val0
	}

	if merge_mode == MERGE_MODE_LAST {
		return val1
	}

	// MERGE_MODE_COMBINE
	var unique = make(map[string]bool)
	var v0, v1, m [][]string

	// fmt.Fprintf(os.Stderr, "MERGE[%v]     %v    ->    %v\n", string(key), string(val0), string(val1))

	if e := json.Unmarshal(val0, &v0); e != nil {
		return val1
	}

	if e := json.Unmarshal(val1, &v1); e != nil {
		return val0
	}

	for i := range v0 {
		if len(v0[i]) == 0 {
			continue
		}
		unique[strings.Join(v0[i], "\x00")] = true
	}

	for i := range v1 {
		if len(v1[i]) == 0 {
			continue
		}
		unique[strings.Join(v1[i], "\x00")] = true
	}

	for i := range unique {
		m = append(m, strings.SplitN(i, "\x00", 2))
	}

	d, e := json.Marshal(m)
	if e != nil {
		fmt.Fprintf(os.Stderr, "JSON merge error: %v -> %v + %v\n", e, val0, val1)
		return val0
	}

	return d
}

func reverseKey(s string) string {
	b := make([]byte, len(s))
	var j int = len(s) - 1
	for i := 0; i <= j; i++ {
		b[j-i] = s[i]
	}
	return string(b)
}

func showProgress(quit chan int) {
	start := time.Now()

	for {
		select {
		case <-quit:
			fmt.Fprintf(os.Stderr, "[*] Complete\n")
			return
		case <-time.After(time.Second * 1):
			if input_count == 0 && merge_count == 0 {
				// Reset start, so that we show stats only from our first input
				start = time.Now()
				continue
			}
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

func writeToMtbl(s *mtbl.Sorter, c chan NewRecord) {
	for r := range c {
		if e := s.Add(r.Key, r.Val); e != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to add key=%v (%v): %v\n", r.Key, r.Val, e)
		}
	}

	wg.Done()
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Usage = func() { usage() }

	compression := flag.String("c", "snappy", "The compression type to use (none, snappy, zlib, lz4, lz4hc)")
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1024, "The maximum amount of memory to use, in megabytes, for the sorting phase, per output file")
	selected_merge_mode := flag.String("M", "combine", "The merge mode: combine, first, or last")

	flag.Parse()

	if len(flag.Args()) != 1 {
		usage()
		os.Exit(1)
	}

	switch *selected_merge_mode {
	case "combine":
		merge_mode = MERGE_MODE_COMBINE
	case "first":
		merge_mode = MERGE_MODE_FIRST
	case "last":
		merge_mode = MERGE_MODE_LAST
	default:
		fmt.Fprintf(os.Stderr, "Error: Invalid merge mode specified: %s\n", *selected_merge_mode)
		usage()
		os.Exit(1)
	}

	fname := flag.Args()[0]
	_ = os.Remove(fname)

	sort_opt := mtbl.SorterOptions{Merge: mergeFunc, MaxMemory: 1024 * 1024}
	sort_opt.MaxMemory *= *sort_mem

	if len(*sort_tmp) > 0 {
		sort_opt.TempDir = *sort_tmp
	}

	compression_alg, ok := compression_types[*compression]
	if !ok {
		fmt.Fprintf(os.Stderr, "[-] Invalid compression algorithm: %s\n", *compression)
		os.Exit(1)
	}

	s := mtbl.SorterInit(&sort_opt)
	w, w_e := mtbl.WriterInit(fname, &mtbl.WriterOptions{Compression: compression_alg})

	if w_e != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %s\n", w_e)
		os.Exit(1)
	}

	s_ch := make(chan NewRecord, 1000)
	go writeToMtbl(s, s_ch)
	wg.Add(1)

	quit := make(chan int)
	go showProgress(quit)

	scanner := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 1024*1024*512)
	scanner.Buffer(buf, 1024*1024*512)

	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if len(raw) == 0 {
			continue
		}

		bits := strings.SplitN(raw, ",", 2)

		if len(bits) != 2 {
			fmt.Fprintf(os.Stderr, "[-] Invalid line: %s\n", raw)
			continue
		}

		atomic.AddInt64(&input_count, 1)

		name := bits[0]
		data := bits[1]

		if len(name) == 0 || len(data) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Invalid line: %s\n", raw)
			continue
		}

		outp := [][]string{}

		vals := strings.SplitN(data, "\x00", -1)
		for i := range vals {
			info := strings.SplitN(vals[i], ",", 2)

			// This is a single-mapped value without a type prefix
			// Types: a, aaaa
			if len(info) == 1 {
				outp = append(outp, []string{vals[i]})
				// This is a pair-mapped value with a dns record type
				// Types: fdns, cname, ns, mx, ptr
			} else {
				outp = append(outp, info)
				// Reverse the name key for easy prefix searching
				name = reverseKey(name)
			}
		}

		json, e := json.Marshal(outp)
		if e != nil {
			fmt.Fprintf(os.Stderr, "[-] Could not marshal %v: %s\n", outp, e)
			continue
		}

		s_ch <- NewRecord{Key: []byte(name), Val: json}
	}

	close(s_ch)
	wg.Wait()

	if e := s.Write(w); e != nil {
		fmt.Fprintf(os.Stderr, "[-] Error writing IP file: %s\n", e)
		os.Exit(1)
	}

	quit <- 0

	s.Destroy()
	w.Destroy()

}
