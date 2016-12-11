package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/edmonds/golang-mtbl"
	"os"
	"runtime"
	"strings"
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

var merge_count = 0
var input_count = 0

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Creates two MTBL databases from a Sonar RDNS CSV input")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func mergeFunc(key []byte, val0 []byte, val1 []byte) (mergedVal []byte) {

	merge_count++

	if merge_mode == MERGE_MODE_FIRST {
		return val0
	}

	if merge_mode == MERGE_MODE_LAST {
		return val1
	}

	// MERGE_MODE_COMBINE

	// Use null as our record separator
	bits := strings.SplitN(string(val0), "\x00", -1)

	// Limit merged records to 100 entries
	if len(bits) > 1000 {
		return val0
	}

	// Use a map to deduplicate values
	m := make(map[string]int)
	for i := range bits {
		m[bits[i]] = 1
	}

	// Merge in the new value
	m[string(val1)] = 1

	// Recreate our list of unique values
	vals := make([]string, 0, len(m))
	for i := range m {
		vals = append(vals, i)
	}

	// Rejoin with nulls
	return []byte(strings.Join(vals, "\x00"))
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
			fmt.Fprintf(os.Stderr, "[*] Completed\n")
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

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }

	compression := flag.String("c", "snappy", "The compression type to use (none, snappy, zlib, lz4, lz4hc)")
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1, "The maximum amount of memory to use, in gigabytes, for the sorting phase, per output file")
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

	out_prefix := flag.Args()[0]
	out_ip := out_prefix + "-ip.mtbl"
	out_name := out_prefix + "-name.mtbl"

	sort_opt_ip := mtbl.SorterOptions{Merge: mergeFunc, MaxMemory: 1000000000}
	sort_opt_ip.MaxMemory *= *sort_mem

	sort_opt_name := mtbl.SorterOptions{Merge: mergeFunc, MaxMemory: 1000000000}
	sort_opt_name.MaxMemory *= *sort_mem

	if len(*sort_tmp) > 0 {
		sort_opt_ip.TempDir = (*sort_tmp)[:]
		sort_opt_name.TempDir = (*sort_tmp)[:]
	}

	compression_alg, ok := compression_types[*compression]
	if !ok {
		fmt.Fprintf(os.Stderr, "[-] Invalid compression algorithm: %s\n", *compression)
		os.Exit(1)
	}

	s_ip := mtbl.SorterInit(&sort_opt_ip)
	defer s_ip.Destroy()

	s_name := mtbl.SorterInit(&sort_opt_name)
	defer s_name.Destroy()

	os.Remove(out_ip)
	w_ip, w_ip_e := mtbl.WriterInit(out_ip, &mtbl.WriterOptions{Compression: compression_alg})
	defer w_ip.Destroy()

	if w_ip_e != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %s\n", w_ip_e)
		os.Exit(1)
	}

	os.Remove(out_name)
	w_name, w_name_e := mtbl.WriterInit(out_name, &mtbl.WriterOptions{Compression: compression_alg})
	defer w_name.Destroy()

	if w_name_e != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %s\n", w_name_e)
		os.Exit(1)
	}

	quit := make(chan int)
	go showProgress(quit)

	scanner := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 1024*1024*8)
	scanner.Buffer(buf, 1024*1024*8)

	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if len(raw) == 0 {
			continue
		}

		bits := strings.SplitN(raw, ",", 2)

		if len(bits) < 2 {
			fmt.Fprintf(os.Stderr, "[-] Invalid line: %s\n", raw)
			continue
		}

		input_count++

		ip := bits[0]
		name := bits[1]

		if len(name) == 0 {
			continue
		}

		rname := reverseKey(name)
		ip_ptr := []byte("ptr_" + name)
		name_ptr := []byte("r-ptr_" + ip)

		if e := s_ip.Add([]byte(ip), ip_ptr); e != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to add %v -> %v: %v\n", ip, string(ip_ptr), e)
		}

		if e := s_name.Add([]byte(rname), name_ptr); e != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to add %v -> %v: %v\n", rname, string(name_ptr), e)
		}
	}

	if e := s_ip.Write(w_ip); e != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %s\n", e)
		os.Exit(1)
	}

	if e := s_name.Write(w_name); e != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %s\n", e)
		os.Exit(1)
	}

	quit <- 0
}
