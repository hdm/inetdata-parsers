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
	"time"
)

var compression_types = map[string]int{
	"none":   mtbl.COMPRESSION_NONE,
	"snappy": mtbl.COMPRESSION_SNAPPY,
	"zlib":   mtbl.COMPRESSION_ZLIB,
	"lz4":    mtbl.COMPRESSION_LZ4,
	"lz4hc":  mtbl.COMPRESSION_LZ4HC,
}

func fail(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
	os.Exit(-1)
}

func warn(args ...interface{}) {
	fmt.Fprintln(os.Stderr, args...)
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Creates a MTBL database from a CSV input.")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func mergeFunc(key []byte, val0 []byte, val1 []byte) (mergedVal []byte) {

	var v0, v1 [][]string

	if e := json.Unmarshal(val0, &v0); e != nil {
		fmt.Fprintf(os.Stderr, "Unmarshal v0: %v -> %v\n", string(val0), e)
		return val1
	}

	if e := json.Unmarshal(val1, &v1); e != nil {
		fmt.Fprintf(os.Stderr, "Unmarshal v1: %v -> %v\n", string(val1), e)
		return val0
	}

	var m [][]string

	for i := 0; i < len(v0); i++ {
		m = append(m, v0[i])
	}

	for i := 0; i < len(v1); i++ {
		m = append(m, v1[i])
	}

	d, e := json.Marshal(m)
	if e != nil {
		fmt.Fprintf(os.Stderr, "JSON merge error: %v  key=%v -> %v + %v\n", e, key, val0, val1)
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

func writeToMtbl(s *mtbl.Sorter, key string, rtype string, rvalue string) {
	if len(key) == 0 {
		return
	}

	value := [][]string{[]string{rtype, rvalue}}
	value_json, e := json.Marshal(value)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Failed to marshal: key=%v (%v,%v)\n", key, rtype, rvalue)
		return
	}

	if e := s.Add([]byte(key), value_json); e != nil {
		fmt.Fprintf(os.Stderr, "Failed to add key=%v (%v): %v\n", key, string(value_json), e)
		return
	}
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Usage = func() { usage() }

	compression := flag.String("c", "lz4", "The compression type to use (none, snappy, zlib, lz4, lz4hc)")
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1, "The maximum amount of memory to use, in gigabytes, for the sorting phase, per output file")

	flag.Parse()

	if len(flag.Args()) != 1 {
		usage()
		os.Exit(1)
	}

	out_prefix := flag.Args()[0]
	out_ip := out_prefix + "-ip.mtbl"
	out_name := out_prefix + "-name.mtbl"

	sort_opt := mtbl.SorterOptions{Merge: mergeFunc, MaxMemory: 1000000000}
	sort_opt.MaxMemory *= *sort_mem
	if len(*sort_tmp) > 0 {
		sort_opt.TempDir = *sort_tmp
	}

	compression_alg, ok := compression_types[*compression]
	if !ok {
		fmt.Fprintf(os.Stderr, "Invalid compression algorithm: %s\n", *compression)
		os.Exit(1)
	}

	// Output for FDNS:
	//   1) <ip> -> [ ['dnstype', 'value'], ..]
	//   2) <reverse-name> -> [ ['r-dnstype', 'value'], ..]

	s_ip := mtbl.SorterInit(&sort_opt)
	defer s_ip.Destroy()

	s_name := mtbl.SorterInit(&sort_opt)
	defer s_name.Destroy()

	os.Remove(out_ip)
	w_ip, w_ip_e := mtbl.WriterInit(out_ip, &mtbl.WriterOptions{Compression: compression_alg})
	defer w_ip.Destroy()

	if w_ip_e != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", w_ip_e)
		os.Exit(1)
	}

	os.Remove(out_name)
	w_name, w_name_e := mtbl.WriterInit(out_name, &mtbl.WriterOptions{Compression: compression_alg})
	defer w_name.Destroy()

	if w_name_e != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", w_name_e)
		os.Exit(1)
	}

	start := time.Now()
	records := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if len(raw) == 0 {
			continue
		}

		bits := strings.SplitN(raw, ",", 3)

		if len(bits) < 3 {
			fmt.Fprintf(os.Stderr, "Invalid line: %s\n", raw)
			continue
		}

		if records > 0 && records%1000000 == 0 {
			elapsed := time.Since(start)
			if elapsed.Seconds() > 1.0 {
				fmt.Fprintf(os.Stderr, "[*] Processed %d records in %d seconds (%d/s)\n", records, int(elapsed.Seconds()), int(float64(records)/elapsed.Seconds()))
			}
		}

		records++

		name := bits[0]
		dtype := bits[1]
		dvalue := bits[2]
		rname := reverseKey(name)
		rvalue := reverseKey(dvalue)

		writeToMtbl(s_name, rname, dtype, dvalue)

		switch dtype {
		case "a", "aaaa":
			writeToMtbl(s_ip, dvalue, dtype, name)

		case "cname", "ns", "ptr":
			writeToMtbl(s_name, rvalue, "r-"+dtype, name)

		case "mx":
			parts := strings.SplitN(dvalue, " ", 2)
			if len(parts) != 2 {
				continue
			}
			dvalue = parts[1]
			rvalue = reverseKey(parts[1])
			writeToMtbl(s_name, rvalue, "r-"+dtype, name)
		}
	}

	if e := s_ip.Write(w_ip); e != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", e)
		os.Exit(1)
	}

	if e := s_name.Write(w_name); e != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", e)
		os.Exit(1)
	}

}
