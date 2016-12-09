package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/edmonds/golang-mtbl"
	"github.com/peterbourgon/mergemap"
	"os"
	"runtime"
)

var compression_types = map[string]int{
	"none":   mtbl.COMPRESSION_NONE,
	"snappy": mtbl.COMPRESSION_SNAPPY,
	"zlib":   mtbl.COMPRESSION_ZLIB,
	"lz4":    mtbl.COMPRESSION_LZ4,
	"lz4hc":  mtbl.COMPRESSION_LZ4HC,
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Creates a MTBL database from a JSON input.")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

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

func reverseKey(s string) string {
	b := make([]byte, len(s))
	var j int = len(s) - 1
	for i := 0; i <= j; i++ {
		b[j-i] = s[i]
	}
	return string(b)
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Usage = func() { usage() }

	kname := flag.String("k", "", "The field name to use as the key")
	reverse_key := flag.Bool("r", false, "Store the key in reverse order")
	compression := flag.String("c", "snappy", "The compression type to use (none, snappy, zlib, lz4, lz4hc)")
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1, "The maximum amount of memory to use, in gigabytes, for the sorting phase")

	flag.Parse()

	if len(flag.Args()) != 1 {
		usage()
		os.Exit(1)
	}

	if len(*kname) == 0 {
		usage()
		os.Exit(1)
	}

	fname := flag.Args()[0]

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

	s := mtbl.SorterInit(&sort_opt)
	defer s.Destroy()

	w, we := mtbl.WriterInit(fname, &mtbl.WriterOptions{Compression: compression_alg})
	defer w.Destroy()

	if we != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", we)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 1024*1024*8)
	scanner.Buffer(buf, 1024*1024*8)

	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}

		var v map[string]interface{}

		if e := json.Unmarshal(raw, &v); e != nil {
			fmt.Fprintf(os.Stderr, "Invalid JSON: %v -> %v\n", e, string(raw))
			continue
		}

		kval, ok := v[*kname]
		if !ok {
			fmt.Fprintf(os.Stderr, "Missing key: %v -> %v\n", *kname, string(raw))
			continue
		}

		kstr := kval.(string)

		if *reverse_key {
			kstr = reverseKey(kstr)
		}

		if e := s.Add([]byte(kstr), []byte(raw)); e != nil {
			fmt.Printf("Failed to add %v -> %v: %v\n", kstr, raw, e)
		}

	}

	if e := s.Write(w); e != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", e)
		os.Exit(1)
	}
}
