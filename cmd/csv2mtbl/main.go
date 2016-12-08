package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

import "github.com/hdm/golang-mtbl"

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
	return []byte(string(val0) + "\n" + string(val1))
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

	index_key := flag.Int("k", 1, "The field index to use as the key")
	index_val := flag.Int("v", 2, "The field index to use as the value")
	reverse_key := flag.Bool("r", false, "Store the key in reverse order")
	max_fields := flag.Int("M", -1, "The maximum number of fields to parse with the delimiter")
	compression := flag.String("c", "snappy", "The compression type to use (none, snappy, zlib, lz4, lz4hc)")
	delimiter := flag.String("d", ",", "The delimiter to use as a field separator")
	sort_skip := flag.Bool("S", false, "Skip the sorting phase and assume keys are in pre-sorted order")
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1, "The maximum amount of memory to use, in gigabytes, for the sorting phase")

	flag.Parse()

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
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if len(raw) == 0 {
			continue
		}

		bits := strings.SplitN(raw, *delimiter, *max_fields)

		if len(bits) < *index_key {
			fmt.Fprintf(os.Stderr, "No key: %s\n", raw)
			continue
		}

		if len(bits) < *index_val {
			fmt.Fprintf(os.Stderr, "No value: %s\n", raw)
			continue
		}

		kstr := bits[*index_key-1]
		if len(kstr) == 0 {
			continue
		}

		vstr := bits[*index_val-1]
		if len(vstr) == 0 {
			continue
		}

		if *reverse_key {
			kstr = reverseKey(kstr)
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
}
