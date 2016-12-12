package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/edmonds/golang-mtbl"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const MERGE_MODE_COMBINE = 0
const MERGE_MODE_FIRST = 1
const MERGE_MODE_LAST = 2

var match_ipv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

var match_ipv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

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
var output_count int64 = 0

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
			mcount := atomic.LoadInt64(&merge_count)

			if icount == 0 && ocount == 0 {
				// Reset start, so that we show stats only from our first input
				start = time.Now()
				continue
			}
			elapsed := time.Since(start)
			if elapsed.Seconds() > 1.0 {
				fmt.Fprintf(os.Stderr, "[*] [sonar-fdns2mtbl] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out) (merged: %d)\n",
					icount,
					ocount,
					int(elapsed.Seconds()),
					int(float64(icount)/elapsed.Seconds()),
					int(float64(ocount)/elapsed.Seconds()),
					mcount)
			}
		}
	}
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

func writeToMtbl(s *mtbl.Sorter, c chan NewRecord, d chan bool) {
	for r := range c {
		if e := s.Add(r.Key, r.Val); e != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to add key=%v (%v): %v\n", r.Key, r.Val, e)
		}
		atomic.AddInt64(&output_count, 1)
	}
	d <- true
}

func inputParser(d chan string, c chan NewRecord) {

	for raw := range d {

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
		vals := strings.SplitN(data, "\x00", -1)
		outp := [][]string{}

		for i := range vals {
			info := strings.SplitN(vals[i], ",", 2)

			if len(info) == 1 {
				// This is a single-mapped value without a type prefix
				// Types: a, aaaa
				outp = append(outp, []string{vals[i]})
			} else {
				// This is a pair-mapped value with a dns record type
				// Types: fdns, cname, ns, mx, ptr
				outp = append(outp, info)
			}
		}

		json, e := json.Marshal(outp)
		if e != nil {
			fmt.Fprintf(os.Stderr, "[-] Could not marshal %v: %s\n", outp, e)
			continue
		}

		// Reverse the key unless its an IP address
		if !(match_ipv4.Match([]byte(name)) || match_ipv6.Match([]byte(name))) {
			name = reverseKey(name)
		}

		c <- NewRecord{Key: []byte(name), Val: json}
	}
	wg.Done()
}

func stdinReader(out chan<- string) error {

	var (
		backbufferSize  = 200000
		frontbufferSize = 50000
		r               = bufio.NewReaderSize(os.Stdin, frontbufferSize)
		buf             []byte
		pred            []byte
		err             error
	)

	if backbufferSize <= frontbufferSize {
		backbufferSize = (frontbufferSize / 3) * 4
	}

	for {
		buf, err = r.ReadSlice('\n')

		if err == bufio.ErrBufferFull {
			if len(buf) == 0 {
				continue
			}

			if pred == nil {
				pred = make([]byte, len(buf), backbufferSize)
				copy(pred, buf)
			} else {
				pred = append(pred, buf...)
			}
			continue
		} else if err == io.EOF && len(buf) == 0 && len(pred) == 0 {
			break
		}

		if len(pred) > 0 {
			buf, pred = append(pred, buf...), pred[:0]
		}

		if len(buf) > 0 && buf[len(buf)-1] == '\n' {
			buf = buf[:len(buf)-1]
		}

		if len(buf) == 0 {
			continue
		}

		// fmt.Fprintf(os.Stderr, "Line: %s\n", string(buf))
		out <- string(buf)
	}

	close(out)

	if err != nil && err != io.EOF {
		return err
	}

	return nil
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

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
	s_done := make(chan bool, 1)

	go writeToMtbl(s, s_ch, s_done)

	p_ch := make(chan string, 1000)
	for i := 0; i < runtime.NumCPU(); i++ {
		go inputParser(p_ch, s_ch)
		wg.Add(1)
	}

	quit := make(chan int)
	go showProgress(quit)

	// Reader closers c_inp on completion
	e := stdinReader(p_ch)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %s\n", e)
	}

	close(p_ch)
	wg.Wait()

	close(s_ch)
	<-s_done

	if e := s.Write(w); e != nil {
		fmt.Fprintf(os.Stderr, "[-] Error writing MTBL: %s\n", e)
		os.Exit(1)
	}

	quit <- 0

	s.Destroy()
	w.Destroy()
}
