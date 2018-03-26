package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hdm/golang-mtbl"
	"github.com/hdm/inetdata-parsers"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/net/publicsuffix"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
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
var output_count int64 = 0
var input_count int64 = 0
var invalid_count int64 = 0
var timestamps *bool

var wg_raw_ct_input sync.WaitGroup
var wg_parsed_ct_writer sync.WaitGroup
var wg_sorted_ct_parser sync.WaitGroup
var wg_sort_reader sync.WaitGroup

type CTEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type NewRecord struct {
	Key []byte
	Val []byte
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options] <output.mtbl>")
	fmt.Println("")
	fmt.Println("Reads a CT log in JSONL format (one line per record) and emits a MTBL")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func showProgress(quit chan int) {
	start := time.Now()
	for {
		select {
		case <-quit:
			return
		case <-time.After(time.Second * 1):
			icount := atomic.LoadInt64(&input_count)
			ocount := atomic.LoadInt64(&output_count)
			mcount := atomic.LoadInt64(&merge_count)
			ecount := atomic.LoadInt64(&invalid_count)

			if icount == 0 && ocount == 0 {
				// Reset start, so that we show stats only from our first input
				start = time.Now()
				continue
			}
			elapsed := time.Since(start)
			if elapsed.Seconds() > 1.0 {
				fmt.Fprintf(os.Stderr, "[*] [inetdata-ct2mtbl] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out) (merged: %d, invalid: %d)\n",
					icount,
					ocount,
					int(elapsed.Seconds()),
					int(float64(icount)/elapsed.Seconds()),
					int(float64(ocount)/elapsed.Seconds()),
					mcount, ecount)
			}
		}
	}
}

func scrubX509Value(bit string) string {
	bit = strings.Replace(bit, "\x00", "[0x00]", -1)
	bit = strings.Replace(bit, " ", "_", -1)
	return bit
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

func writeToMtbl(s *mtbl.Sorter, c chan NewRecord, d chan bool) {
	for r := range c {
		if e := s.Add(r.Key, r.Val); e != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to add key=%v (%v): %v\n", r.Key, r.Val, e)
		}
		atomic.AddInt64(&output_count, 1)
	}
	d <- true
}

func sortedCTParser(d chan string, c chan NewRecord) {

	for raw := range d {

		bits := strings.SplitN(raw, ",", 2)

		if len(bits) != 2 {
			continue
		}

		name := bits[0]
		data := bits[1]

		if len(name) == 0 || len(data) == 0 {
			atomic.AddInt64(&invalid_count, 1)
			continue
		}
		vals := strings.SplitN(data, "\x00", -1)

		outm := make(map[string][]string)
		for i := range vals {
			info := strings.SplitN(vals[i], ",", 2)
			if len(info) < 2 {
				continue
			}

			dkey := info[0]
			dval := info[1]

			cval, exists := outm[dkey]
			if exists {
				cval := append(cval, dval)
				outm[dkey] = cval
			} else {
				outm[dkey] = []string{dval}
			}

		}

		var outp [][]string

		for r := range outm {
			sorted_vals := outm[r]
			sort.Strings(sorted_vals)
			joined_vals := strings.Join(sorted_vals, " ")
			outp = append(outp, []string{r, joined_vals})
		}

		json, e := json.Marshal(outp)
		if e != nil {
			fmt.Fprintf(os.Stderr, "[-] Could not marshal %v: %s\n", outm, e)
			continue
		}

		// Reverse the key unless its an IP address
		if !(inetdata.Match_IPv4.Match([]byte(name)) || inetdata.Match_IPv6.Match([]byte(name))) {
			name = inetdata.ReverseKey(name)
		}

		c <- NewRecord{Key: []byte(name), Val: json}
	}

	close(c)

	wg_sorted_ct_parser.Done()
}

func parsedCTWriter(o <-chan string, fd io.WriteCloser) {
	for r := range o {
		fd.Write([]byte(r))
	}
	wg_parsed_ct_writer.Done()
}

func rawCTReader(c <-chan string, o chan<- string) {

	for r := range c {
		var entry CTEntry

		if err := json.Unmarshal([]byte(r), &entry); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing input: %s\n", r)
			continue
		}

		var leaf ct.MerkleTreeLeaf

		if rest, err := tls.Unmarshal(entry.LeafInput, &leaf); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal MerkleTreeLeaf: %v (%s)", err, r)
			continue
		} else if len(rest) > 0 {
			fmt.Fprintf(os.Stderr, "Trailing data (%d bytes) after MerkleTreeLeaf: %q", len(rest), rest)
			continue
		}

		var cert *x509.Certificate
		var err error

		switch leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:

			cert, err = x509.ParseCertificate(leaf.TimestampedEntry.X509Entry.Data)
			if err != nil && !strings.Contains(err.Error(), "NonFatalErrors:") {
				fmt.Fprintf(os.Stderr, "Failed to parse cert: %s\n", err.Error())
				continue
			}

		case ct.PrecertLogEntryType:

			cert, err = x509.ParseTBSCertificate(leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil && !strings.Contains(err.Error(), "NonFatalErrors:") {
				fmt.Fprintf(os.Stderr, "Failed to parse precert: %s\n", err.Error())
				continue
			}

		default:
			fmt.Fprintf(os.Stderr, "Unknown entry type: %v (%s)", leaf.TimestampedEntry.EntryType, r)
			continue
		}

		// Valid input
		atomic.AddInt64(&input_count, 1)

		var names = make(map[string]struct{})

		if _, err := publicsuffix.EffectiveTLDPlusOne(cert.Subject.CommonName); err == nil {
			// Make sure this looks like an actual hostname or IP address
			if !(inetdata.Match_IPv4.Match([]byte(cert.Subject.CommonName)) ||
				inetdata.Match_IPv6.Match([]byte(cert.Subject.CommonName))) &&
				(strings.Contains(cert.Subject.CommonName, " ") ||
					strings.Contains(cert.Subject.CommonName, ":")) {
				continue
			}
			names[strings.ToLower(cert.Subject.CommonName)] = struct{}{}
		}

		for _, alt := range cert.DNSNames {
			if _, err := publicsuffix.EffectiveTLDPlusOne(alt); err == nil {
				// Make sure this looks like an actual hostname or IP address
				if !(inetdata.Match_IPv4.Match([]byte(cert.Subject.CommonName)) ||
					inetdata.Match_IPv6.Match([]byte(cert.Subject.CommonName))) &&
					(strings.Contains(alt, " ") ||
						strings.Contains(alt, ":")) {
					continue
				}
				names[strings.ToLower(alt)] = struct{}{}
			}
		}

		sha1hash := ""

		// Write the names to the output channel
		for n := range names {
			if len(sha1hash) == 0 {
				sha1 := sha1.Sum(cert.Raw)
				sha1hash = hex.EncodeToString(sha1[:])
			}

			// Dump associated email addresses if available
			for _, extra := range cert.EmailAddresses {
				o <- fmt.Sprintf("%s,email,%s\n", n, strings.ToLower(scrubX509Value(extra)))
			}

			// Dump associated IP addresses if we have at least one name
			for _, extra := range cert.IPAddresses {
				o <- fmt.Sprintf("%s,ip,%s\n", n, extra)
			}

			o <- fmt.Sprintf("%s,ts,%d\n", n, leaf.TimestampedEntry.Timestamp)
			o <- fmt.Sprintf("%s,cn,%s\n", n, strings.ToLower(scrubX509Value(cert.Subject.CommonName)))
			o <- fmt.Sprintf("%s,sha1,%s\n", n, sha1hash)

			// Dump associated SANs (overkill, but saves a second lookup)
			for _, extra := range cert.DNSNames {
				o <- fmt.Sprintf("%s,dns,%s\n", n, strings.ToLower(extra))
			}
		}
	}

	wg_raw_ct_input.Done()
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	compression := flag.String("c", "snappy", "The compression type to use (none, snappy, zlib, lz4, lz4hc)")
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1, "The maximum amount of memory to use, in gigabytes, for the sorting phases")
	selected_merge_mode := flag.String("M", "combine", "The merge mode: combine, first, or last")
	version := flag.Bool("version", false, "Show the version and build timestamp")

	flag.Parse()

	if *version {
		inetdata.PrintVersion("inetdata-ct2mtbl")
		os.Exit(0)
	}

	if len(*sort_tmp) == 0 {
		*sort_tmp = os.Getenv("HOME")
	}

	if len(*sort_tmp) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Configure the MTBL output

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
	sort_opt.MaxMemory *= (*sort_mem * 1024)

	if len(*sort_tmp) > 0 {
		sort_opt.TempDir = *sort_tmp
	}

	compression_alg, ok := inetdata.MTBLCompressionTypes[*compression]
	if !ok {
		fmt.Fprintf(os.Stderr, "[-] Invalid compression algorithm: %s\n", *compression)
		os.Exit(1)
	}

	mtbl_sorter := mtbl.SorterInit(&sort_opt)
	mtbl_writer, w_e := mtbl.WriterInit(fname, &mtbl.WriterOptions{Compression: compression_alg})
	if w_e != nil {
		fmt.Fprintf(os.Stderr, "[-] Error: %s\n", w_e)
		os.Exit(1)
	}

	defer mtbl_sorter.Destroy()
	defer mtbl_writer.Destroy()

	mtbl_sorter_ch := make(chan NewRecord, 1)
	mtbl_sorter_done := make(chan bool, 1)

	// Read from the mtbl_sorter_ch for NewRecords and write to the MTBL sorter
	go writeToMtbl(mtbl_sorter, mtbl_sorter_ch, mtbl_sorter_done)

	// Create the sort and rollup pipeline
	subprocs := []*exec.Cmd{}

	// Create a sort process
	sort_proc := exec.Command("nice",
		"sort",
		"-u",
		"--key=1",
		"--field-separator=,",
		"--compress-program=pigz",
		fmt.Sprintf("--parallel=%d", runtime.NumCPU()),
		fmt.Sprintf("--temporary-directory=%s", *sort_tmp),
		fmt.Sprintf("--buffer-size=%dG", *sort_mem))

	// Configure stdio
	sort_stdin, sie := sort_proc.StdinPipe()
	if sie != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create sort stdin pipe: %s\n", sie)
		os.Exit(1)
	}

	sort_stdout, soe := sort_proc.StdoutPipe()
	if soe != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create sort stdout pipe: %s\n", soe)
		os.Exit(1)
	}

	sort_proc.Stderr = os.Stderr
	subprocs = append(subprocs, sort_proc)

	// Start the sort process
	if e := sort_proc.Start(); e != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to execute the sort command: %s\n", e)
		os.Exit(1)
	}

	// Create the inetdata-csvrollup process
	roll_proc := exec.Command("nice", "inetdata-csvrollup")

	// Configure stdio
	roll_stdout, roe := roll_proc.StdoutPipe()
	if roe != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create sort stdout pipe: %s\n", roe)
		os.Exit(1)
	}

	roll_proc.Stderr = os.Stderr
	roll_proc.Stdin = sort_stdout
	subprocs = append(subprocs, roll_proc)

	// Start the rollup process
	if e := roll_proc.Start(); e != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to execute the inetdata-csvrollup command: %s\n", e)
		os.Exit(1)
	}

	// Create a second sort process
	sort2_proc := exec.Command("nice",
		"sort",
		"-u",
		"--key=1",
		"--field-separator=,",
		"--compress-program=pigz",
		fmt.Sprintf("--parallel=%d", runtime.NumCPU()),
		fmt.Sprintf("--temporary-directory=%s", *sort_tmp),
		fmt.Sprintf("--buffer-size=%dG", *sort_mem))

	sort2_stdout, ssoe := sort2_proc.StdoutPipe()
	if ssoe != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to create sort stdout pipe: %s\n", ssoe)
		os.Exit(1)
	}
	sort2_proc.Stdin = roll_stdout
	sort2_proc.Stderr = os.Stderr

	subprocs = append(subprocs, sort2_proc)

	// Start the sort process
	if e := sort2_proc.Start(); e != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to execute the second sort command: %s\n", e)
		os.Exit(1)
	}

	// Read rollup entries, convert to json, send to the MTBL writer
	c_ct_sorted_output := make(chan string)
	wg_sorted_ct_parser.Add(1)
	go sortedCTParser(c_ct_sorted_output, mtbl_sorter_ch)

	wg_sort_reader.Add(1)
	go func() {
		// Read rollup entries from the sort pipe and send to the parser
		e := inetdata.ReadLinesFromReader(sort2_stdout, c_ct_sorted_output)
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error reading sort 2 input: %s\n", e)
			os.Exit(1)
		}
		wg_sort_reader.Done()
	}()

	// Start the progress tracker
	quit := make(chan int)
	go showProgress(quit)

	// Large channel buffer evens out spikey per-record processing time
	c_ct_raw_input := make(chan string, 4096)

	// Output
	c_ct_parsed_output := make(chan string)

	// Launch one input parser per core
	wg_raw_ct_input.Add(runtime.NumCPU())
	for i := 0; i < runtime.NumCPU(); i++ {
		go rawCTReader(c_ct_raw_input, c_ct_parsed_output)
	}

	// Launch a writer that feeds parsed entries into the sort input pipe
	wg_parsed_ct_writer.Add(1)
	go parsedCTWriter(c_ct_parsed_output, sort_stdin)

	// Read CT JSON from stdin, parse, and send to sort
	e := inetdata.ReadLines(os.Stdin, c_ct_raw_input)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %s\n", e)
	}

	// Wait for the input parsers
	wg_raw_ct_input.Wait()

	// Close the output handle
	close(c_ct_parsed_output)

	// Wait for the output goroutine
	wg_parsed_ct_writer.Wait()

	// Close the sort 1 input pipe
	sort_stdin.Close()

	// Wait for the sort reader
	wg_sort_reader.Wait()

	// Wait for subproceses to complete
	for i := range subprocs {
		subprocs[i].Wait()
	}

	// Wait for the sortedCT processor
	wg_sorted_ct_parser.Wait()

	// Wait for the MTBL sorter to finish
	<-mtbl_sorter_done

	// Finalize the MTBL sorter with a write
	if e = mtbl_sorter.Write(mtbl_writer); e != nil {
		fmt.Fprintf(os.Stderr, "[-] Error writing MTBL: %s\n", e)
		os.Exit(1)
	}

	// Stop the progress monitor
	quit <- 0
}
