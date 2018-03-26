package main

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hdm/inetdata-parsers"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"golang.org/x/net/publicsuffix"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

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

type ParsedCTEntry struct {
	Sha1Hash   string   `json:"h"`
	Timestamp  uint64   `json:"t"`
	CommonName string   `json:"cn,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	IP         []net.IP `json:"ip,omitempty"`
	Email      []string `json:"email,omitempty"`
}

type ParsedCTEntryOutput struct {
	Certs []ParsedCTEntry `json:"certs"`
}

type NewRecord struct {
	Key []byte
	Val []byte
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Reads a CT log in JSONL format (one line per record) and emits a CSV")
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
				fmt.Fprintf(os.Stderr, "[*] [inetdata-ct2csv] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out) (merged: %d, invalid: %d)\n",
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

func writeToOutput(c chan NewRecord, d chan bool) {

	for r := range c {
		fmt.Fprintf(os.Stdout, "%s\t%s\n", r.Key, r.Val)
	}

	// Signal that we are done
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

		outm := ParsedCTEntryOutput{}

		for i := range vals {
			info := ParsedCTEntry{}

			if err := json.Unmarshal([]byte(vals[i]), &info); err != nil {
				fmt.Fprintf(os.Stderr, "[-] Could not unmarshal %s: %s\n", vals[i], err)
				continue
			}
			outm.Certs = append(outm.Certs, info)
		}

		json, e := json.Marshal(outm)
		if e != nil {
			fmt.Fprintf(os.Stderr, "[-] Could not marshal %v: %s\n", outm, e)
			continue
		}

		// Reverse the key unless its an IP address or SHA1 hash
		if !(inetdata.Match_IPv4.Match([]byte(name)) ||
			inetdata.Match_IPv6.Match([]byte(name)) ||
			inetdata.Match_SHA1.Match([]byte(name))) {
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

		for _, alt := range cert.IPAddresses {
			names[fmt.Sprintf("%s", alt)] = struct{}{}
		}

		sha1 := sha1.Sum(cert.Raw)
		sha1hash := hex.EncodeToString(sha1[:])
		wrote_hash := false

		// Write the names to the output channel
		for n := range names {

			info := ParsedCTEntry{Sha1Hash: sha1hash, Timestamp: leaf.TimestampedEntry.Timestamp}
			info.CommonName = scrubX509Value(cert.Subject.CommonName)

			// Dump associated email addresses if available
			for _, extra := range cert.EmailAddresses {
				info.Email = append(info.Email, scrubX509Value(extra))
			}

			// Dump associated IP addresses if we have at least one name
			for _, extra := range cert.IPAddresses {
				info.IP = append(info.IP, extra)
			}

			// Dump associated SANs (overkill, but saves a second lookup)
			for _, extra := range cert.DNSNames {
				info.DNS = append(info.DNS, extra)
			}

			info_bytes, err := json.Marshal(info)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to marshal: %s %+v", n, info)
				continue
			}

			if wrote_hash == false {
				o <- fmt.Sprintf("%s,%s\n", sha1hash, info_bytes)
				wrote_hash = true
			}

			o <- fmt.Sprintf("%s,%s\n", n, info_bytes)
		}
	}

	wg_raw_ct_input.Done()
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1, "The maximum amount of memory to use, in gigabytes, for the sorting phases")
	version := flag.Bool("version", false, "Show the version and build timestamp")

	flag.Parse()

	if *version {
		inetdata.PrintVersion("inetdata-ct2csv")
		os.Exit(0)
	}

	if len(*sort_tmp) == 0 {
		*sort_tmp = os.Getenv("HOME")
	}

	if len(*sort_tmp) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	jsonl_writer_ch := make(chan NewRecord, 1)
	jsonl_writer_done := make(chan bool, 1)

	// Read from the jsonl_writer_ch for NewRecords and write to the CSV writer
	go writeToOutput(jsonl_writer_ch, jsonl_writer_done)

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

	// Read rollup entries, convert to json, send to the CSV writer
	c_ct_sorted_output := make(chan string)
	wg_sorted_ct_parser.Add(1)
	go sortedCTParser(c_ct_sorted_output, jsonl_writer_ch)

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

	// Wait for the json writer to finish
	<-jsonl_writer_done

	// Stop the progress monitor
	quit <- 0
}
