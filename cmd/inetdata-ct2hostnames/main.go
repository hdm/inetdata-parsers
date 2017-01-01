package main

import (
	"encoding/json"
	"flag"
	"fmt"
	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/tls"
	"github.com/google/certificate-transparency/go/x509"
	"github.com/hdm/inetdata-parsers"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var output_count int64 = 0
var input_count int64 = 0

var wi sync.WaitGroup
var wo sync.WaitGroup

type CTEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Reads a CT log in JSONL format (one line per record) and emits hostnames")
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

			if icount == 0 && ocount == 0 {
				// Reset start, so that we show stats only from our first input
				start = time.Now()
				continue
			}
			elapsed := time.Since(start)
			if elapsed.Seconds() > 1.0 {
				fmt.Fprintf(os.Stderr, "[*] [inetdata-ct2hostnames] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out)\n",
					icount,
					ocount,
					int(elapsed.Seconds()),
					int(float64(icount)/elapsed.Seconds()),
					int(float64(ocount)/elapsed.Seconds()))
			}
		}
	}
}

func outputWriter(o <-chan string) {
	for name := range o {
		fmt.Println(name)
		atomic.AddInt64(&output_count, 1)
	}
	wo.Done()
}

func inputParser(c <-chan string, o chan<- string) {

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

		if _, err := inetdata.PublicSuffixFind(cert.Subject.CommonName); err == nil {
			names[strings.ToLower(cert.Subject.CommonName)] = struct{}{}
		}

		for _, alt := range cert.DNSNames {
			if _, err := inetdata.PublicSuffixFind(alt); err == nil {
				names[strings.ToLower(alt)] = struct{}{}
			}
		}

		// Write the names to the output channel
		for n := range names {
			o <- n
		}
	}

	wi.Done()
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	version := flag.Bool("version", false, "Show the version and build timestamp")

	flag.Parse()

	if *version {
		inetdata.PrintVersion()
		os.Exit(0)
	}

	// Start the progress tracker
	quit := make(chan int)
	go showProgress(quit)

	// Input
	c_inp := make(chan string)

	// Output
	c_out := make(chan string)

	// Launch one input parser per core
	for i := 0; i < runtime.NumCPU(); i++ {
		go inputParser(c_inp, c_out)
	}
	wi.Add(runtime.NumCPU())

	// Launch a single output writer
	go outputWriter(c_out)
	wo.Add(1)

	// Reader closers c_inp on completion
	e := inetdata.ReadLines(os.Stdin, c_inp)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %s\n", e)
	}

	// Wait for the input parsers
	wi.Wait()

	// Close the output handle
	close(c_out)

	// Wait for the output goroutine
	wo.Wait()

	// Stop the progress monitor
	quit <- 0
}
