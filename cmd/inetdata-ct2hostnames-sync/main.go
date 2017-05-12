package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/hdm/inetdata-parsers"
	"golang.org/x/net/publicsuffix"
	"io/ioutil"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var CTLogs = []string{
	"https://ct.googleapis.com/pilot",
	"https://ct.googleapis.com/aviator",
	"https://ct.googleapis.com/rocketeer",
	"https://ct.googleapis.com/submariner",
	"https://ct.googleapis.com/skydiver",
	"https://ct.googleapis.com/icarus",
	"https://ct.googleapis.com/daedalus",
	"https://ct1.digicert-ct.com/log",
	"https://ct.izenpe.eus",
	"https://ct.ws.symantec.com",
	"https://vega.ws.symantec.com",
	"https://ctlog.api.venafi.com",
	"https://ctlog-gen2.api.venafi.com",
	"https://ctlog.wosign.com",
	"https://ctserver.cnnic.cn",
	"https://ct.startssl.com",
	"https://www.certificatetransparency.cn/ct",
}

var output_count int64 = 0
var input_count int64 = 0
var timestamps *bool
var storagedir *string
var tail *int
var follow *bool

var wd sync.WaitGroup
var wi sync.WaitGroup
var wo sync.WaitGroup

type CTEntry struct {
	LeafInput []byte `json:"leaf_input"`
	ExtraData []byte `json:"extra_data"`
}

type CTEntries struct {
	Entries []CTEntry `json:"entries"`
}

type CTEntriesError struct {
	ErrorMessage string `json:"error_message"`
	Success      bool   `json:"success"`
}

type CTHead struct {
	TreeSize          int64  `json:"tree_size"`
	Timestamp         int64  `json:"timestamp"`
	SHA256RootHash    string `json:"sha256_root_hash"`
	TreeHeadSignature string `json:"tree_head_signature"`
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Synchronizes data from one or more CT logs and extract hostnames")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func downloadJSON(url string) ([]byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}, err
	}

	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}, err
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}, err
	}

	return content, err
}

func downloadSTH(logurl string) (CTHead, error) {
	var sth CTHead
	url := fmt.Sprintf("%s/ct/v1/get-sth", logurl)
	data, err := downloadJSON(url)
	if err != nil {
		return sth, err
	}

	err = json.Unmarshal(data, &sth)
	return sth, err
}

func downloadEntries(logurl string, start_index int64, stop_index int64) (CTEntries, error) {
	var entries CTEntries
	var entries_error CTEntriesError

	url := fmt.Sprintf("%s/ct/v1/get-entries?start=%d&end=%d", logurl, start_index, stop_index)
	data, err := downloadJSON(url)
	if err != nil {
		return entries, err
	}

	if strings.Contains(string(data), "\"error_message\":") {
		err = json.Unmarshal(data, &entries_error)
		if err != nil {
			return entries, err
		}
		return entries, errors.New(entries_error.ErrorMessage)
	}

	err = json.Unmarshal(data, &entries)
	return entries, err
}

func logNameToPath(name string) string {
	bits := strings.SplitN(name, "//", 2)
	return strings.Replace(bits[1], "/", "_", -1)
}

func downloadLog(log string, c_inp chan<- CTEntry) {
	defer wd.Done()

	sth, sth_err := downloadSTH(log)
	if sth_err != nil {
		fmt.Fprintf(os.Stderr, "Failed to download STH for %s: %s\n", log, sth_err)
	}

	var start_index int64 = 0

	if *tail > 0 {
		start_index = sth.TreeSize - int64(*tail)
		if start_index < 0 {
			start_index = 0
		}
	}

	var entry_count int64 = 1000

	for index := start_index; index < sth.TreeSize; index += entry_count {
		stop_index := index + entry_count - 1
		if stop_index >= sth.TreeSize {
			stop_index = sth.TreeSize - 1
		}

		entries, err := downloadEntries(log, index, stop_index)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to download entries for %s: index %d -> %s\n", log, index, err)
			return
		}
		for entry_index := range entries.Entries {
			c_inp <- entries.Entries[entry_index]
		}
	}
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
				fmt.Fprintf(os.Stderr, "[*] [inetdata-ct2hostnames-sync] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out)\n",
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

func inputParser(c <-chan CTEntry, o chan<- string) {

	for entry := range c {

		var leaf ct.MerkleTreeLeaf

		if rest, err := tls.Unmarshal(entry.LeafInput, &leaf); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal MerkleTreeLeaf: %v (%v)", err, entry)
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
			fmt.Fprintf(os.Stderr, "Unknown entry type: %v (%v)", leaf.TimestampedEntry.EntryType, entry)
			continue
		}

		// Valid input
		atomic.AddInt64(&input_count, 1)

		var names = make(map[string]struct{})

		if _, err := publicsuffix.EffectiveTLDPlusOne(cert.Subject.CommonName); err == nil {
			// Make sure the CN looks like an actual hostname
			if strings.Contains(cert.Subject.CommonName, " ") ||
				strings.Contains(cert.Subject.CommonName, ":") ||
				inetdata.Match_IPv4.Match([]byte(cert.Subject.CommonName)) {
				continue
			}
			names[strings.ToLower(cert.Subject.CommonName)] = struct{}{}
		}

		for _, alt := range cert.DNSNames {
			if _, err := publicsuffix.EffectiveTLDPlusOne(alt); err == nil {
				// Make sure the CN looks like an actual hostname
				if strings.Contains(alt, " ") ||
					strings.Contains(alt, ":") ||
					inetdata.Match_IPv4.Match([]byte(alt)) {
					continue
				}
				names[strings.ToLower(alt)] = struct{}{}
			}
		}

		// Write the names to the output channel
		if *timestamps {
			for n := range names {
				o <- fmt.Sprintf("%d\t%s", leaf.TimestampedEntry.Timestamp, n)
			}
		} else {
			for n := range names {
				o <- n
			}
		}
	}

	wi.Done()
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	version := flag.Bool("version", false, "Show the version and build timestamp")
	timestamps = flag.Bool("timestamps", false, "Prefix all extracted names with the CT entry timestamp")
	storagedir = flag.String("storage", os.Getenv("HOME")+"/.ct", "The filesystem path to use for storage")
	logurl := flag.String("logurl", "", "Only read from the specified CT log url")
	tail = flag.Int("tail", 0, "Only retrieve the specified number of entries per log (0 for all)")
	follow = flag.Bool("follow", false, "Follow the head of the log")

	flag.Parse()

	if *version {
		inetdata.PrintVersion("inetdata-ct2hostnames-sync")
		os.Exit(0)
	}

	logs := []string{}
	if len(*logurl) > 0 {
		logs = append(logs, *logurl)
	} else {
		for idx := range CTLogs {
			logs = append(logs, CTLogs[idx])
		}
	}

	// Start the progress tracker
	quit := make(chan int)
	go showProgress(quit)

	// Input
	c_inp := make(chan CTEntry)

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

	for idx := range logs {
		go downloadLog(logs[idx], c_inp)
		wd.Add(1)
	}
	// Wait for downloaders
	wd.Wait()

	// Close the input channel
	close(c_inp)

	// Wait for the input parsers
	wi.Wait()

	// Close the output handle
	close(c_out)

	// Wait for the output goroutine
	wo.Wait()

	// Stop the progress monitor
	quit <- 0
}
