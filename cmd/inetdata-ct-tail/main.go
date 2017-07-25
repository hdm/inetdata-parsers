package main

import (
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/fathom6/inetdata-parsers"
	ct "github.com/google/certificate-transparency-go"
	ct_tls "github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
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
	"https://ct2.digicert-ct.com/log",
	"https://ct.izenpe.eus",
	"https://ct.ws.symantec.com",
	"https://vega.ws.symantec.com",
	"https://sirius.ws.symantec.com",
	"https://ctlog.api.venafi.com",
	"https://ctlog-gen2.api.venafi.com",
	"https://ctlog.wosign.com",
	"https://ctserver.cnnic.cn",
	"https://ct.startssl.com",
	"https://www.certificatetransparency.cn/ct",
	"https://ct.gdca.com.cn",
	"https://ctlog.gdca.com.cn",
}

var output_count int64 = 0
var input_count int64 = 0
var number *int
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

func scrubX509Value(bit string) string {
	bit = strings.Replace(bit, "\x00", "[0x00]", -1)
	bit = strings.Replace(bit, " ", "_", -1)
	return bit
}

func downloadJSON(url string) ([]byte, error) {

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}, err
	}

	req.Header.Set("Accept", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}

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
	var iteration int64 = 0
	var current_index int64 = 0

	defer wd.Done()

	for {

		if iteration > 0 {
			fmt.Fprintf(os.Stderr, "[*] Sleeping for 10 seconds (%s) at index %d\n", log, current_index)
			time.Sleep(time.Duration(10) * time.Second)
		}

		sth, sth_err := downloadSTH(log)
		if sth_err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to download STH for %s: %s\n", log, sth_err)
		}

		var start_index int64 = 0

		if iteration == 0 {
			start_index = sth.TreeSize - int64(*number)
			if start_index < 0 {
				start_index = 0
			}
			current_index = start_index
		} else {
			start_index = current_index
		}

		var entry_count int64 = 1000

		for index := start_index; index < sth.TreeSize; index += entry_count {
			stop_index := index + entry_count - 1
			if stop_index >= sth.TreeSize {
				stop_index = sth.TreeSize - 1
			}

			entries, err := downloadEntries(log, index, stop_index)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Failed to download entries for %s: index %d -> %s\n", log, index, err)
				return
			}
			for entry_index := range entries.Entries {
				c_inp <- entries.Entries[entry_index]
			}
		}

		// Move our index to the end of the last tree
		current_index = sth.TreeSize
		iteration++

		// Break after one loop unless we are in follow mode
		if !*follow {
			break
		}

	}
}

func outputWriter(o <-chan string) {
	for name := range o {
		fmt.Print(name)
		atomic.AddInt64(&output_count, 1)
	}
	wo.Done()
}

func inputParser(c <-chan CTEntry, o chan<- string) {

	for entry := range c {

		var leaf ct.MerkleTreeLeaf

		if rest, err := ct_tls.Unmarshal(entry.LeafInput, &leaf); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to unmarshal MerkleTreeLeaf: %v (%v)", err, entry)
			continue
		} else if len(rest) > 0 {
			fmt.Fprintf(os.Stderr, "[-] Trailing data (%d bytes) after MerkleTreeLeaf: %q", len(rest), rest)
			continue
		}

		var cert *x509.Certificate
		var err error

		switch leaf.TimestampedEntry.EntryType {
		case ct.X509LogEntryType:

			cert, err = x509.ParseCertificate(leaf.TimestampedEntry.X509Entry.Data)
			if err != nil && !strings.Contains(err.Error(), "NonFatalErrors:") {
				fmt.Fprintf(os.Stderr, "[-] Failed to parse cert: %s\n", err.Error())
				continue
			}

		case ct.PrecertLogEntryType:

			cert, err = x509.ParseTBSCertificate(leaf.TimestampedEntry.PrecertEntry.TBSCertificate)
			if err != nil && !strings.Contains(err.Error(), "NonFatalErrors:") {
				fmt.Fprintf(os.Stderr, "[-] Failed to parse precert: %s\n", err.Error())
				continue
			}

		default:
			fmt.Fprintf(os.Stderr, "[-] Unknown entry type: %v (%v)", leaf.TimestampedEntry.EntryType, entry)
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

			// Dump associated SANs
			for _, extra := range cert.DNSNames {
				o <- fmt.Sprintf("%s,dns,%s\n", strings.ToLower(extra), n)
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
	logurl := flag.String("logurl", "", "Only read from the specified CT log url")
	number = flag.Int("n", 100, "The number of entries from the end to start from")
	follow = flag.Bool("f", false, "Follow the tail of the CT log")

	flag.Parse()

	if *version {
		inetdata.PrintVersion("inetdata-ct-tail")
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
}
