package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/hdm/inetdata-parsers"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var output_count int64 = 0
var input_count int64 = 0
var stdout_lock sync.Mutex
var wg1 sync.WaitGroup
var wg2 sync.WaitGroup

type OutputKey struct {
	Key  string
	Vals []string
}

type DNSRecord struct {
	Timestamp string `json:"timestamp"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Value     string `json:"value"`
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Reads an unsorted Sonar v2 FDNS/RDNS JSONL from stdin, writes out sorted and merged normal and inverse CSVs.")
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
				fmt.Fprintf(os.Stderr, "[*] [inetdata-csvsplit] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out)\n",
					icount,
					ocount,
					int(elapsed.Seconds()),
					int(float64(icount)/elapsed.Seconds()),
					int(float64(ocount)/elapsed.Seconds()))
			}
		}
	}
}

func outputWriter(fd io.WriteCloser, c chan string) {
	for r := range c {
		fd.Write([]byte(r))
		atomic.AddInt64(&output_count, 1)
	}
	wg1.Done()
}

func inputParser(c chan string, c_names chan string, c_inverse chan string) {

	for r := range c {

		rec := DNSRecord{}

		mapped := map[string]string{}
		err := json.Unmarshal([]byte(r), &mapped)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Bad JSON: %s\n", r)
			continue
		}

		if val, ok := mapped["name"]; ok {
			rec.Name = strings.TrimSpace(val)
		} else {
			continue
		}

		if val, ok := mapped["type"]; ok {
			rec.Type = strings.TrimSpace(val)
		} else {
			continue
		}

		if val, ok := mapped["value"]; ok {
			rec.Value = strings.TrimSpace(val)
		} else {
			continue
		}

		if val, ok := mapped["timestamp"]; ok {
			rec.Timestamp = strings.TrimSpace(val)
		} else {
			continue
		}

		// Skip any record that refers to itself
		if rec.Value == rec.Name {
			continue
		}

		// Skip any record with an empty value
		if len(rec.Value) == 0 || len(rec.Name) == 0 {
			continue
		}

		if rec.Type == "ptr" {
			// Determine the field type based on pattern
			if inetdata.Match_IPv4.Match([]byte(rec.Name)) {
				rec.Type = "a"
			} else if inetdata.Match_IPv6.Match([]byte(rec.Name)) {
				rec.Type = "aaaa"
			}
		}

		atomic.AddInt64(&input_count, 1)

		switch rec.Type {
		case "a":
			// Skip invalid IPv4 records (TODO: verify logic)
			if !(inetdata.Match_IPv4.Match([]byte(rec.Value)) || inetdata.Match_IPv4.Match([]byte(rec.Name))) {
				continue
			}
			c_names <- fmt.Sprintf("%s,%s,%s\n", rec.Name, rec.Type, rec.Value)
			c_inverse <- fmt.Sprintf("%s,r-%s,%s\n", rec.Value, rec.Type, rec.Name)

		case "aaaa":
			// Skip invalid IPv6 records (TODO: verify logic)
			if !(inetdata.Match_IPv6.Match([]byte(rec.Value)) || inetdata.Match_IPv6.Match([]byte(rec.Name))) {
				continue
			}
			c_names <- fmt.Sprintf("%s,%s,%s\n", rec.Name, rec.Type, rec.Value)
			c_inverse <- fmt.Sprintf("%s,r-%s,%s\n", rec.Value, rec.Type, rec.Name)

		case "cname", "ns", "ptr":
			c_names <- fmt.Sprintf("%s,%s,%s\n", rec.Name, rec.Type, rec.Value)
			c_inverse <- fmt.Sprintf("%s,r-%s,%s\n", rec.Value, rec.Type, rec.Name)

		case "mx":
			parts := strings.SplitN(rec.Value, " ", 2)
			if len(parts) != 2 || len(parts[1]) == 0 {
				continue
			}
			c_names <- fmt.Sprintf("%s,%s,%s\n", rec.Name, rec.Type, parts[1])
			c_inverse <- fmt.Sprintf("%s,r-%s,%s\n", parts[1], rec.Type, rec.Name)

		default:
			// No inverse output for other record types (TXT, DNSSEC, etc)
			c_names <- fmt.Sprintf("%s,%s,%s\n", rec.Name, rec.Type, rec.Value)
		}
	}
	wg2.Done()
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1, "The maximum amount of memory to use, in gigabytes, for each of the six sort processes")
	version := flag.Bool("version", false, "Show the version and build timestamp")

	flag.Parse()

	if *version {
		inetdata.PrintVersion("inetdata-sonardnsv2-split")
		os.Exit(0)
	}

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}

	if len(*sort_tmp) == 0 {
		*sort_tmp = os.Getenv("HOME")
	}

	if len(*sort_tmp) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Output files
	base := flag.Args()[0]
	out_fds := []*os.File{}

	suffix := []string{"-names.gz", "-names-inverse.gz"}
	for i := range suffix {
		fd, e := os.Create(base + suffix[i])
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create %s: %s\n", base+suffix[i], e)
			os.Exit(1)
		}
		out_fds = append(out_fds, fd)
		defer fd.Close()
	}

	// Sort and compression pipes
	sort_input := [2]io.WriteCloser{}
	subprocs := []*exec.Cmd{}

	for i := range out_fds {

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
		sort_input[i] = sort_stdin
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
		if soe != nil {
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

		// Create a pigz compressor process
		pigz_proc := exec.Command("nice", "pigz", "-c")

		// Configure stdio
		pigz_proc.Stderr = os.Stderr

		// Feed output file with pigz output
		pigz_proc.Stdout = out_fds[i]

		// Feed pigz with sort output
		pigz_proc.Stdin = sort2_stdout

		// Start the pigz process
		e := pigz_proc.Start()
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to execute the pigz command: %s\n", e)
			os.Exit(1)
		}

		subprocs = append(subprocs, pigz_proc)
	}

	c_names := make(chan string, 1000)
	c_inverse := make(chan string, 1000)

	go outputWriter(sort_input[0], c_names)
	go outputWriter(sort_input[1], c_inverse)
	wg1.Add(2)

	// Progress tracker
	quit := make(chan int)
	go showProgress(quit)

	// Parse stdin
	c_inp := make(chan string, 1000)
	go inputParser(c_inp, c_names, c_inverse)
	go inputParser(c_inp, c_names, c_inverse)
	wg2.Add(2)

	// Reader closes c_inp on completion
	e := inetdata.ReadLines(os.Stdin, c_inp)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %s\n", e)
	}

	// Wait for the input parsers to finish
	wg2.Wait()

	close(c_names)
	close(c_inverse)

	// Wait for the channel writers to finish
	wg1.Wait()

	for i := range sort_input {
		sort_input[i].Close()
	}

	// Stop the main process monitoring, since stats are now static
	quit <- 0

	// Wait for the downstream processes to complete
	for i := range subprocs {
		subprocs[i].Wait()
	}

	for i := range out_fds {
		out_fds[i].Close()
	}
}
