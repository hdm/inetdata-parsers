package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var match_ipv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

var match_ipv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

var output_count int64 = 0
var input_count int64 = 0
var stdout_lock sync.Mutex
var wg sync.WaitGroup

type OutputKey struct {
	Key  string
	Vals []string
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options]")
	fmt.Println("")
	fmt.Println("Reads an unsorted FDNS CSV from stdin, inverts the keys with the values, and writes ")
	fmt.Println("unsorted output to stdout. Record types are prepended with 'r' to indicate that the")
	fmt.Println("relationship is inverted.")
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

			if icount == 0 && ocount == 0 {
				// Reset start, so that we show stats only from our first input
				start = time.Now()
				continue
			}
			elapsed := time.Since(start)
			if elapsed.Seconds() > 1.0 {
				fmt.Fprintf(os.Stderr, "[*] [sonar-csvinvert] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out)\n",
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

func inputParser(c chan string, c_ip4 chan string, c_ip6 chan string, c_names chan string) {

	for r := range c {

		raw := strings.TrimSpace(r)

		if len(raw) == 0 {
			continue
		}

		var name, rtype, value string

		bits := strings.SplitN(raw, ",", 3)

		if len(bits) < 2 || len(bits[0]) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Invalid line: %q\n", raw)
			continue
		}

		// Tons of records with a blank (".") DNS response, just ignore
		if len(bits[1]) == 0 {
			continue
		}

		name = bits[0]

		if len(bits) == 3 {
			// FDNS data with three fields
			rtype = bits[1]
			value = bits[2]
		}

		if len(bits) == 2 {
			// RDNS data with two fields
			value = bits[1]

			// Determine the field type based on pattern
			if match_ipv4.Match([]byte(name)) {
				rtype = "a"
			} else if match_ipv6.Match([]byte(name)) {
				rtype = "aaaa"
			} else {
				fmt.Fprintf(os.Stderr, "[-] Unknown two-field format: %s\n", raw)
				continue
			}
		}

		// Skip any record that refers to itself
		if value == name {
			continue
		}

		atomic.AddInt64(&input_count, 1)

		switch rtype {
		case "a":
			// Skip invalid IPv4 records
			if !match_ipv4.Match([]byte(value)) {
				continue
			}
			c_ip4 <- fmt.Sprintf("%s,%s\n", value, name)

		case "aaaa":
			// Skip invalid IPv6 records
			if !match_ipv6.Match([]byte(value)) {
				continue
			}
			c_ip6 <- fmt.Sprintf("%s,%s\n", value, name)

		case "cname", "ns", "ptr":
			c_names <- fmt.Sprintf("%s,r-%s,%s\n", value, rtype, name)

		case "mx":
			parts := strings.SplitN(value, " ", 2)
			if len(parts) != 2 || len(parts[1]) == 0 {
				continue
			}
			c_names <- fmt.Sprintf("%s,r-%s,%s\n", parts[1], rtype, name)
		}
	}
	wg.Done()
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }
	sort_tmp := flag.String("t", "", "The temporary directory to use for the sorting phase")
	sort_mem := flag.Uint64("m", 1, "The maximum amount of memory to use, in gigabytes, for each of the six sort processes")

	flag.Parse()

	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(1)
	}

	if len(*sort_tmp) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	// Output files
	base := flag.Args()[0]
	out_fds := []*os.File{}

	suffix := []string{"-ip4.gz", "-ip6.gz", "-names.gz"}
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
	sort_input := [3]io.WriteCloser{}
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

		// Create the sonar-csvrollup process
		roll_proc := exec.Command("nice", "sonar-csvrollup")

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
			fmt.Fprintf(os.Stderr, "Error: failed to execute the sonar-csvrollup command: %s\n", e)
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

	c_ip4 := make(chan string, 1000)
	c_ip6 := make(chan string, 1000)
	c_names := make(chan string, 1000)

	go outputWriter(sort_input[0], c_ip4)
	go outputWriter(sort_input[1], c_ip6)
	go outputWriter(sort_input[2], c_names)

	// Progress tracker
	quit := make(chan int)
	go showProgress(quit)

	// Parse stdin
	c_inp := make(chan string, 1000)
	go inputParser(c_inp, c_ip4, c_ip6, c_names)
	go inputParser(c_inp, c_ip4, c_ip6, c_names)
	wg.Add(2)

	// Reader closers c_inp on completion
	e := stdinReader(c_inp)
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %s\n", e)
	}

	// Wait for the input parsers to finish
	wg.Wait()

	close(c_ip4)
	close(c_ip6)
	close(c_names)

	// Wait for the channel writers to finish
	wg.Add(3)
	wg.Wait()

	for i := range sort_input {
		sort_input[i].Close()
	}

	// Stop the main process monitoring, since stats are now static
	quit <- 0

	// Wait for the downstream processes to complete
	for i := range subprocs {
		fmt.Fprintf(os.Stderr, "Waiting on subproc #%d\n", i)
		subprocs[i].Wait()
	}

	for i := range out_fds {
		out_fds[i].Close()
	}
}
