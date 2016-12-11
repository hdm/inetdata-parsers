package main

import (
	"bufio"
	"flag"
	"fmt"
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
			if input_count == 0 && output_count == 0 {
				// Reset start, so that we show stats only from our first input
				start = time.Now()
				continue
			}
			elapsed := time.Since(start)
			if elapsed.Seconds() > 1.0 {
				fmt.Fprintf(os.Stderr, "[*] [sonar-csvinvert] Read %d and wrote %d records in %d seconds (%d/s in, %d/s out)\n",
					input_count,
					output_count,
					int(elapsed.Seconds()),
					int(float64(input_count)/elapsed.Seconds()),
					int(float64(output_count)/elapsed.Seconds()))
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

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

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
	wg.Add(3)

	// Progress tracker
	quit := make(chan int)
	go showProgress(quit)

	scanner := bufio.NewScanner(os.Stdin)

	// Support extremely long lines
	buf := make([]byte, 0, 1024*1024*64)
	scanner.Buffer(buf, 1024*1024*64)

	// Parse the FDNS file to create inverse outputs
	for scanner.Scan() {
		raw := strings.TrimSpace(scanner.Text())
		if len(raw) == 0 {
			continue
		}

		bits := strings.SplitN(raw, ",", 3)

		if len(bits) != 3 || len(bits[0]) == 0 || len(bits[1]) == 0 || len(bits[2]) == 0 {
			fmt.Fprintf(os.Stderr, "[-] Invalid line: %s\n", raw)
			continue
		}

		name := bits[0]
		rtype := bits[1]
		value := bits[2]

		input_count++

		switch rtype {
		case "a":
			c_ip4 <- fmt.Sprintf("%s,%s\n", value, name)

		case "aaaa":
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

	close(c_ip4)
	close(c_ip6)
	close(c_names)

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
