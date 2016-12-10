package main

import (
	"flag"
	"fmt"
	"github.com/edmonds/golang-mtbl"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
)

func reverseKey(s string) string {
	b := make([]byte, len(s))
	var j int = len(s) - 1
	for i := 0; i <= j; i++ {
		b[j-i] = s[i]
	}
	return string(b)
}

func usage() {
	fmt.Println("Usage: " + os.Args[0] + " [options] <mtbl> ... <mtbl>")
	fmt.Println("")
	fmt.Println("Queries one or more MTBL databases")
	fmt.Println("")
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func findPaths(args []string) []string {
	var paths []string
	for i := range args {
		path := args[i]
		info, e := os.Stat(path)
		if e != nil {
			fmt.Fprintf(os.Stderr, "Error: Path %s : %v\n", path, e)
			os.Exit(1)
		}

		if info.Mode().IsRegular() {
			paths = append(paths, path)
			continue
		}

		if info.Mode().IsDir() {
			if files, e := ioutil.ReadDir(path); e == nil {
				for _, f := range files {
					if f.Mode().IsRegular() {
						npath := path + string(os.PathSeparator) + f.Name()
						paths = append(paths, npath)
					}
				}
			}
		}
	}
	return paths
}

func main() {

	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Usage = func() { usage() }

	key_only := flag.Bool("k", false, "Display key names only")
	val_only := flag.Bool("v", false, "Display values only")
	prefix := flag.String("p", "", "Only return keys with this prefix")
	rev_prefix := flag.String("r", "", "Only return keys with this prefix in reverse form")
	rev_key := flag.Bool("R", false, "Display matches with the key in reverse form")
	zero_split := flag.Bool("z", false, "Split values into arrays using the null byte")
	no_quotes := flag.Bool("n", false, "Print raw values, not quoted values")

	flag.Parse()

	if len(flag.Args()) == 0 {
		usage()
		os.Exit(1)
	}

	if *key_only && *val_only {
		fmt.Fprintf(os.Stderr, "Error: Only one of -k or -v can be specified\n")
		usage()
		os.Exit(1)
	}

	if len(*prefix) > 0 && len(*rev_prefix) > 0 {
		fmt.Fprintf(os.Stderr, "Error: Only one of -p or -r can be specified\n")
		usage()
		os.Exit(1)
	}

	paths := findPaths(flag.Args())

	for i := range paths {
		path := paths[i]
		r, e := mtbl.ReaderInit(path, &mtbl.ReaderOptions{VerifyChecksums: true})
		defer r.Destroy()

		if e != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %s\n", path, e)
			os.Exit(1)
		}

		var it *mtbl.Iter

		if len(*prefix) > 0 {
			p := *prefix
			it = mtbl.IterPrefix(r, []byte(p))
		} else if len(*rev_prefix) > 0 {
			p := reverseKey(*rev_prefix)
			it = mtbl.IterPrefix(r, []byte(p))
		} else {
			it = mtbl.IterAll(r)
		}

		for {
			key_bytes, val_bytes, ok := it.Next()
			if !ok {
				break
			}

			key := string(key_bytes)
			val := []string{string(val_bytes)}

			if *zero_split {
				val = strings.SplitN(string(val_bytes), "\x00", -1)
			}

			if *rev_key {
				key = reverseKey(key)
			}

			if *key_only {
				fmt.Printf("%s\n", key)
			} else if *val_only {
				if *no_quotes {
					fmt.Printf("%s\n", val)
				} else {
					fmt.Printf("%q\n", val)
				}
			} else {
				if *no_quotes {
					fmt.Printf("%s\t%s\n", key, val)
				} else {
					fmt.Printf("%s\t%q\n", key, val)
				}
			}
		}

	}

}
