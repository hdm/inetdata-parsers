package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/edmonds/golang-mtbl"
	"github.com/hdm/inetdata-parsers/utils"
	"io/ioutil"
	"os"
	"runtime"
)

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
	os.Setenv("LC_ALL", "C")

	flag.Usage = func() { usage() }

	key_only := flag.Bool("k", false, "Display key names only")
	val_only := flag.Bool("v", false, "Display values only")
	prefix := flag.String("p", "", "Only return keys with this prefix")
	rev_prefix := flag.String("r", "", "Only return keys with this prefix in reverse form")
	rev_key := flag.Bool("R", false, "Display matches with the key in reverse form")
	no_quotes := flag.Bool("n", false, "Print raw values, not quoted values")
	as_json := flag.Bool("j", false, "Print each record as a single line of JSON")
	version := flag.Bool("version", false, "Show the version and build timestamp")

	flag.Parse()

	if *version {
		utils.PrintVersion()
		os.Exit(0)
	}

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
			p := utils.ReverseKey(*rev_prefix)
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
			val := string(val_bytes)

			if *rev_key {
				key = utils.ReverseKey(key)
			}

			if *as_json {
				o := make(map[string]interface{})
				v := make([][]string, 1)

				if de := json.Unmarshal([]byte(val), &v); de != nil {
					fmt.Fprintf(os.Stderr, "Could not unmarshal %s -> %s as json: %s\n", key, val, e)
					continue
				}

				o["key"] = string(key)
				o["val"] = v

				b, e := json.Marshal(o)
				if e != nil {
					fmt.Fprintf(os.Stderr, "Could not marshal %s -> %s as json: %s\n", key, val, e)
					continue
				}
				fmt.Println(string(b))

			} else if *key_only {
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
