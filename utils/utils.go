package utils

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/edmonds/golang-mtbl"
)

var Version string = "0.0.1"

var MTBLCompressionTypes = map[string]int{
	"none":   mtbl.COMPRESSION_NONE,
	"snappy": mtbl.COMPRESSION_SNAPPY,
	"zlib":   mtbl.COMPRESSION_ZLIB,
	"lz4":    mtbl.COMPRESSION_LZ4,
	"lz4hc":  mtbl.COMPRESSION_LZ4HC,
}

var Match_IPv6 = regexp.MustCompile(`^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?$`)

var Match_IPv4 = regexp.MustCompile(`^(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))$`)

var Split_WS = regexp.MustCompile(`\s+`)

func PrintVersion() {
	fmt.Fprintf(os.Stderr, "v%s\n", Version)
}

func ReverseKey(s string) string {
	b := []byte(s)
	j := len(s) / 2
	for i := 0; i <= j; i++ {
		b[i], b[len(b)-1-i] = b[len(b)-1-i], b[i]
	}
	return string(b)
}

func ReadLines(input *os.File, out chan<- string) error {

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

		out <- string(buf)
	}

	close(out)

	if err != nil && err != io.EOF {
		return err
	}

	return nil
}
