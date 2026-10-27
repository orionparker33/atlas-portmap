// Command gendata regenerates internal/vendordb/data from the public registries: the IEEE MAC
// address blocks (MA-L, MA-M, MA-S and the legacy IAB) and IANA's Private Enterprise Numbers.
//
//	go run ./tools/gendata -out internal/vendordb/data
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ouiSources = []struct {
	url    string
	digits int
}{
	{"https://standards-oui.ieee.org/oui/oui.csv", 6},     // MA-L, 24-bit
	{"https://standards-oui.ieee.org/oui28/mam.csv", 7},   // MA-M, 28-bit
	{"https://standards-oui.ieee.org/oui36/oui36.csv", 9}, // MA-S, 36-bit
	{"https://standards-oui.ieee.org/iab/iab.csv", 9},     // IAB, 36-bit (legacy)
}

const penURL = "https://www.iana.org/assignments/enterprise-numbers.txt"

var hexPrefix = regexp.MustCompile(`^[0-9A-F]+$`)

func main() {
	out := flag.String("out", "internal/vendordb/data", "output directory")
	timeout := flag.Duration("timeout", 2*time.Minute, "per-download timeout")
	flag.Parse()
	if err := run(*out, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "gendata:", err)
		os.Exit(1)
	}
}

func run(dir string, timeout time.Duration) error {
	var sources strings.Builder
	fmt.Fprintf(&sources, "Generated %s by tools/gendata.\n\n", time.Now().UTC().Format(time.RFC3339))

	oui := map[string]string{}
	for _, s := range ouiSources {
		body, err := fetch(s.url, timeout)
		if err != nil {
			return err
		}
		n, err := parseIEEE(body, s.digits, oui)
		if err != nil {
			return fmt.Errorf("%s: %w", s.url, err)
		}
		fmt.Fprintf(&sources, "%s  %d entries  sha256 %s\n", s.url, n, sum(body))
	}
	body, err := fetch(penURL, timeout)
	if err != nil {
		return err
	}
	pen := parsePEN(body)
	if len(pen) < 1000 {
		return fmt.Errorf("%s: only %d entries parsed; format changed?", penURL, len(pen))
	}
	fmt.Fprintf(&sources, "%s  %d entries  sha256 %s\n", penURL, len(pen), sum(body))

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	ouiKeys := make([]string, 0, len(oui))
	for k := range oui {
		ouiKeys = append(ouiKeys, k)
	}
	sort.Strings(ouiKeys)
	if err := writeGz(filepath.Join(dir, "oui.tsv.gz"), func(w io.Writer) {
		for _, k := range ouiKeys {
			fmt.Fprintf(w, "%s\t%s\n", k, oui[k])
		}
	}); err != nil {
		return err
	}
	penKeys := make([]int, 0, len(pen))
	for k := range pen {
		penKeys = append(penKeys, k)
	}
	sort.Ints(penKeys)
	if err := writeGz(filepath.Join(dir, "pen.tsv.gz"), func(w io.Writer) {
		for _, k := range penKeys {
			fmt.Fprintf(w, "%d\t%s\n", k, pen[k])
		}
	}); err != nil {
		return err
	}
	fmt.Fprintf(&sources, "\noui.tsv.gz: %d prefixes; pen.tsv.gz: %d enterprises\n", len(oui), len(pen))
	return os.WriteFile(filepath.Join(dir, "SOURCES.txt"), []byte(sources.String()), 0o644)
}

func fetch(url string, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "atlas-portmap-gendata/1")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64<<20))
}

// parseIEEE reads an IEEE registry CSV (Registry,Assignment,Organization Name,Organization
// Address) and adds assignment -> organisation.
func parseIEEE(body []byte, digits int, into map[string]string) (int, error) {
	r := csv.NewReader(bytes.NewReader(body))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	n := 0
	for i := 0; ; i++ {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
		if i == 0 || len(rec) < 3 {
			continue
		}
		a := strings.ToUpper(strings.TrimSpace(rec[1]))
		org := clean(rec[2])
		if len(a) != digits || !hexPrefix.MatchString(a) || org == "" {
			continue
		}
		into[a] = org
		n++
	}
	if n == 0 {
		return 0, fmt.Errorf("no assignments parsed")
	}
	return n, nil
}

// parsePEN reads IANA's enterprise-numbers.txt: a decimal at column 0, the organisation on
// the next line indented by two spaces.
func parsePEN(body []byte) map[int]string {
	out := map[int]string{}
	cur := -1
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " \r")
		if line == "" {
			continue
		}
		if n, err := strconv.Atoi(line); err == nil && line[0] != ' ' {
			cur = n
			continue
		}
		if cur >= 0 && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			if org := clean(line); org != "" && org != "---none---" {
				out[cur] = org
			}
			cur = -1
		}
	}
	return out
}

func clean(s string) string {
	s = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)), " ")
	return s
}

func writeGz(path string, fill func(io.Writer)) error {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}
	bw := bufio.NewWriter(zw)
	fill(bw)
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
