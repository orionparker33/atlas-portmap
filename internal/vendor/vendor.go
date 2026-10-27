// Package vendor maps MAC addresses to IEEE-registered organisations and sysObjectIDs to IANA
// Private Enterprise Numbers. The data is embedded; regenerate it with tools/gendata.
package vendor

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/orionparker33/atlas-portmap/internal/mib"
)

//go:embed data/oui.tsv.gz
var ouiData []byte

//go:embed data/pen.tsv.gz
var penData []byte

// DB is the loaded registry data.
type DB struct {
	oui map[string]string // upper-case hex prefix (6, 7 or 9 digits) -> organisation
	pen map[int]string
}

var (
	once    sync.Once
	defDB   *DB
	loadErr error
)

// Default returns the embedded database, decompressed once.
func Default() (*DB, error) {
	once.Do(func() { defDB, loadErr = load(ouiData, penData) })
	return defDB, loadErr
}

func load(ouiGz, penGz []byte) (*DB, error) {
	d := &DB{oui: make(map[string]string, 60000), pen: make(map[int]string, 70000)}
	if err := readTSV(ouiGz, func(k, v string) { d.oui[strings.ToUpper(k)] = v }); err != nil {
		return nil, fmt.Errorf("oui data: %w", err)
	}
	if err := readTSV(penGz, func(k, v string) {
		if n, err := strconv.Atoi(k); err == nil {
			d.pen[n] = v
		}
	}); err != nil {
		return nil, fmt.Errorf("pen data: %w", err)
	}
	return d, nil
}

func readTSV(gz []byte, add func(k, v string)) error {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return err
	}
	defer zr.Close()
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "\t"); ok && k != "" {
			add(k, v)
		}
	}
	return sc.Err()
}

// Locally is reported for locally administered addresses, which no registry owns.
const Locally = "(locally administered)"

// MAC returns the registered organisation for mac: the longest IEEE block match (36-bit MA-S
// and IAB, 28-bit MA-M, 24-bit MA-L). Locally administered addresses (randomised client MACs,
// VMs, containers) return Locally.
func (d *DB) MAC(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}
	if mac[0]&0x02 != 0 {
		return Locally
	}
	h := strings.ToUpper(hex.EncodeToString(mac))
	for _, n := range []int{9, 7, 6} {
		if len(h) >= n {
			if v, ok := d.oui[h[:n]]; ok {
				return v
			}
		}
	}
	return ""
}

// Enterprise maps a sysObjectID (1.3.6.1.4.1.<n>.…) to its Private Enterprise Number and
// registered organisation.
func (d *DB) Enterprise(sysObjectID string) (int, string) {
	n := mib.Enterprise(sysObjectID)
	if n < 0 {
		return -1, ""
	}
	return n, d.pen[n]
}

// Counts reports how many prefixes and enterprises are loaded.
func (d *DB) Counts() (oui, pen int) { return len(d.oui), len(d.pen) }
