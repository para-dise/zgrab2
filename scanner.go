package zgrab2

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

var scanners map[string]*Scanner
var orderedScanners []string

// RegisterScan registers each individual scanner to be ran by the framework
func RegisterScan(name string, s Scanner) {
	//add to list and map
	if scanners[name] != nil {
		log.Fatalf("name: %s already used", name)
	}
	orderedScanners = append(orderedScanners, name)
	scanners[name] = &s
}

// PrintScanners prints all registered scanners
func PrintScanners() {
	for k, v := range scanners {
		fmt.Println(k, v)
	}
}

func startHeapProfiling() {
	go func() {
		for {
			var buf bytes.Buffer
			runtime.GC() // get up-to-date heap stats
			err := pprof.WriteHeapProfile(&buf)
			if err != nil {
				log.Println("Failed to write heap profile:", err)
				continue
			}

			// Save snapshot to disk if safe
			t := time.Now().Format("20060102-150405")
			fname := "heap-" + t + ".pprof"
			if f, err := os.Create(fname); err == nil {
				f.Write(buf.Bytes())
				f.Close()
			}

			time.Sleep(10 * time.Second)
		}
	}()
}

// RunScanner runs a single scan on a target and returns the resulting data
func RunScanner(s Scanner, mon *Monitor, target ScanTarget) (string, ScanResponse) {
	t := time.Now()
	status, res, e := s.Scan(target)
	var err *string
	if e == nil {
		mon.statusesChan <- moduleStatus{name: s.GetName(), st: statusSuccess}
		err = nil
	} else {
		mon.statusesChan <- moduleStatus{name: s.GetName(), st: statusFailure}
		errString := e.Error()
		err = &errString
	}
	resp := ScanResponse{Result: res, Protocol: s.Protocol(), Error: err, Timestamp: t.Format(time.RFC3339), Status: status}
	return s.GetName(), resp
}

func init() {
	//startHeapProfiling()
	scanners = make(map[string]*Scanner)
}
