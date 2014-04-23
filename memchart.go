package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"time"
)

//piddata represents Data read from /proc/$PID
type piddata struct {
	cmdline string
	Name    string `json:"name"`
	RSS     int    `json:"rss"`
	PSS     int    `json:"pss"`
	USS     int    `json:"uss"`
}

//isKernelProc checks whether the given piddata is of a kernel process
func isKernelProc(pd *piddata) bool {
	return len(pd.cmdline) == 0
}

//snapshotPid reads raw data from the /proc files corresponding to pid
func snapshotPid(pid string) (*piddata, error) {
	pidpath := "/proc/" + pid + "/"
	cmdline, err := ioutil.ReadFile(pidpath + "cmdline")
	if err != nil {
		log.Println("No process with pid", pid)
		return nil, err
	}
	smaps, err := ioutil.ReadFile(pidpath + "smaps")
	if err != nil {
		return nil, err
	}
	stat, err := ioutil.ReadFile(pidpath + "stat")
	if err != nil {
		return nil, err
	}
	i, j := strings.Index(string(stat), "("), strings.Index(string(stat), ")")
	name := string(stat[i+1 : j])

	pd := &piddata{cmdline: string(cmdline), Name: name}
	pd.RSS, pd.PSS, pd.USS = memsizes(string(smaps))

	return pd, nil
}

//The representation of all mappings belonging to a PID keyed on start address
type pmaps map[string]map[string]int

var allpids map[string]*piddata

// getsmaps extracts the individual map entries from a smaps-formatted string
func getsmaps(smaps string) *pmaps {
	pm := make(pmaps)

	lines := strings.Split(smaps, "\n")
	start := ""

	for _, line := range lines {
		if len(line) == 0 {
			break
		}
		f := strings.Fields(line)
		if "kB" != (f[len(f)-1]) {
			start = strings.Split(f[0], "-")[0]
			pm[start] = make(map[string]int)
		} else {
			n := strings.ToLower(strings.TrimRight(f[0], ":"))
			pm[start][n], _ = strconv.Atoi(f[1])
		}
	}

	return &pm
}

func memsizes(smaps string) (int, int, int) {
	pm := getsmaps(smaps)
	rss, pss, uss := 0, 0, 0
	for _, m := range *pm {
		rss += m["rss"]
		pss += m["pss"]
		uss += m["private_clean"] + m["private_dirty"]
	}
	return rss, pss, uss
}

//A snapshot containing the timestamp and all PIDs' data
type snap struct {
	Time string              `json:"time"`
	Pids map[string]*piddata `json:"pids"`
}

//Creates a JSON string reflecting the current snapshot
//FIXME: need syncronization between constructing and printing the map
func makeJSON() string {
	timestamp := time.Now().Format("03:04:05")
	j, err := json.MarshalIndent(snap{timestamp, allpids}, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(j)
}

//Returns a tabular format of the measurements suitable for CSV output
func makeCSV() [][]string {
	d := make([][]string, len(allpids))
	c := 0
	for pid, entry := range allpids {
		d[c] = make([]string, 5)
		d[c][0] = pid
		d[c][1] = entry.Name
		d[c][2] = strconv.Itoa(entry.RSS)
		d[c][3] = strconv.Itoa(entry.USS)
		d[c][4] = strconv.Itoa(entry.PSS)
		c++
	}
	return d
}

const (
	DumpCSV  = 0
	DumpJSON = 1
)

func dump(typ int) {
	if typ == DumpCSV {
		printCSV(os.Stdout)
	} else {
		j := makeJSON()
		println(string(j))
	}
}

func work(pids []string) {
	if len(pids) == 0 {
		pids = snapshotAll()
	}
	snapshotPids(pids)
	if verbose {
		dump(DumpCSV)
	}
}

func snapshotPids(pids []string) {
	for _, pid := range pids {
		pd, err := snapshotPid(pid)
		if err == nil {
			if !isKernelProc(pd) {
				allpids[pid] = pd
			}
		} else {
			if os.IsNotExist(err) {
				delete(allpids, pid)
			}
		}
	}
}

func snapshotAll() []string {
	os.Chdir("/proc")

	f, err := os.Open("/proc")
	if err != nil {
		log.Fatal(err)
	}

	entries, err := f.Readdir(0)
	if err != nil {
		log.Fatal(err)
	}

	pids := []string{}
	for _, e := range entries {
		name := e.Name()
		if name[0] >= '0' && name[0] <= '9' {
			pids = append(pids, name)
		}
	}

	return pids
}

//The main URL handler
func viewHandle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		return
	}
	j := makeJSON()
	fmt.Fprintln(w, j)
}

//Return CSV of latest snapshot
func printCSV(w io.Writer) {
	csvw := csv.NewWriter(w)
	fmt.Fprintln(w, "pid,name,rss,uss,pss")
	csvw.WriteAll(makeCSV())
}

//Return CSV of latest snapshot
func csvHandle(w http.ResponseWriter, r *http.Request) {
	printCSV(w)
}

var verbose bool
var port string
var seconds int
var exit bool

//Serve the latest snapshot JSON data
func webserver() {
	http.HandleFunc("/", viewHandle)
	http.HandleFunc("/csv", csvHandle)

	log.Println("Listening at http://localhost:" + port)

	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func parseOptions() {
	flag.StringVar(&port, "p", "7777", "Port to listen on")
	flag.IntVar(&seconds, "s", 120, "Seconds between measurements")
	flag.BoolVar(&verbose, "v", false, "Verbose mode")
	flag.BoolVar(&exit, "e", false, "Dump a single snapshot then exit immediately")
	flag.Parse()
}

//Application entry point
func main() {
	parseOptions()
	log.SetFlags(0)
	allpids = make(map[string]*piddata)

	if exit {
		verbose = true
		work(nil)
		return
	}

	go webserver()

	pids := flag.Args()
	for {
		work(pids)
		time.Sleep(time.Duration(seconds) * time.Second)
	}
}
