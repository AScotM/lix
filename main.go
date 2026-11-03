package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Proc      string
	Sys       string
	Interval  time.Duration
	Count     int
	Format    string
	Top       int
	PID       int
	Detail    bool
	Sections  string
	Threshold float64
	Output    string
}
type CPU struct {
	Name          string  `json:"name"`
	User          uint64  `json:"user"`
	Nice          uint64  `json:"nice"`
	System        uint64  `json:"system"`
	Idle          uint64  `json:"idle"`
	IOWait        uint64  `json:"iowait"`
	IRQ           uint64  `json:"irq"`
	SoftIRQ       uint64  `json:"softirq"`
	Steal         uint64  `json:"steal"`
	Guest         uint64  `json:"guest"`
	GuestNice     uint64  `json:"guest_nice"`
	Usage         float64 `json:"usage_percent"`
	IOWaitPercent float64 `json:"iowait_percent"`
	StealPercent  float64 `json:"steal_percent"`
}
type CPUInfo struct {
	Cores          []CPU  `json:"cores"`
	Context        uint64 `json:"context_switches"`
	Forks          uint64 `json:"forks"`
	Running        uint64 `json:"running"`
	Blocked        uint64 `json:"blocked"`
	Boot           uint64 `json:"boot_unix"`
	Interrupts     uint64 `json:"interrupts"`
	SoftInterrupts uint64 `json:"soft_interrupts"`
}
type Load struct {
	One     float64 `json:"one"`
	Five    float64 `json:"five"`
	Fifteen float64 `json:"fifteen"`
	Running uint64  `json:"running"`
	Total   uint64  `json:"total"`
	LastPID uint64  `json:"last_pid"`
}
type Memory struct {
	Values      map[string]uint64 `json:"bytes"`
	Used        uint64            `json:"used"`
	UsedPercent float64           `json:"used_percent"`
	SwapUsed    uint64            `json:"swap_used"`
	SwapPercent float64           `json:"swap_percent"`
}
type PressureLine struct {
	Avg10  float64 `json:"avg10"`
	Avg60  float64 `json:"avg60"`
	Avg300 float64 `json:"avg300"`
	Total  uint64  `json:"total_microseconds"`
}
type Pressure struct {
	Some  *PressureLine `json:"some,omitempty"`
	Full  *PressureLine `json:"full,omitempty"`
	Error string        `json:"error,omitempty"`
}
type Process struct {
	PID          int      `json:"pid"`
	PPID         int      `json:"ppid"`
	Name         string   `json:"name"`
	State        string   `json:"state"`
	UID          int      `json:"uid"`
	Threads      int      `json:"threads"`
	RSS          uint64   `json:"rss_bytes"`
	VMSize       uint64   `json:"virtual_bytes"`
	ReadBytes    uint64   `json:"read_bytes"`
	WriteBytes   uint64   `json:"write_bytes"`
	FDs          int      `json:"fd_count"`
	Cmdline      string   `json:"cmdline,omitempty"`
	CPUPercent   float64  `json:"cpu_percent"`
	CPUJiffies   uint64   `json:"cpu_jiffies"`
	StartJiffies uint64   `json:"start_jiffies"`
	Errors       []string `json:"errors,omitempty"`
}
type ProcessSummary struct {
	Total   int            `json:"total"`
	States  map[string]int `json:"states"`
	Zombies int            `json:"zombies"`
	Threads int            `json:"threads"`
	RSS     uint64         `json:"rss_bytes"`
	Skipped int            `json:"skipped"`
}
type Network struct {
	Interfaces map[string]NetInterface      `json:"interfaces"`
	TCP        map[string]int               `json:"tcp_states"`
	UDP        int                          `json:"udp_sockets"`
	Unix       int                          `json:"unix_sockets"`
	SNMP       map[string]map[string]uint64 `json:"snmp"`
	Netstat    map[string]map[string]uint64 `json:"netstat"`
}
type NetInterface struct {
	RXBytes   uint64  `json:"rx_bytes"`
	RXPackets uint64  `json:"rx_packets"`
	RXErrors  uint64  `json:"rx_errors"`
	RXDrops   uint64  `json:"rx_drops"`
	TXBytes   uint64  `json:"tx_bytes"`
	TXPackets uint64  `json:"tx_packets"`
	TXErrors  uint64  `json:"tx_errors"`
	TXDrops   uint64  `json:"tx_drops"`
	RXRate    float64 `json:"rx_bytes_per_second"`
	TXRate    float64 `json:"tx_bytes_per_second"`
}
type Disk struct {
	Name                   string  `json:"name"`
	Reads                  uint64  `json:"reads"`
	ReadSectors            uint64  `json:"read_sectors"`
	Writes                 uint64  `json:"writes"`
	WriteSectors           uint64  `json:"write_sectors"`
	InFlight               uint64  `json:"in_flight"`
	IOMilliseconds         uint64  `json:"io_milliseconds"`
	WeightedIOMilliseconds uint64  `json:"weighted_io_milliseconds"`
	ReadBPS                float64 `json:"read_bytes_per_second"`
	WriteBPS               float64 `json:"write_bytes_per_second"`
	BusyPercent            float64 `json:"busy_percent"`
}
type Mount struct {
	Device  string `json:"device"`
	Target  string `json:"target"`
	FSType  string `json:"fs_type"`
	Options string `json:"options"`
}
type Cgroup struct {
	Path     string            `json:"path"`
	Version  int               `json:"version"`
	CPU      map[string]string `json:"cpu,omitempty"`
	Memory   map[string]string `json:"memory,omitempty"`
	IO       map[string]string `json:"io,omitempty"`
	PIDs     map[string]string `json:"pids,omitempty"`
	Pressure map[string]string `json:"pressure,omitempty"`
}
type Alert struct {
	Severity  string  `json:"severity"`
	Metric    string  `json:"metric"`
	Value     float64 `json:"value"`
	Threshold float64 `json:"threshold"`
	Message   string  `json:"message"`
}
type Snapshot struct {
	Time            time.Time           `json:"timestamp"`
	Hostname        string              `json:"hostname"`
	Kernel          string              `json:"kernel"`
	Uptime          float64             `json:"uptime_seconds"`
	CPUs            int                 `json:"logical_cpus"`
	Load            *Load               `json:"load,omitempty"`
	CPU             *CPUInfo            `json:"cpu,omitempty"`
	Memory          *Memory             `json:"memory,omitempty"`
	Pressure        map[string]Pressure `json:"pressure,omitempty"`
	Processes       *ProcessSummary     `json:"process_summary,omitempty"`
	TopProcesses    []Process           `json:"top_processes,omitempty"`
	SelectedProcess *Process            `json:"selected_process,omitempty"`
	Network         *Network            `json:"network,omitempty"`
	Disks           []Disk              `json:"disks,omitempty"`
	Mounts          []Mount             `json:"mounts,omitempty"`
	Cgroup          *Cgroup             `json:"cgroup,omitempty"`
	VMStat          map[string]uint64   `json:"vmstat,omitempty"`
	Filesystems     map[string]uint64   `json:"file_handles,omitempty"`
	Alerts          []Alert             `json:"alerts,omitempty"`
	Errors          []string            `json:"errors,omitempty"`
}
type Baseline struct {
	At        time.Time
	CPU       map[string]CPU
	Processes map[int]Process
	Network   map[string]NetInterface
	Disks     map[string]Disk
}
type Collector struct {
	cfg      Config
	base     *Baseline
	sections map[string]bool
}

func main() {
	cfg := Config{}
	flag.StringVar(&cfg.Proc, "proc", "/proc", "procfs root")
	flag.StringVar(&cfg.Sys, "sys", "/sys", "sysfs root")
	flag.DurationVar(&cfg.Interval, "interval", time.Second, "sampling interval")
	flag.IntVar(&cfg.Count, "count", 1, "samples, zero means continuous")
	flag.StringVar(&cfg.Format, "format", "text", "text, json, jsonl")
	flag.IntVar(&cfg.Top, "top", 10, "maximum processes to display")
	flag.IntVar(&cfg.PID, "pid", 0, "inspect a specific process")
	flag.BoolVar(&cfg.Detail, "detail", false, "include command lines, descriptors, and mounts")
	flag.StringVar(&cfg.Sections, "sections", "all", "comma-separated: cpu,memory,pressure,process,network,disk,mount,cgroup,vmstat,files")
	flag.Float64Var(&cfg.Threshold, "threshold", 80, "warning threshold percent")
	flag.StringVar(&cfg.Output, "output", "-", "output file or - for stdout")
	flag.Parse()
	if err := validate(cfg); err != nil {
		fatal(err)
	}
	out := io.Writer(os.Stdout)
	if cfg.Output != "-" {
		f, err := os.Create(cfg.Output)
		if err != nil {
			fatal(err)
		}
		defer f.Close()
		out = f
	}
	collector := Collector{cfg: cfg, sections: sectionSet(cfg.Sections)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for i := 0; cfg.Count == 0 || i < cfg.Count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(cfg.Interval):
			}
		}
		snap := collector.Collect()
		if err := render(out, snap, cfg); err != nil {
			fatal(err)
		}
	}
}
func validate(c Config) error {
	if c.Interval <= 0 {
		return errors.New("interval must be positive")
	}
	if c.Count < 0 || c.Top < 0 || c.PID < 0 {
		return errors.New("count, top and pid must not be negative")
	}
	if c.Threshold < 0 || c.Threshold > 100 {
		return errors.New("threshold must be 0..100")
	}
	if c.Format != "text" && c.Format != "json" && c.Format != "jsonl" {
		return errors.New("invalid format")
	}
	if c.Count != 1 && c.Format == "json" {
		return errors.New("use jsonl for multiple samples")
	}
	return nil
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "lix:", err); os.Exit(1) }
func sectionSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, x := range strings.Split(s, ",") {
		m[strings.ToLower(strings.TrimSpace(x))] = true
	}
	return m
}
func (c *Collector) enabled(s string) bool { return c.sections["all"] || c.sections[s] }
func readFile(path string) (string, error) { b, e := os.ReadFile(path); return string(b), e }
func readTrim(path string) string          { s, _ := readFile(path); return strings.TrimSpace(s) }
func parseU(s string) uint64               { v, _ := strconv.ParseUint(s, 10, 64); return v }
func parseI(s string) int                  { v, _ := strconv.Atoi(s); return v }
func parseF(s string) float64              { v, _ := strconv.ParseFloat(s, 64); return v }
func percentage(n, d float64) float64 {
	if d <= 0 {
		return 0
	}
	return n / d * 100
}
func delta(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}
func rate(a, b uint64, seconds float64) float64 {
	if seconds <= 0 {
		return 0
	}
	return float64(delta(a, b)) / seconds
}
func splitLines(s string) []string { return strings.Split(strings.TrimSpace(s), "\n") }
func (c *Collector) path(parts ...string) string {
	return filepath.Join(append([]string{c.cfg.Proc}, parts...)...)
}
func (c *Collector) sys(parts ...string) string {
	return filepath.Join(append([]string{c.cfg.Sys}, parts...)...)
}
func (c *Collector) Collect() Snapshot {
	s := Snapshot{Time: time.Now(), CPUs: runtime.NumCPU()}
	s.Hostname, _ = os.Hostname()
	s.Kernel = readTrim(c.path("sys", "kernel", "osrelease"))
	if v, e := readFile(c.path("uptime")); e == nil {
		f := strings.Fields(v)
		if len(f) > 0 {
			s.Uptime = parseF(f[0])
		}
	} else {
		s.Errors = append(s.Errors, "uptime: "+e.Error())
	}
	old := c.base
	elapsed := 0.0
	if old != nil {
		elapsed = s.Time.Sub(old.At).Seconds()
	}
	next := &Baseline{At: s.Time, CPU: map[string]CPU{}, Processes: map[int]Process{}, Network: map[string]NetInterface{}, Disks: map[string]Disk{}}
	if c.enabled("cpu") {
		if v, e := c.readCPU(); e == nil {
			s.CPU = &v
			for i := range v.Cores {
				core := &v.Cores[i]
				if old != nil {
					if p, ok := old.CPU[core.Name]; ok {
						dt := delta(cpuTotal(*core), cpuTotal(p))
						busy := delta(cpuBusy(*core), cpuBusy(p))
						core.Usage = percentage(float64(busy), float64(dt))
						core.IOWaitPercent = percentage(float64(delta(core.IOWait, p.IOWait)), float64(dt))
						core.StealPercent = percentage(float64(delta(core.Steal, p.Steal)), float64(dt))
					}
				}
				next.CPU[core.Name] = *core
			}
			if len(v.Cores) > 0 && old != nil && v.Cores[0].Usage >= c.cfg.Threshold {
				s.alert("CPU", v.Cores[0].Usage, c.cfg.Threshold, "aggregate CPU utilization")
			}
		} else {
			s.Errors = append(s.Errors, "cpu: "+e.Error())
		}
		if v, e := c.readLoad(); e == nil {
			s.Load = &v
		} else {
			s.Errors = append(s.Errors, "load: "+e.Error())
		}
	}
	if c.enabled("memory") {
		if v, e := c.readMemory(); e == nil {
			s.Memory = &v
			if v.UsedPercent >= c.cfg.Threshold {
				s.alert("memory", v.UsedPercent, c.cfg.Threshold, "memory usage")
			}
			if v.SwapPercent >= c.cfg.Threshold && v.Values["SwapTotal"] > 0 {
				s.alert("swap", v.SwapPercent, c.cfg.Threshold, "swap usage")
			}
		} else {
			s.Errors = append(s.Errors, "memory: "+e.Error())
		}
	}
	if c.enabled("pressure") {
		s.Pressure = c.readPressures()
		for name, p := range s.Pressure {
			if p.Some != nil && p.Some.Avg10 >= c.cfg.Threshold {
				s.alert("psi."+name, p.Some.Avg10, c.cfg.Threshold, "pressure some avg10")
			}
		}
	}
	if c.enabled("process") {
		list, summary, e := c.readProcesses()
		if e != nil {
			s.Errors = append(s.Errors, "process: "+e.Error())
		} else {
			s.Processes = &summary
			for i := range list {
				p := &list[i]
				if old != nil {
					if prev, ok := old.Processes[p.PID]; ok && prev.StartJiffies == p.StartJiffies {
						hz := c.clockTicks()
						p.CPUPercent = percentage(float64(delta(p.CPUJiffies, prev.CPUJiffies))/hz, elapsed)
					}
				}
				next.Processes[p.PID] = *p
			}
			sort.Slice(list, func(i, j int) bool {
				if list[i].CPUPercent != list[j].CPUPercent {
					return list[i].CPUPercent > list[j].CPUPercent
				}
				return list[i].RSS > list[j].RSS
			})
			n := c.cfg.Top
			if n > len(list) {
				n = len(list)
			}
			s.TopProcesses = list[:n]
			if c.cfg.PID > 0 {
				for i := range list {
					if list[i].PID == c.cfg.PID {
						p := list[i]
						s.SelectedProcess = &p
						break
					}
				}
				if s.SelectedProcess == nil {
					s.Errors = append(s.Errors, fmt.Sprintf("pid %d not found or inaccessible", c.cfg.PID))
				}
			}
			if summary.Zombies > 0 {
				s.Alerts = append(s.Alerts, Alert{Severity: "info", Metric: "zombies", Value: float64(summary.Zombies), Message: "zombie processes detected"})
			}
		}
	}
	if c.enabled("network") {
		v, e := c.readNetwork()
		if e != nil {
			s.Errors = append(s.Errors, "network: "+e.Error())
		} else {
			for k, n := range v.Interfaces {
				if old != nil {
					if p, ok := old.Network[k]; ok {
						n.RXRate = rate(n.RXBytes, p.RXBytes, elapsed)
						n.TXRate = rate(n.TXBytes, p.TXBytes, elapsed)
					}
				}
				v.Interfaces[k] = n
				next.Network[k] = n
			}
			s.Network = &v
		}
	}
	if c.enabled("disk") {
		v, e := c.readDisks()
		if e != nil {
			s.Errors = append(s.Errors, "disk: "+e.Error())
		} else {
			for i := range v {
				d := &v[i]
				if old != nil {
					if p, ok := old.Disks[d.Name]; ok {
						d.ReadBPS = rate(d.ReadSectors*512, p.ReadSectors*512, elapsed)
						d.WriteBPS = rate(d.WriteSectors*512, p.WriteSectors*512, elapsed)
						d.BusyPercent = percentage(float64(delta(d.IOMilliseconds, p.IOMilliseconds))/1000, elapsed)
					}
				}
				next.Disks[d.Name] = *d
			}
			s.Disks = v
		}
	}
	if c.enabled("mount") || c.cfg.Detail {
		s.Mounts = c.readMounts()
	}
	if c.enabled("cgroup") {
		s.Cgroup = c.readCgroup()
	}
	if c.enabled("vmstat") {
		s.VMStat = c.readKV(c.path("vmstat"))
	}
	if c.enabled("files") {
		s.Filesystems = c.readFileStats()
	}
	c.base = next
	return s
}
func (s *Snapshot) alert(metric string, value, threshold float64, message string) {
	s.Alerts = append(s.Alerts, Alert{Severity: "warning", Metric: metric, Value: value, Threshold: threshold, Message: message})
}
func cpuTotal(c CPU) uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}
func cpuBusy(c CPU) uint64 { return c.User + c.Nice + c.System + c.IRQ + c.SoftIRQ + c.Steal }
func (c *Collector) readCPU() (CPUInfo, error) {
	v, e := readFile(c.path("stat"))
	if e != nil {
		return CPUInfo{}, e
	}
	result := CPUInfo{}
	for _, line := range splitLines(v) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if f[0] == "cpu" || strings.HasPrefix(f[0], "cpu") && len(f[0]) > 3 && f[0][3] >= '0' && f[0][3] <= '9' {
			if len(f) < 5 {
				return CPUInfo{}, fmt.Errorf("truncated cpu record: %s", line)
			}
			vals := make([]uint64, 10)
			for i := 1; i < len(f) && i <= 10; i++ {
				n, e := strconv.ParseUint(f[i], 10, 64)
				if e != nil {
					return CPUInfo{}, e
				}
				vals[i-1] = n
			}
			result.Cores = append(result.Cores, CPU{Name: f[0], User: vals[0], Nice: vals[1], System: vals[2], Idle: vals[3], IOWait: vals[4], IRQ: vals[5], SoftIRQ: vals[6], Steal: vals[7], Guest: vals[8], GuestNice: vals[9]})
			continue
		}
		n := parseU(f[1])
		switch f[0] {
		case "ctxt":
			result.Context = n
		case "processes":
			result.Forks = n
		case "procs_running":
			result.Running = n
		case "procs_blocked":
			result.Blocked = n
		case "btime":
			result.Boot = n
		case "intr":
			result.Interrupts = n
		case "softirq":
			result.SoftInterrupts = n
		}
	}
	if len(result.Cores) == 0 {
		return result, errors.New("missing aggregate CPU")
	}
	return result, nil
}
func (c *Collector) readLoad() (Load, error) {
	v, e := readFile(c.path("loadavg"))
	if e != nil {
		return Load{}, e
	}
	f := strings.Fields(v)
	if len(f) < 5 {
		return Load{}, errors.New("truncated loadavg")
	}
	parts := strings.SplitN(f[3], "/", 2)
	if len(parts) != 2 {
		return Load{}, errors.New("invalid task count")
	}
	return Load{One: parseF(f[0]), Five: parseF(f[1]), Fifteen: parseF(f[2]), Running: parseU(parts[0]), Total: parseU(parts[1]), LastPID: parseU(f[4])}, nil
}
func (c *Collector) readMemory() (Memory, error) {
	v, e := readFile(c.path("meminfo"))
	if e != nil {
		return Memory{}, e
	}
	m := Memory{Values: map[string]uint64{}}
	for _, line := range splitLines(v) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, e := strconv.ParseUint(f[1], 10, 64)
		if e != nil {
			continue
		}
		if len(f) >= 3 && f[2] == "kB" {
			n *= 1024
		}
		m.Values[strings.TrimSuffix(f[0], ":")] = n
	}
	total := m.Values["MemTotal"]
	available, ok := m.Values["MemAvailable"]
	if !ok {
		available = m.Values["MemFree"] + m.Values["Buffers"] + m.Values["Cached"]
	}
	m.Used = delta(total, available)
	m.UsedPercent = percentage(float64(m.Used), float64(total))
	m.SwapUsed = delta(m.Values["SwapTotal"], m.Values["SwapFree"])
	m.SwapPercent = percentage(float64(m.SwapUsed), float64(m.Values["SwapTotal"]))
	return m, nil
}
func (c *Collector) readPressures() map[string]Pressure {
	m := map[string]Pressure{}
	for _, name := range []string{"cpu", "memory", "io"} {
		v, e := readFile(c.path("pressure", name))
		if e != nil {
			m[name] = Pressure{Error: e.Error()}
			continue
		}
		p := Pressure{}
		for _, line := range splitLines(v) {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			x := &PressureLine{}
			for _, field := range f[1:] {
				pair := strings.SplitN(field, "=", 2)
				if len(pair) != 2 {
					continue
				}
				switch pair[0] {
				case "avg10":
					x.Avg10 = parseF(pair[1])
				case "avg60":
					x.Avg60 = parseF(pair[1])
				case "avg300":
					x.Avg300 = parseF(pair[1])
				case "total":
					x.Total = parseU(pair[1])
				}
			}
			switch f[0] {
			case "some":
				p.Some = x
			case "full":
				p.Full = x
			}
		}
		m[name] = p
	}
	return m
}
func (c *Collector) clockTicks() float64 { return 100 }
func (c *Collector) readProcesses() ([]Process, ProcessSummary, error) {
	entries, e := os.ReadDir(c.path())
	if e != nil {
		return nil, ProcessSummary{}, e
	}
	summary := ProcessSummary{States: map[string]int{}}
	list := make([]Process, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, e := strconv.Atoi(entry.Name())
		if e != nil || pid <= 0 {
			continue
		}
		p, e := c.readProcess(pid)
		if e != nil {
			summary.Skipped++
			continue
		}
		summary.Total++
		summary.States[p.State]++
		summary.Threads += p.Threads
		summary.RSS += p.RSS
		if p.State == "Z" {
			summary.Zombies++
		}
		list = append(list, p)
	}
	return list, summary, nil
}
func (c *Collector) readProcess(pid int) (Process, error) {
	p := Process{PID: pid, UID: -1, FDs: -1}
	base := c.path(strconv.Itoa(pid))
	v, e := readFile(filepath.Join(base, "stat"))
	if e != nil {
		return p, e
	}
	left := strings.IndexByte(v, '(')
	right := strings.LastIndexByte(v, ')')
	if left < 0 || right <= left {
		return p, errors.New("invalid process stat")
	}
	p.Name = v[left+1 : right]
	f := strings.Fields(v[right+1:])
	if len(f) < 22 {
		return p, errors.New("truncated process stat")
	}
	p.State = f[0]
	p.PPID = parseI(f[1])
	p.CPUJiffies = parseU(f[11]) + parseU(f[12])
	p.Threads = parseI(f[17])
	p.StartJiffies = parseU(f[19])
	p.VMSize = parseU(f[20])
	p.RSS = parseU(f[21]) * uint64(os.Getpagesize())
	status, e := readFile(filepath.Join(base, "status"))
	if e == nil {
		for _, line := range splitLines(status) {
			parts := strings.Fields(line)
			if len(parts) >= 2 && parts[0] == "Uid:" {
				p.UID = parseI(parts[1])
			}
		}
	}
	if c.cfg.Detail || c.cfg.PID == pid {
		if b, e := os.ReadFile(filepath.Join(base, "cmdline")); e == nil {
			p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
		}
		if entries, e := os.ReadDir(filepath.Join(base, "fd")); e == nil {
			p.FDs = len(entries)
		} else {
			p.Errors = append(p.Errors, "fd: "+e.Error())
		}
		if v, e := readFile(filepath.Join(base, "io")); e == nil {
			for _, line := range splitLines(v) {
				f := strings.Fields(line)
				if len(f) < 2 {
					continue
				}
				switch f[0] {
				case "read_bytes:":
					p.ReadBytes = parseU(f[1])
				case "write_bytes:":
					p.WriteBytes = parseU(f[1])
				}
			}
		}
	}
	return p, nil
}
func (c *Collector) readNetwork() (Network, error) {
	v, e := readFile(c.path("net", "dev"))
	if e != nil {
		return Network{}, e
	}
	n := Network{Interfaces: map[string]NetInterface{}, TCP: map[string]int{}, SNMP: c.readProtocolMap("snmp"), Netstat: c.readProtocolMap("netstat")}
	for _, line := range splitLines(v) {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		f := strings.Fields(parts[1])
		if len(f) < 16 {
			continue
		}
		n.Interfaces[strings.TrimSpace(parts[0])] = NetInterface{RXBytes: parseU(f[0]), RXPackets: parseU(f[1]), RXErrors: parseU(f[2]), RXDrops: parseU(f[3]), TXBytes: parseU(f[8]), TXPackets: parseU(f[9]), TXErrors: parseU(f[10]), TXDrops: parseU(f[11])}
	}
	states := map[string]string{"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW_SYN_RECV"}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		v, e := readFile(c.path("net", name))
		if e != nil {
			continue
		}
		lines := splitLines(v)
		for _, line := range lines[1:] {
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			if strings.HasPrefix(name, "udp") {
				n.UDP++
				continue
			}
			state := strings.ToUpper(f[3])
			if x, ok := states[state]; ok {
				state = x
			}
			n.TCP[state]++
		}
	}
	if v, e := readFile(c.path("net", "unix")); e == nil {
		lines := splitLines(v)
		if len(lines) > 1 {
			n.Unix = len(lines) - 1
		}
	}
	return n, nil
}
func (c *Collector) readProtocolMap(name string) map[string]map[string]uint64 {
	v, e := readFile(c.path("net", name))
	if e != nil {
		return nil
	}
	lines := splitLines(v)
	result := map[string]map[string]uint64{}
	for i := 0; i+1 < len(lines); i += 2 {
		keys := strings.Fields(lines[i])
		vals := strings.Fields(lines[i+1])
		if len(keys) != len(vals) || len(keys) == 0 || keys[0] != vals[0] {
			continue
		}
		group := strings.TrimSuffix(keys[0], ":")
		result[group] = map[string]uint64{}
		for j := 1; j < len(keys); j++ {
			if n, e := strconv.ParseUint(vals[j], 10, 64); e == nil {
				result[group][keys[j]] = n
			}
		}
	}
	return result
}
func (c *Collector) readDisks() ([]Disk, error) {
	v, e := readFile(c.path("diskstats"))
	if e != nil {
		return nil, e
	}
	out := []Disk{}
	for _, line := range splitLines(v) {
		f := strings.Fields(line)
		if len(f) < 14 {
			continue
		}
		out = append(out, Disk{Name: f[2], Reads: parseU(f[3]), ReadSectors: parseU(f[5]), Writes: parseU(f[7]), WriteSectors: parseU(f[9]), InFlight: parseU(f[11]), IOMilliseconds: parseU(f[12]), WeightedIOMilliseconds: parseU(f[13])})
	}
	return out, nil
}
func unescapeMount(s string) string {
	r := strings.NewReplacer("\\040", " ", "\\011", "\t", "\\012", "\n", "\\134", "\\")
	return r.Replace(s)
}
func (c *Collector) readMounts() []Mount {
	v, e := readFile(c.path("self", "mountinfo"))
	if e != nil {
		return nil
	}
	out := []Mount{}
	for _, line := range splitLines(v) {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		a := strings.Fields(parts[0])
		b := strings.Fields(parts[1])
		if len(a) < 6 || len(b) < 3 {
			continue
		}
		out = append(out, Mount{Device: unescapeMount(b[1]), Target: unescapeMount(a[4]), FSType: b[0], Options: a[5]})
	}
	return out
}
func (c *Collector) readKV(path string) map[string]uint64 {
	v, e := readFile(path)
	if e != nil {
		return nil
	}
	m := map[string]uint64{}
	for _, line := range splitLines(v) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		if n, e := strconv.ParseUint(f[1], 10, 64); e == nil {
			m[f[0]] = n
		}
	}
	return m
}
func (c *Collector) readFileStats() map[string]uint64 {
	v, e := readFile(c.path("sys", "fs", "file-nr"))
	if e != nil {
		return nil
	}
	f := strings.Fields(v)
	if len(f) < 3 {
		return nil
	}
	return map[string]uint64{"allocated": parseU(f[0]), "unused": parseU(f[1]), "maximum": parseU(f[2])}
}
func (c *Collector) readCgroup() *Cgroup {
	v, e := readFile(c.path("self", "cgroup"))
	if e != nil {
		return nil
	}
	g := &Cgroup{}
	for _, line := range splitLines(v) {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			g.Version = 2
			g.Path = parts[2]
			break
		}
	}
	if g.Version != 2 {
		g.Version = 1
		return g
	}
	root := c.sys("fs", "cgroup")
	rel := strings.TrimPrefix(filepath.Clean(g.Path), "/")
	dir := filepath.Join(root, rel)
	if !strings.HasPrefix(dir, root+string(os.PathSeparator)) && dir != root {
		return g
	}
	g.CPU = c.readCgroupFiles(dir, []string{"cpu.stat", "cpu.max", "cpu.weight", "cpu.pressure"})
	g.Memory = c.readCgroupFiles(dir, []string{"memory.current", "memory.max", "memory.peak", "memory.swap.current", "memory.swap.max", "memory.events", "memory.stat", "memory.pressure"})
	g.IO = c.readCgroupFiles(dir, []string{"io.stat", "io.max", "io.pressure"})
	g.PIDs = c.readCgroupFiles(dir, []string{"pids.current", "pids.max", "pids.events"})
	g.Pressure = c.readCgroupFiles(dir, []string{"cpu.pressure", "memory.pressure", "io.pressure"})
	return g
}
func (c *Collector) readCgroupFiles(dir string, names []string) map[string]string {
	m := map[string]string{}
	for _, name := range names {
		if v, e := readFile(filepath.Join(dir, name)); e == nil {
			m[name] = strings.TrimSpace(v)
		}
	}
	return m
}
func human(n uint64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	x := float64(n)
	units := []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}
	i := 0
	for x >= 1024 && i < len(units)-1 {
		x /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", x, units[i])
}
func duration(s float64) string {
	if s < 0 || math.IsNaN(s) || math.IsInf(s, 0) {
		return "unknown"
	}
	d := uint64(s)
	return fmt.Sprintf("%dd %02dh %02dm %02ds", d/86400, d%86400/3600, d%3600/60, d%60)
}
func render(w io.Writer, s Snapshot, c Config) error {
	if c.Format == "json" || c.Format == "jsonl" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if c.Format == "jsonl" {
			enc.SetIndent("", "")
		}
		return enc.Encode(s)
	}
	_, e := fmt.Fprintf(w, "LIX  %s  %s  kernel=%s  uptime=%s  cpus=%d\n", s.Time.Format(time.RFC3339), s.Hostname, s.Kernel, duration(s.Uptime), s.CPUs)
	if e != nil {
		return e
	}
	if s.Load != nil {
		fmt.Fprintf(w, "LOAD  1m=%.2f  5m=%.2f  15m=%.2f  tasks=%d/%d\n", s.Load.One, s.Load.Five, s.Load.Fifteen, s.Load.Running, s.Load.Total)
	}
	if s.CPU != nil {
		fmt.Fprintln(w, "CPU")
		for i, v := range s.CPU.Cores {
			if i > 0 && i > 64 && !c.Detail {
				fmt.Fprintln(w, "  additional cores omitted (use -detail)")
				break
			}
			fmt.Fprintf(w, "  %-8s usage=%6.2f%% iowait=%6.2f%% steal=%6.2f%% ticks=%d\n", v.Name, v.Usage, v.IOWaitPercent, v.StealPercent, cpuTotal(v))
		}
		fmt.Fprintf(w, "  context=%d forks=%d running=%d blocked=%d interrupts=%d\n", s.CPU.Context, s.CPU.Forks, s.CPU.Running, s.CPU.Blocked, s.CPU.Interrupts)
	}
	if s.Memory != nil {
		m := s.Memory
		fmt.Fprintf(w, "MEMORY  used=%s (%.2f%%) total=%s available=%s swap=%s/%s (%.2f%%)\n", human(m.Used), m.UsedPercent, human(m.Values["MemTotal"]), human(m.Values["MemAvailable"]), human(m.SwapUsed), human(m.Values["SwapTotal"]), m.SwapPercent)
		if c.Detail {
			keys := sortedKeys(m.Values)
			for _, k := range keys {
				fmt.Fprintf(w, "  %-24s %s\n", k, human(m.Values[k]))
			}
		}
	}
	if len(s.Pressure) > 0 {
		fmt.Fprintln(w, "PRESSURE")
		for _, name := range []string{"cpu", "memory", "io"} {
			p := s.Pressure[name]
			if p.Error != "" {
				fmt.Fprintf(w, "  %-8s unavailable: %s\n", name, p.Error)
				continue
			}
			if p.Some != nil {
				fmt.Fprintf(w, "  %-8s some avg10=%6.2f avg60=%6.2f avg300=%6.2f total=%d\n", name, p.Some.Avg10, p.Some.Avg60, p.Some.Avg300, p.Some.Total)
			}
			if p.Full != nil {
				fmt.Fprintf(w, "           full avg10=%6.2f avg60=%6.2f avg300=%6.2f total=%d\n", p.Full.Avg10, p.Full.Avg60, p.Full.Avg300, p.Full.Total)
			}
		}
	}
	if s.Processes != nil {
		p := s.Processes
		fmt.Fprintf(w, "PROCESSES  total=%d zombies=%d threads=%d skipped=%d\n", p.Total, p.Zombies, p.Threads, p.Skipped)
		for _, k := range sortedKeys(p.States) {
			fmt.Fprintf(w, "  state %-4s %d\n", k, p.States[k])
		}
		for _, p := range s.TopProcesses {
			fmt.Fprintf(w, "  pid=%-7d ppid=%-7d state=%-2s cpu=%7.2f%% rss=%-12s threads=%-4d %s\n", p.PID, p.PPID, p.State, p.CPUPercent, human(p.RSS), p.Threads, p.Name)
		}
		if s.SelectedProcess != nil {
			b, _ := json.MarshalIndent(s.SelectedProcess, "  ", "  ")
			fmt.Fprintf(w, "SELECTED PROCESS\n  %s\n", b)
		}
	}
	if s.Network != nil {
		fmt.Fprintln(w, "NETWORK")
		for _, name := range sortedKeys(s.Network.Interfaces) {
			v := s.Network.Interfaces[name]
			fmt.Fprintf(w, "  %-14s rx=%-12s tx=%-12s rx/s=%-12s tx/s=%-12s errors=%d/%d drops=%d/%d\n", name, human(v.RXBytes), human(v.TXBytes), human(uint64(v.RXRate)), human(uint64(v.TXRate)), v.RXErrors, v.TXErrors, v.RXDrops, v.TXDrops)
		}
		fmt.Fprintf(w, "  TCP=%v UDP=%d UNIX=%d\n", s.Network.TCP, s.Network.UDP, s.Network.Unix)
	}
	if s.Disks != nil {
		fmt.Fprintln(w, "DISKS")
		for _, d := range s.Disks {
			fmt.Fprintf(w, "  %-12s reads=%-10d writes=%-10d read/s=%-12s write/s=%-12s busy=%6.2f%%\n", d.Name, d.Reads, d.Writes, human(uint64(d.ReadBPS)), human(uint64(d.WriteBPS)), d.BusyPercent)
		}
	}
	if s.Cgroup != nil {
		fmt.Fprintf(w, "CGROUP  version=%d path=%s\n", s.Cgroup.Version, s.Cgroup.Path)
		if c.Detail {
			for _, m := range []map[string]string{s.Cgroup.CPU, s.Cgroup.Memory, s.Cgroup.IO, s.Cgroup.PIDs} {
				for _, k := range sortedKeys(m) {
					fmt.Fprintf(w, "  %s: %s\n", k, strings.ReplaceAll(m[k], "\n", "; "))
				}
			}
		}
	}
	if s.Mounts != nil {
		fmt.Fprintf(w, "MOUNTS  count=%d\n", len(s.Mounts))
		if c.Detail {
			for _, m := range s.Mounts {
				fmt.Fprintf(w, "  %-10s %-30s %s\n", m.FSType, m.Target, m.Device)
			}
		}
	}
	if s.VMStat != nil {
		fmt.Fprintf(w, "VMSTAT  keys=%d pgfault=%d pgmajfault=%d pswpin=%d pswpout=%d\n", len(s.VMStat), s.VMStat["pgfault"], s.VMStat["pgmajfault"], s.VMStat["pswpin"], s.VMStat["pswpout"])
	}
	if s.Filesystems != nil {
		fmt.Fprintf(w, "FILE HANDLES  allocated=%d max=%d\n", s.Filesystems["allocated"], s.Filesystems["maximum"])
	}
	for _, a := range s.Alerts {
		fmt.Fprintf(w, "ALERT [%s] %s: %s (%.2f)\n", a.Severity, a.Metric, a.Message, a.Value)
	}
	for _, msg := range s.Errors {
		fmt.Fprintf(w, "ERROR %s\n", msg)
	}
	fmt.Fprintln(w)
	return nil
}
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
