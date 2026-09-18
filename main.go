package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type CPUStats struct {
	User       uint64
	Nice       uint64
	System     uint64
	Idle       uint64
	IOWait     uint64
	IRQ        uint64
	SoftIRQ    uint64
	Steal      uint64
	Guest      uint64
	GuestNice  uint64
	Processes  uint64
	Running    uint64
	Blocked    uint64
	Context    uint64
	BootTime   uint64
}

type MemoryStats struct {
	Total       uint64
	Free        uint64
	Available   uint64
	Buffers     uint64
	Cached      uint64
	SwapCached  uint64
	SwapTotal   uint64
	SwapFree    uint64
	Dirty       uint64
	Writeback   uint64
	Slab        uint64
	PageTables  uint64
	KernelStack uint64
}

type LoadStats struct {
	Load1        float64
	Load5        float64
	Load15       float64
	Running      uint64
	Total        uint64
	LastPID      uint64
}

type ProcessStats struct {
	Total   int
	Running int
	Sleeping int
	Stopped int
	Zombie  int
	Other   int
}

type Pressure struct {
	Some string
	Full string
}

func main() {
	fmt.Println("procview - Linux /proc system snapshot")
	fmt.Println()

	uptime, err := readUptime()
	if err != nil {
		fail(err)
	}

	load, err := readLoad()
	if err != nil {
		fail(err)
	}

	cpu, err := readCPUStats()
	if err != nil {
		fail(err)
	}

	memory, err := readMemory()
	if err != nil {
		fail(err)
	}

	processes, err := readProcesses()
	if err != nil {
		fail(err)
	}

	fmt.Println("SYSTEM")
	fmt.Printf("  Uptime:          %s\n", formatDuration(uptime))
	fmt.Printf("  Boot time:       %s\n", formatBootTime(cpu.BootTime))
	fmt.Printf("  Logical CPUs:    %d\n", runtime.NumCPU())
	fmt.Println()

	fmt.Println("LOAD")
	fmt.Printf("  1 minute:        %.2f\n", load.Load1)
	fmt.Printf("  5 minutes:       %.2f\n", load.Load5)
	fmt.Printf("  15 minutes:      %.2f\n", load.Load15)
	fmt.Printf("  Tasks:           %d/%d running\n", load.Running, load.Total)
	fmt.Printf("  Last PID:        %d\n", load.LastPID)
	fmt.Println()

	printCPU(cpu)
	printMemory(memory)
	printProcesses(processes)
	printPressure()
}

func readUptime() (time.Duration, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("invalid /proc/uptime")
	}

	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, err
	}

	return time.Duration(seconds * float64(time.Second)), nil
}

func readLoad() (LoadStats, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return LoadStats{}, err
	}

	fields := strings.Fields(string(data))
	if len(fields) < 5 {
		return LoadStats{}, fmt.Errorf("invalid /proc/loadavg")
	}

	load1, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return LoadStats{}, err
	}

	load5, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return LoadStats{}, err
	}

	load15, err := strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return LoadStats{}, err
	}

	taskParts := strings.SplitN(fields[3], "/", 2)
	if len(taskParts) != 2 {
		return LoadStats{}, fmt.Errorf("invalid task data in /proc/loadavg")
	}

	running, err := strconv.ParseUint(taskParts[0], 10, 64)
	if err != nil {
		return LoadStats{}, err
	}

	total, err := strconv.ParseUint(taskParts[1], 10, 64)
	if err != nil {
		return LoadStats{}, err
	}

	lastPID, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return LoadStats{}, err
	}

	return LoadStats{
		Load1:   load1,
		Load5:   load5,
		Load15:  load15,
		Running: running,
		Total:   total,
		LastPID: lastPID,
	}, nil
}

func readCPUStats() (CPUStats, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return CPUStats{}, err
	}
	defer file.Close()

	var stats CPUStats

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "cpu":
			values := make([]uint64, 10)

			for i := 1; i < len(fields) && i <= 10; i++ {
				value, err := strconv.ParseUint(fields[i], 10, 64)
				if err != nil {
					return CPUStats{}, err
				}
				values[i-1] = value
			}

			stats.User = values[0]
			stats.Nice = values[1]
			stats.System = values[2]
			stats.Idle = values[3]
			stats.IOWait = values[4]
			stats.IRQ = values[5]
			stats.SoftIRQ = values[6]
			stats.Steal = values[7]
			stats.Guest = values[8]
			stats.GuestNice = values[9]

		case "ctxt":
			stats.Context = parseField(fields)

		case "btime":
			stats.BootTime = parseField(fields)

		case "processes":
			stats.Processes = parseField(fields)

		case "procs_running":
			stats.Running = parseField(fields)

		case "procs_blocked":
			stats.Blocked = parseField(fields)
		}
	}

	if err := scanner.Err(); err != nil {
		return CPUStats{}, err
	}

	return stats, nil
}

func parseField(fields []string) uint64 {
	if len(fields) < 2 {
		return 0
	}

	value, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0
	}

	return value
}

func readMemory() (MemoryStats, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return MemoryStats{}, err
	}
	defer file.Close()

	values := make(map[string]uint64)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")

		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		values[key] = value * 1024
	}

	if err := scanner.Err(); err != nil {
		return MemoryStats{}, err
	}

	return MemoryStats{
		Total:       values["MemTotal"],
		Free:        values["MemFree"],
		Available:   values["MemAvailable"],
		Buffers:     values["Buffers"],
		Cached:      values["Cached"],
		SwapCached:  values["SwapCached"],
		SwapTotal:   values["SwapTotal"],
		SwapFree:    values["SwapFree"],
		Dirty:       values["Dirty"],
		Writeback:   values["Writeback"],
		Slab:        values["Slab"],
		PageTables:  values["PageTables"],
		KernelStack: values["KernelStack"],
	}, nil
}

func readProcesses() (ProcessStats, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ProcessStats{}, err
	}

	var stats ProcessStats

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}

		state, err := readProcessState(entry.Name())
		if err != nil {
			continue
		}

		stats.Total++

		switch state {
		case "R":
			stats.Running++
		case "S", "D", "I":
			stats.Sleeping++
		case "T", "t":
			stats.Stopped++
		case "Z":
			stats.Zombie++
		default:
			stats.Other++
		}
	}

	return stats, nil
}

func readProcessState(pid string) (string, error) {
	file, err := os.Open("/proc/" + pid + "/status")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "State:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1], nil
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("state unavailable")
}

func readPressure(resource string) (Pressure, error) {
	file, err := os.Open("/proc/pressure/" + resource)
	if err != nil {
		return Pressure{}, err
	}
	defer file.Close()

	var pressure Pressure

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "some ") {
			pressure.Some = strings.TrimPrefix(line, "some ")
		}

		if strings.HasPrefix(line, "full ") {
			pressure.Full = strings.TrimPrefix(line, "full ")
		}
	}

	if err := scanner.Err(); err != nil {
		return Pressure{}, err
	}

	return pressure, nil
}

func printCPU(cpu CPUStats) {
	total := cpu.User +
		cpu.Nice +
		cpu.System +
		cpu.Idle +
		cpu.IOWait +
		cpu.IRQ +
		cpu.SoftIRQ +
		cpu.Steal

	fmt.Println("CPU COUNTERS")
	fmt.Printf("  User:            %d\n", cpu.User)
	fmt.Printf("  System:          %d\n", cpu.System)
	fmt.Printf("  Idle:            %d\n", cpu.Idle)
	fmt.Printf("  I/O wait:        %d\n", cpu.IOWait)
	fmt.Printf("  IRQ:             %d\n", cpu.IRQ)
	fmt.Printf("  Soft IRQ:        %d\n", cpu.SoftIRQ)
	fmt.Printf("  Steal:           %d\n", cpu.Steal)
	fmt.Printf("  Total ticks:     %d\n", total)
	fmt.Printf("  Context switches:%d\n", cpu.Context)
	fmt.Printf("  Forks since boot:%d\n", cpu.Processes)
	fmt.Printf("  Running:         %d\n", cpu.Running)
	fmt.Printf("  Blocked:         %d\n", cpu.Blocked)
	fmt.Println()
}

func printMemory(memory MemoryStats) {
	used := uint64(0)

	if memory.Total > memory.Available {
		used = memory.Total - memory.Available
	}

	percentage := float64(0)

	if memory.Total > 0 {
		percentage = float64(used) / float64(memory.Total) * 100
	}

	fmt.Println("MEMORY")
	fmt.Printf("  Total:           %s\n", humanBytes(memory.Total))
	fmt.Printf("  Used:            %s (%.1f%%)\n", humanBytes(used), percentage)
	fmt.Printf("  Available:       %s\n", humanBytes(memory.Available))
	fmt.Printf("  Free:            %s\n", humanBytes(memory.Free))
	fmt.Printf("  Buffers:         %s\n", humanBytes(memory.Buffers))
	fmt.Printf("  Cache:           %s\n", humanBytes(memory.Cached))
	fmt.Printf("  Slab:            %s\n", humanBytes(memory.Slab))
	fmt.Printf("  Page tables:     %s\n", humanBytes(memory.PageTables))
	fmt.Printf("  Kernel stack:    %s\n", humanBytes(memory.KernelStack))
	fmt.Printf("  Dirty:           %s\n", humanBytes(memory.Dirty))
	fmt.Printf("  Writeback:       %s\n", humanBytes(memory.Writeback))

	if memory.SwapTotal > 0 {
		swapUsed := memory.SwapTotal - memory.SwapFree

		fmt.Printf(
			"  Swap:            %s / %s\n",
			humanBytes(swapUsed),
			humanBytes(memory.SwapTotal),
		)
	} else {
		fmt.Println("  Swap:            disabled")
	}

	fmt.Println()
}

func printProcesses(processes ProcessStats) {
	fmt.Println("PROCESSES")
	fmt.Printf("  Total:           %d\n", processes.Total)
	fmt.Printf("  Running:         %d\n", processes.Running)
	fmt.Printf("  Sleeping:        %d\n", processes.Sleeping)
	fmt.Printf("  Stopped:         %d\n", processes.Stopped)
	fmt.Printf("  Zombie:          %d\n", processes.Zombie)
	fmt.Printf("  Other:           %d\n", processes.Other)
	fmt.Println()
}

func printPressure() {
	fmt.Println("PRESSURE STALL INFORMATION")

	resources := []string{"cpu", "memory", "io"}

	for _, resource := range resources {
		pressure, err := readPressure(resource)
		if err != nil {
			fmt.Printf("  %-8s unavailable\n", strings.ToUpper(resource))
			continue
		}

		fmt.Printf("  %s\n", strings.ToUpper(resource))

		if pressure.Some != "" {
			fmt.Printf("    some: %s\n", pressure.Some)
		}

		if pressure.Full != "" {
			fmt.Printf("    full: %s\n", pressure.Full)
		}
	}
}

func humanBytes(bytes uint64) string {
	const unit = 1024

	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	div := uint64(unit)
	exp := 0

	for value := bytes / unit; value >= unit && exp < 5; value /= unit {
		div *= unit
		exp++
	}

	units := []string{"KiB", "MiB", "GiB", "TiB", "PiB", "EiB"}

	return fmt.Sprintf(
		"%.2f %s",
		float64(bytes)/float64(div),
		units[exp],
	)
}

func formatDuration(duration time.Duration) string {
	seconds := uint64(duration.Seconds())

	days := seconds / 86400
	seconds %= 86400

	hours := seconds / 3600
	seconds %= 3600

	minutes := seconds / 60
	seconds %= 60

	if days > 0 {
		return fmt.Sprintf(
			"%dd %02dh %02dm %02ds",
			days,
			hours,
			minutes,
			seconds,
		)
	}

	return fmt.Sprintf(
		"%02dh %02dm %02ds",
		hours,
		minutes,
		seconds,
	)
}

func formatBootTime(timestamp uint64) string {
	if timestamp == 0 {
		return "unknown"
	}

	return time.Unix(int64(timestamp), 0).
		Local().
		Format("2006-01-02 15:04:05")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
