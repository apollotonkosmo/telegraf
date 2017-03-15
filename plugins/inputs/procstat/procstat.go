package procstat

import (
	"fmt"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/process"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

type PID int32

type PIDGatherer interface {
	PidFile(path string) ([]PID, error)
	Pattern(pattern string) ([]PID, error)
	Uid(user string) ([]PID, error)
	FullPattern(path string) ([]PID, error)
}

type Process interface {
	IOCounters() (*process.IOCountersStat, error)
	MemoryInfo() (*process.MemoryInfoStat, error)
	NumCtxSwitches() (*process.NumCtxSwitchesStat, error)
	NumFDs() (int32, error)
	NumThreads() (int32, error)
	Percent(interval time.Duration) (float64, error)
	Times() (*cpu.TimesStat, error)
	Tags() map[string]string
}

type Proc struct {
	HasCPUTimes bool

	tags map[string]string
	*process.Process
}

func (p *Proc) Tags() map[string]string {
	return p.tags
}

type Procstat struct {
	PidFile     string `toml:"pid_file"`
	Exe         string
	Pattern     string
	Prefix      string
	ProcessName string
	User        string
	PidTag      bool

	pidGatherer PIDGatherer
	pInfo       map[PID]*Proc
}

var sampleConfig = `
  ## Must specify one of: pid_file, exe, or pattern
  ## PID file to monitor process
  pid_file = "/var/run/nginx.pid"
  ## executable name (ie, pgrep <exe>)
  # exe = "nginx"
  ## pattern as argument for pgrep (ie, pgrep -f <pattern>)
  # pattern = "nginx"
  ## user as argument for pgrep (ie, pgrep -u <user>)
  # user = "nginx"

  ## override for process_name
  ## This is optional; default is sourced from /proc/<pid>/status
  # process_name = "bar"
  ## Field name prefix
  prefix = ""
  ## comment this out if you want raw cpu_time stats
  fielddrop = ["cpu_time_*"]
  ## This is optional; moves pid into a tag instead of a field
  pid_tag = false
`

func (_ *Procstat) SampleConfig() string {
	return sampleConfig
}

func (_ *Procstat) Description() string {
	return "Monitor process cpu and memory usage"
}

func (p *Procstat) Gather(acc telegraf.Accumulator) error {
	if p.pidGatherer == nil {
		pgrep, err := NewPgrep()
		if err != nil {
			return err
		}
		p.pidGatherer = pgrep
	}

	procs, err := p.createProcesses(p.pInfo)
	if err != nil {
		return fmt.Errorf(
			"E! Error: procstat getting process, exe: [%s] pidfile: [%s] pattern: [%s] user: [%s] %s",
			p.Exe, p.PidFile, p.Pattern, p.User, err.Error())
	}
	p.pInfo = procs

	for pid, proc := range p.pInfo {
		if p.PidTag {
			proc.Tags()["pid"] = fmt.Sprint(pid)
		}
		p := NewSpecProcessor(p.ProcessName, p.Prefix, pid, acc, proc)
		p.pushMetrics()
	}

	return nil
}

func (p *Procstat) createProcesses(prevInfo map[PID]*Proc) (map[PID]*Proc, error) {
	pids, tags, err := p.gatherPids()
	if err != nil {
		return nil, err
	}

	procs := make(map[PID]*Proc)

	for _, pid := range pids {
		info, ok := prevInfo[pid]
		if ok {
			procs[pid] = info
		} else {
			proc, err := process.NewProcess(int32(pid))
			if err != nil {
				continue
			}

			procTags := make(map[string]string)
			for k, v := range tags {
				procTags[k] = v
			}

			pinfo := Proc{
				Process:     proc,
				HasCPUTimes: false,
				tags:        procTags,
			}
			procs[pid] = &pinfo
		}
	}
	return procs, nil
}

func (p *Procstat) gatherPids() ([]PID, map[string]string, error) {
	var pids []PID
	var tags map[string]string
	var err error

	if p.PidFile != "" {
		pids, err = p.pidGatherer.PidFile(p.PidFile)
		tags = map[string]string{"pidfile": p.PidFile}
	} else if p.Exe != "" {
		pids, err = p.pidGatherer.Pattern(p.Exe)
		tags = map[string]string{"exe": p.Exe}
	} else if p.Pattern != "" {
		pids, err = p.pidGatherer.FullPattern(p.Pattern)
		tags = map[string]string{"pattern": p.Pattern}
	} else if p.User != "" {
		pids, err = p.pidGatherer.Uid(p.User)
		tags = map[string]string{"user": p.User}
	} else {
		err = fmt.Errorf("Either exe, pid_file, user, or pattern has to be specified")
	}

	return pids, tags, err
}

func init() {
	inputs.Add("procstat", func() telegraf.Input {
		return &Procstat{}
	})
}
