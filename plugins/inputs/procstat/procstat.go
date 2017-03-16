package procstat

import (
	"fmt"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

type PID int32

type Procstat struct {
	PidFile     string `toml:"pid_file"`
	Exe         string
	Pattern     string
	Prefix      string
	ProcessName string
	User        string
	PidTag      bool

	pidFinder       PIDFinder
	createPIDFinder func() (PIDFinder, error)
	procs           map[PID]Process
	createProcess   func(PID) (Process, error)
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
	procs, err := p.updateProcesses(p.procs)
	if err != nil {
		return fmt.Errorf(
			"E! Error: procstat getting process, exe: [%s] pidfile: [%s] pattern: [%s] user: [%s] %s",
			p.Exe, p.PidFile, p.Pattern, p.User, err.Error())
	}
	p.procs = procs

	for _, proc := range p.procs {
		p := NewSpecProcessor(p.Prefix, acc, proc)
		p.pushMetrics()
	}

	return nil
}

// Update monitored Processes
func (p *Procstat) updateProcesses(prevInfo map[PID]Process) (map[PID]Process, error) {
	pids, tags, err := p.findPids()
	if err != nil {
		return nil, err
	}

	procs := make(map[PID]Process)

	for _, pid := range pids {
		info, ok := prevInfo[pid]
		if ok {
			procs[pid] = info
		} else {
			proc, err := p.createProcess(pid)
			if err != nil {
				// No problem; process may have ended after we found it
				continue
			}
			procs[pid] = proc

			// Add initial tags
			for k, v := range tags {
				proc.Tags()[k] = v
			}

			// Add pid tag if needed
			if p.PidTag {
				proc.Tags()["pid"] = fmt.Sprint(pid)
			}
			if p.ProcessName != "" {
				proc.Tags()["process_name"] = p.ProcessName
			}
		}
	}
	return procs, nil
}

// Create and return PIDGatherer lazily
func (p *Procstat) getPIDFinder() (PIDFinder, error) {
	if p.pidFinder == nil {
		f, err := p.createPIDFinder()
		if err != nil {
			return nil, err
		}
		p.pidFinder = f
	}
	return p.pidFinder, nil
}

// Get matching PIDs and their initial tags
func (p *Procstat) findPids() ([]PID, map[string]string, error) {
	var pids []PID
	var tags map[string]string
	var err error

	f, err := p.getPIDFinder()
	if err != nil {
		return nil, nil, err
	}

	if p.PidFile != "" {
		pids, err = f.PidFile(p.PidFile)
		tags = map[string]string{"pidfile": p.PidFile}
	} else if p.Exe != "" {
		pids, err = f.Pattern(p.Exe)
		tags = map[string]string{"exe": p.Exe}
	} else if p.Pattern != "" {
		pids, err = f.FullPattern(p.Pattern)
		tags = map[string]string{"pattern": p.Pattern}
	} else if p.User != "" {
		pids, err = f.Uid(p.User)
		tags = map[string]string{"user": p.User}
	} else {
		err = fmt.Errorf("Either exe, pid_file, user, or pattern has to be specified")
	}

	return pids, tags, err
}

func init() {
	inputs.Add("procstat", func() telegraf.Input {
		return &Procstat{
			createPIDFinder: NewPgrep,
			createProcess:   NewProc,
		}
	})
}
