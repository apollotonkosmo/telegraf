package procstat

import (
	"time"

	"github.com/influxdata/telegraf"
)

type SpecProcessor struct {
	Prefix string
	fields map[string]interface{}
	acc    telegraf.Accumulator
	proc   Process
}

func NewSpecProcessor(
	prefix string,
	acc telegraf.Accumulator,
	proc Process,
) *SpecProcessor {
	return &SpecProcessor{
		Prefix: prefix,
		fields: make(map[string]interface{}),
		acc:    acc,
		proc:   proc,
	}
}

func (p *SpecProcessor) pushMetrics() {
	var prefix string
	if p.Prefix != "" {
		prefix = p.Prefix + "_"
	}

	fields := map[string]interface{}{}

	//If process_name tag is not already set, set to actual name
	if _, nameInTags := p.proc.Tags()["process_name"]; !nameInTags {
		name, err := p.proc.Name()
		if err == nil {
			p.proc.Tags()["process_name"] = name
		}
	}

	//If pid is not present as a tag, include it as a field.
	if _, pidInTags := p.proc.Tags()["pid"]; !pidInTags {
		fields["pid"] = int32(p.proc.PID())
	}

	numThreads, err := p.proc.NumThreads()
	if err == nil {
		fields[prefix+"num_threads"] = numThreads
	}

	fds, err := p.proc.NumFDs()
	if err == nil {
		fields[prefix+"num_fds"] = fds
	}

	ctx, err := p.proc.NumCtxSwitches()
	if err == nil {
		fields[prefix+"voluntary_context_switches"] = ctx.Voluntary
		fields[prefix+"involuntary_context_switches"] = ctx.Involuntary
	}

	io, err := p.proc.IOCounters()
	if err == nil {
		fields[prefix+"read_count"] = io.ReadCount
		fields[prefix+"write_count"] = io.WriteCount
		fields[prefix+"read_bytes"] = io.ReadBytes
		fields[prefix+"write_bytes"] = io.WriteBytes
	}

	cpu_time, err := p.proc.Times()
	if err == nil {
		fields[prefix+"cpu_time_user"] = cpu_time.User
		fields[prefix+"cpu_time_system"] = cpu_time.System
		fields[prefix+"cpu_time_idle"] = cpu_time.Idle
		fields[prefix+"cpu_time_nice"] = cpu_time.Nice
		fields[prefix+"cpu_time_iowait"] = cpu_time.Iowait
		fields[prefix+"cpu_time_irq"] = cpu_time.Irq
		fields[prefix+"cpu_time_soft_irq"] = cpu_time.Softirq
		fields[prefix+"cpu_time_steal"] = cpu_time.Steal
		fields[prefix+"cpu_time_stolen"] = cpu_time.Stolen
		fields[prefix+"cpu_time_guest"] = cpu_time.Guest
		fields[prefix+"cpu_time_guest_nice"] = cpu_time.GuestNice
	}

	cpu_perc, err := p.proc.Percent(time.Duration(0))
	if err == nil {
		fields[prefix+"cpu_usage"] = cpu_perc
	}

	mem, err := p.proc.MemoryInfo()
	if err == nil {
		fields[prefix+"memory_rss"] = mem.RSS
		fields[prefix+"memory_vms"] = mem.VMS
		fields[prefix+"memory_swap"] = mem.Swap
	}

	p.acc.AddFields("procstat", fields, p.proc.Tags())
}
