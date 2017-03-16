package procstat

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/influxdata/telegraf/testutil"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/process"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestPgrep struct {
	pids []PID
	err  error
}

type TestProc struct {
	pid  PID
	tags map[string]string
}

func (pg *TestPgrep) PidFile(path string) ([]PID, error) {
	return pg.pids, pg.err
}

func (pg *TestPgrep) Pattern(pattern string) ([]PID, error) {
	return pg.pids, pg.err
}

func (pg *TestPgrep) Uid(user string) ([]PID, error) {
	return pg.pids, pg.err
}

func (pg *TestPgrep) FullPattern(pattern string) ([]PID, error) {
	return pg.pids, pg.err
}

func NewTestProc(pid PID) (Process, error) {
	proc := &TestProc{
		tags: make(map[string]string),
	}
	return proc, nil
}

func (p *TestProc) PID() PID {
	return p.pid
}

func (p *TestProc) Tags() map[string]string {
	return p.tags
}

func (p *TestProc) IOCounters() (*process.IOCountersStat, error) {
	return &process.IOCountersStat{}, nil
}

func (p *TestProc) MemoryInfo() (*process.MemoryInfoStat, error) {
	return &process.MemoryInfoStat{}, nil
}

func (p *TestProc) Name() (string, error) {
	return "test_proc", nil
}

func (p *TestProc) NumCtxSwitches() (*process.NumCtxSwitchesStat, error) {
	return &process.NumCtxSwitchesStat{}, nil
}

func (p *TestProc) NumFDs() (int32, error) {
	return 0, nil
}

func (p *TestProc) NumThreads() (int32, error) {
	return 0, nil
}

func (p *TestProc) Percent(interval time.Duration) (float64, error) {
	return 0, nil
}

func (p *TestProc) Times() (*cpu.TimesStat, error) {
	return &cpu.TimesStat{}, nil
}

var pid PID = PID(42)
var exe string = "foo"

func TestGather_CreateProcessErrorOk(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Exe:       exe,
		pidFinder: pgrep,
		createProcess: func(pid PID) (Process, error) {
			return nil, fmt.Errorf("File not found")
		},
	}
	require.NoError(t, p.Gather(&acc))
}

func TestGather_CreatePIDFinderError(t *testing.T) {
	var acc testutil.Accumulator

	p := Procstat{
		createPIDFinder: func() (PIDFinder, error) {
			return nil, fmt.Errorf("createPIDFinder error")
		},
		createProcess: NewProc,
	}
	require.Error(t, p.Gather(&acc))
}

func TestGather_ProcessName(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Exe:           exe,
		ProcessName:   "custom_name",
		pidFinder:     pgrep,
		createProcess: NewProc,
	}
	require.NoError(t, p.Gather(&acc))

	assert.Equal(t, "custom_name", acc.TagValue("procstat", "process_name"))
}

func TestGather_NoProcessNameUsesReal(t *testing.T) {
	var acc testutil.Accumulator
	pid := PID(os.Getpid())
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Exe:           exe,
		pidFinder:     pgrep,
		createProcess: NewProc,
	}
	require.NoError(t, p.Gather(&acc))

	assert.True(t, acc.HasTag("procstat", "process_name"))
}

func TestGather_NoPidTag(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Exe:           exe,
		pidFinder:     pgrep,
		createProcess: NewTestProc,
	}
	require.NoError(t, p.Gather(&acc))
	assert.True(t, acc.HasInt32Field("procstat", "pid"))
	assert.False(t, acc.HasTag("procstat", "pid"))
}

func TestGather_PidTag(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Exe:           exe,
		PidTag:        true,
		pidFinder:     pgrep,
		createProcess: NewTestProc,
	}
	require.NoError(t, p.Gather(&acc))
	assert.Equal(t, "42", acc.TagValue("procstat", "pid"))
	assert.False(t, acc.HasInt32Field("procstat", "pid"))
}

func TestGather_Prefix(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Exe:           exe,
		Prefix:        "custom_prefix",
		pidFinder:     pgrep,
		createProcess: NewTestProc,
	}
	require.NoError(t, p.Gather(&acc))
	assert.True(t, acc.HasInt32Field("procstat", "custom_prefix_num_fds"))
}

func TestGather_Exe(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Exe:           exe,
		pidFinder:     pgrep,
		createProcess: NewProc,
	}
	require.NoError(t, p.Gather(&acc))

	assert.Equal(t, exe, acc.TagValue("procstat", "exe"))
}

func TestGather_User(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}
	user := "ada"

	p := Procstat{
		User:          user,
		pidFinder:     pgrep,
		createProcess: NewTestProc,
	}
	require.NoError(t, p.Gather(&acc))

	assert.Equal(t, user, acc.TagValue("procstat", "user"))
}

func TestGather_Pattern(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}
	pattern := "foo"

	p := Procstat{
		Pattern:       pattern,
		pidFinder:     pgrep,
		createProcess: NewTestProc,
	}
	require.NoError(t, p.Gather(&acc))

	assert.Equal(t, pattern, acc.TagValue("procstat", "pattern"))
}

func TestGather_MissingPidMethod(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		pidFinder:     pgrep,
		createProcess: NewTestProc,
	}
	require.Error(t, p.Gather(&acc))
}

func TestGather_PidFile(t *testing.T) {
	var acc testutil.Accumulator
	pgrep := &TestPgrep{pids: []PID{pid}}
	pidfile := "/path/to/pidfile"

	p := Procstat{
		PidFile:       pidfile,
		pidFinder:     pgrep,
		createProcess: NewTestProc,
	}
	require.NoError(t, p.Gather(&acc))

	assert.Equal(t, pidfile, acc.TagValue("procstat", "pidfile"))
}

func TestGather_PercentFirstPass(t *testing.T) {
	var acc testutil.Accumulator
	pid := PID(os.Getpid())
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Pattern:       "foo",
		PidTag:        true,
		pidFinder:     pgrep,
		createProcess: NewProc,
	}
	require.NoError(t, p.Gather(&acc))

	assert.True(t, acc.HasFloatField("procstat", "cpu_time_user"))
	assert.False(t, acc.HasFloatField("procstat", "cpu_usage"))
}

func TestGather_PercentSecondPass(t *testing.T) {
	var acc testutil.Accumulator
	pid := PID(os.Getpid())
	pgrep := &TestPgrep{pids: []PID{pid}}

	p := Procstat{
		Pattern:       "foo",
		PidTag:        true,
		pidFinder:     pgrep,
		createProcess: NewProc,
	}
	require.NoError(t, p.Gather(&acc))
	require.NoError(t, p.Gather(&acc))

	assert.True(t, acc.HasFloatField("procstat", "cpu_time_user"))
	assert.True(t, acc.HasFloatField("procstat", "cpu_usage"))
}
