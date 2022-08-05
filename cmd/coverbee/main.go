package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/cilium/coverbee"
	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"
)

var root = &cobra.Command{
	Use: "coverbee",
	// TODO pimp output
}

func main() {
	root.AddCommand(
		loadCmd(),
		coverageCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var (
	flagMapPinDir       string
	flagCoverMapPinPath string
	flagBlockListPath   string
)

var (
	flagElfPath    string
	flagProgPinDir string
	flagProgType   string
	flagLogPath    string

	flagDisableInterpolation bool
	flagForceInterpolation   bool
)

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

func loadCmd() *cobra.Command {
	load := &cobra.Command{
		Use: "load {--elf=ELF path} {--prog-pin-dir=path to dir} " +
			"{--map-pin-dir=path to dir | --covermap-pin=path to covermap} " +
			"{--block-list=path to blocklist}",
		Short: "Instrument all programs in the given ELF file and load them into the kernel",
		// Long:  "",
		RunE: load,
	}

	fs := load.Flags()

	fs.StringVar(&flagElfPath, "elf", "", "Path to the ELF file containing the programs")
	panicOnError(load.MarkFlagFilename("elf", "o", "elf"))
	panicOnError(load.MarkFlagRequired("elf"))

	fs.StringVar(&flagProgPinDir, "prog-pin-dir", "", "Path the directory where the loaded programs will be pinned")
	panicOnError(load.MarkFlagDirname("prog-pin-dir"))
	panicOnError(load.MarkFlagRequired("prog-pin-dir"))

	fs.StringVar(&flagProgType, "prog-type", "", "Explicitly set the program type")

	fs.StringVar(&flagMapPinDir, "map-pin-dir", "", "Path to the directory containing map pins")
	panicOnError(load.MarkFlagDirname("map-pin-dir"))

	fs.StringVar(&flagCoverMapPinPath, "covermap-pin", "", "Path to pin for the covermap (created by coverbee "+
		"containing coverage information)")
	panicOnError(load.MarkFlagFilename("covermap-pin"))

	fs.StringVar(&flagBlockListPath, "block-list", "", "Path where the block-list is stored (contains coverage data "+
		"to source code mapping, needed when reading from cover map)")
	panicOnError(load.MarkFlagFilename("block-list", "json"))
	panicOnError(load.MarkFlagRequired("block-list"))

	fs.StringVar(&flagLogPath, "log", "", "Path for ultra-verbose log output")

	return load
}

func checkCovermapFlags(cmd *cobra.Command, args []string) error {
	if flagMapPinDir == "" && flagCoverMapPinPath == "" {
		return fmt.Errorf("either --map-pin-dir or --covermap-pin must be set")
	}

	if flagMapPinDir != "" && flagCoverMapPinPath != "" {
		return fmt.Errorf("either --map-pin-dir or --covermap-pin must be set, not both")
	}

	return nil
}

func load(cmd *cobra.Command, args []string) error {
	if err := checkCovermapFlags(cmd, args); err != nil {
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(flagElfPath)
	if err != nil {
		return fmt.Errorf("Load collection spec: %w", err)
	}

	if flagProgType != "" {
		progTestType := strToProgType[flagProgType]
		if progTestType == ebpf.UnspecifiedProgram {
			options := make([]string, 0, len(strToProgType))
			for option := range strToProgType {
				options = append(options, option)
			}
			sort.Strings(options)

			var sb strings.Builder
			fmt.Fprintf(&sb, "Invalid --prog-type value '%s', pick from:\n", flagProgType)
			for _, option := range options {
				fmt.Fprintf(&sb, " - %s\n", option)
			}

			return errors.New(sb.String())
		}

		// Set all unknown program types to the specified type
		for _, spec := range spec.Programs {
			if spec.Type == ebpf.UnspecifiedProgram {
				spec.Type = progTestType
			}
		}
	}

	for _, spec := range spec.Programs {
		if spec.Type == ebpf.UnspecifiedProgram {
			return fmt.Errorf(
				"Program '%s' is of an unspecified type, use --prog-type to explicitly set one",
				spec.Name,
			)
		}
	}

	for _, m := range spec.Maps {
		if m.Extra != nil {
			//nolint:errcheck // we explicitly discard the error, no remediation available
			_, _ = io.ReadAll(m.Extra)
		}
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: 32 << 20,
		},
	}

	if flagMapPinDir != "" {
		opts.Maps.PinPath = flagMapPinDir
	}

	var logWriter io.Writer
	if flagLogPath != "" {
		var logFile *os.File
		logFile, err = os.Create(flagLogPath)
		if err != nil {
			return fmt.Errorf("open log file: %w", err)
		}
		defer logFile.Close()

		logBuf := bufio.NewWriter(logFile)
		defer logBuf.Flush()

		logWriter = logBuf
	}

	coll, cfg, err := coverbee.InstrumentAndLoadCollection(spec, opts, logWriter)
	if err != nil {
		return fmt.Errorf("error while instrumenting and loading program: %w", err)
	}
	defer coll.Close()

	for name, prog := range coll.Programs {
		if err = prog.Pin(filepath.Join(flagProgPinDir, name)); err != nil {
			return fmt.Errorf("error pinning program '%s': %w", name, err)
		}
	}

	if flagMapPinDir != "" {
		if err = coll.Maps["coverbee_covermap"].Pin(filepath.Join(flagMapPinDir, "coverbee_covermap")); err != nil {
			return fmt.Errorf("error pinning covermap: %w", err)
		}
	}

	if flagCoverMapPinPath != "" {
		if err = coll.Maps["coverbee_covermap"].Pin(flagCoverMapPinPath); err != nil {
			return fmt.Errorf("error pinning covermap: %w", err)
		}
	}

	blockList := coverbee.CFGToBlockList(cfg)

	blockListFile, err := os.Create(flagBlockListPath)
	if err != nil {
		return fmt.Errorf("error create block-list: %w", err)
	}
	defer blockListFile.Close()

	if err = json.NewEncoder(blockListFile).Encode(&blockList); err != nil {
		return fmt.Errorf("error encoding block-list: %w", err)
	}

	fmt.Println("Programs instrumented and loaded")

	return nil
}

var (
	flagOutputFormat string
	flagOutputPath   string
)

func coverageCmd() *cobra.Command {
	coverCmd := &cobra.Command{
		Use:   "cover",
		Short: "Collect coverage data and output to file",
		RunE:  coverage,
	}

	fs := coverCmd.Flags()

	fs.StringVar(&flagMapPinDir, "map-pin-dir", "", "Path to the directory containing map pins")
	panicOnError(coverCmd.MarkFlagDirname("map-pin-dir"))

	fs.StringVar(&flagCoverMapPinPath, "covermap-pin", "", "Path to pin for the covermap (created by coverbee "+
		"containing coverage information)")
	panicOnError(coverCmd.MarkFlagFilename("covermap-pin"))

	fs.StringVar(&flagBlockListPath, "block-list", "", "Path where the block-list is stored (contains coverage data "+
		"to source code mapping, needed when reading from cover map)")
	panicOnError(coverCmd.MarkFlagFilename("block-list", "json"))
	panicOnError(coverCmd.MarkFlagRequired("block-list"))

	fs.StringVar(&flagOutputFormat, "format", "html", "Output format (options: html, go-cover)")

	fs.StringVar(&flagOutputPath, "output", "", "Path to the coverage output")
	panicOnError(coverCmd.MarkFlagRequired("output"))

	fs.BoolVar(&flagDisableInterpolation, "disable-interpolation", false, "Disable source based interpolation")
	fs.BoolVar(&flagForceInterpolation, "force-interpolation", false, "Force source based interpolation, or error")

	return coverCmd
}

func coverage(cmd *cobra.Command, args []string) error {
	if err := checkCovermapFlags(cmd, args); err != nil {
		return err
	}

	var (
		coverMap *ebpf.Map
		err      error
	)
	if flagMapPinDir != "" {
		coverMap, err = ebpf.LoadPinnedMap(filepath.Join(flagMapPinDir, "coverbee_covermap"), nil)
		if err != nil {
			return fmt.Errorf("load covermap pin: %w", err)
		}
	} else {
		coverMap, err = ebpf.LoadPinnedMap(flagCoverMapPinPath, nil)
		if err != nil {
			return fmt.Errorf("load covermap pin: %w", err)
		}
	}

	blockList := make([][]coverbee.CoverBlock, 0)

	blockListPath, err := os.Open(flagBlockListPath)
	if err != nil {
		return fmt.Errorf("open block-list: %w", err)
	}

	if err = json.NewDecoder(blockListPath).Decode(&blockList); err != nil {
		return fmt.Errorf("decode block-list: %w", err)
	}

	if err = coverbee.ApplyCoverMapToBlockList(coverMap, blockList); err != nil {
		return fmt.Errorf("apply covermap: %w", err)
	}

	outBlocks := blockList
	if !flagDisableInterpolation {
		outBlocks, err = coverbee.SourceCodeInterpolation(blockList, nil)
		if err != nil {
			if flagForceInterpolation {
				return fmt.Errorf("error while interpolating using source files: %w", err)
			}

			fmt.Printf("Warning error while interpolating using source files, falling back: %s", err.Error())
			outBlocks = blockList
		}
	}

	var output io.Writer
	if flagOutputPath == "-" {
		output = os.Stdout
	} else {
		var f *os.File
		f, err = os.Create(flagOutputPath)
		if err != nil {
			return fmt.Errorf("error creating output file: %w", err)
		}
		output = f
		defer f.Close()
	}

	switch flagOutputFormat {
	case "html":
		if err = coverbee.BlockListToHTML(outBlocks, output, "count"); err != nil {
			return fmt.Errorf("block list to HTML: %w", err)
		}
	case "go-cover", "cover":
		coverbee.BlockListToGoCover(outBlocks, output, "count")
	default:
		return fmt.Errorf("unknown output format")
	}

	return nil
}

var strToProgType = map[string]ebpf.ProgramType{
	"socket":                ebpf.SocketFilter,
	"sk_reuseport/migrate":  ebpf.SkReuseport,
	"sk_reuseport":          ebpf.SkReuseport,
	"kprobe":                ebpf.Kprobe,
	"uprobe":                ebpf.Kprobe,
	"kretprobe":             ebpf.Kprobe,
	"uretprobe":             ebpf.Kprobe,
	"tc":                    ebpf.SchedCLS,
	"classifier":            ebpf.SchedCLS,
	"action":                ebpf.SchedACT,
	"tracepoint":            ebpf.TracePoint,
	"tp":                    ebpf.TracePoint,
	"raw_tracepoint":        ebpf.RawTracepoint,
	"raw_tp":                ebpf.RawTracepoint,
	"raw_tracepoint.w":      ebpf.RawTracepointWritable,
	"raw_tp.w":              ebpf.RawTracepointWritable,
	"tp_btf":                ebpf.Tracing,
	"fentry":                ebpf.Tracing,
	"fmod_ret":              ebpf.Tracing,
	"fexit":                 ebpf.Tracing,
	"fentry.s":              ebpf.Tracing,
	"fmod_ret.s":            ebpf.Tracing,
	"fexit.s":               ebpf.Tracing,
	"freplace":              ebpf.Extension,
	"lsm":                   ebpf.LSM,
	"lsm.s":                 ebpf.LSM,
	"iter":                  ebpf.Tracing,
	"syscall":               ebpf.Syscall,
	"xdp_devmap":            ebpf.XDP,
	"xdp_cpumap":            ebpf.XDP,
	"xdp":                   ebpf.XDP,
	"perf_event":            ebpf.PerfEvent,
	"lwt_in":                ebpf.LWTIn,
	"lwt_out":               ebpf.LWTOut,
	"lwt_xmit":              ebpf.LWTXmit,
	"lwt_seg6local":         ebpf.LWTSeg6Local,
	"cgroup_skb/ingress":    ebpf.CGroupSKB,
	"cgroup_skb/egress":     ebpf.CGroupSKB,
	"cgroup/skb":            ebpf.CGroupSKB,
	"cgroup/sock_create":    ebpf.CGroupSock,
	"cgroup/sock_release":   ebpf.CGroupSock,
	"cgroup/sock":           ebpf.CGroupSock,
	"cgroup/post_bind4":     ebpf.CGroupSock,
	"cgroup/post_bind6":     ebpf.CGroupSock,
	"cgroup/dev":            ebpf.CGroupDevice,
	"sockops":               ebpf.SockOps,
	"sk_skb/stream_parser":  ebpf.SkSKB,
	"sk_skb/stream_verdict": ebpf.SkSKB,
	"sk_skb":                ebpf.SkSKB,
	"sk_msg":                ebpf.SkMsg,
	"lirc_mode2":            ebpf.LircMode2,
	"flow_dissector":        ebpf.FlowDissector,
	"cgroup/bind4":          ebpf.CGroupSockAddr,
	"cgroup/bind6":          ebpf.CGroupSockAddr,
	"cgroup/connect4":       ebpf.CGroupSockAddr,
	"cgroup/connect6":       ebpf.CGroupSockAddr,
	"cgroup/sendmsg4":       ebpf.CGroupSockAddr,
	"cgroup/sendmsg6":       ebpf.CGroupSockAddr,
	"cgroup/recvmsg4":       ebpf.CGroupSockAddr,
	"cgroup/recvmsg6":       ebpf.CGroupSockAddr,
	"cgroup/getpeername4":   ebpf.CGroupSockAddr,
	"cgroup/getpeername6":   ebpf.CGroupSockAddr,
	"cgroup/getsockname4":   ebpf.CGroupSockAddr,
	"cgroup/getsockname6":   ebpf.CGroupSockAddr,
	"cgroup/sysctl":         ebpf.CGroupSysctl,
	"cgroup/getsockopt":     ebpf.CGroupSockopt,
	"cgroup/setsockopt":     ebpf.CGroupSockopt,
	"struct_ops":            ebpf.StructOps,
	"sk_lookup":             ebpf.SkLookup,
	"seccomp":               ebpf.SocketFilter,
}
