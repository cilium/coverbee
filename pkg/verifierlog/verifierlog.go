package verifierlog

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
)

// ParseVerifierLog parses the verbose output of the kernel eBPF verifier. It simply returns all statements in the order
// they appeared in the verifier output.
func ParseVerifierLog(log string) []VerifierStatement {
	scan := bufio.NewScanner(strings.NewReader(log))
	statements := make([]VerifierStatement, 0)
	for scan.Scan() {
		parsed := parseStatement(scan)
		if parsed != nil {
			statements = append(statements, parsed)
		}
	}
	return statements
}

// MergedPerInstruction takes and parses the verifier log. It then merges the observed register and stack states seen
// for each permutation the verifier considers. The resulting state isn't useful for its values, just to see which
// registers are never used and which stack slots/offsets are never used.
func MergedPerInstruction(log string) []VerifierState {
	scan := bufio.NewScanner(strings.NewReader(log))
	states := make([]VerifierState, 0)

	var curState VerifierState

	mergeCurState := func(state VerifierState) {
		for _, reg := range state.Registers {
			found := false
			for i, curReg := range curState.Registers {
				if reg.Register == curReg.Register {
					curState.Registers[i] = reg
					found = true
					break
				}
			}
			if !found {
				curState.Registers = append(curState.Registers, reg)
			}
		}

		for _, slot := range state.Stack {
			found := false
			for i, curSlot := range curState.Stack {
				if slot.Offset == curSlot.Offset {
					curState.Stack[i] = slot
					found = true
					break
				}
			}
			if !found {
				curState.Stack = append(curState.Stack, slot)
			}
		}
	}

	applyCurState := func(instNum int) {
		if instNum >= len(states) {
			states = append(states, make([]VerifierState, 1+instNum-len(states))...)
		}

		// Apply current state to `states`
		for _, curReg := range curState.Registers {
			found := false
			for i, reg := range states[instNum].Registers {
				if reg.Register == curReg.Register {
					states[instNum].Registers[i] = reg
					found = true
					break
				}
			}
			if !found {
				states[instNum].Registers = append(states[instNum].Registers, curReg)
			}
		}

		for _, curSlot := range curState.Stack {
			found := false
			for i, slot := range states[instNum].Stack {
				if slot.Offset == curSlot.Offset {
					states[instNum].Stack[i] = slot
					found = true
					break
				}
			}
			if !found {
				states[instNum].Stack = append(states[instNum].Stack, curSlot)
			}
		}
	}

	for scan.Scan() {
		parsed := parseStatement(scan)
		if parsed != nil {
			switch parsed := parsed.(type) {
			case *RecapState:
				// RecapState only show relevant values not all of them, so apply the diff
				mergeCurState(parsed.State)

			case *ReturnFunctionCall:
				curState = *parsed.CallerState

			case *BranchEvaluation:
				curState = *parsed.State

			case *Instruction:
				// Apply current state to `states`
				applyCurState(parsed.InstructionNumber)

			case *InstructionState:
				// Apply current state to `states`
				applyCurState(parsed.InstructionNumber)

				// InstructionState only show relevant values not all of them, so apply the diff
				mergeCurState(parsed.State)

			default:
				continue
			}
		}
	}

	return states
}

func parseStatement(scan *bufio.Scanner) VerifierStatement {
	line := scan.Text()
	// Skip empty lines
	if line == "" {
		return nil
	}

	if strings.HasPrefix(line, ";") {
		return parseComment(line)
	}

	if strings.HasPrefix(line, "func#") {
		return parseSubProgLocation(line)
	}

	if strings.HasPrefix(line, "propagating") {
		return parsePropagatePrecision(line)
	}

	if strings.HasPrefix(line, "last_idx") {
		return parseBackTrackingHeader(line)
	}

	if strings.HasPrefix(line, "caller") {
		return parseFunctionCall(line, scan)
	}

	if strings.HasPrefix(line, "returning from callee") {
		return parseReturnFunctionCall(line, scan)
	}

	if statePrunedRegex.MatchString(line) {
		return parseStatePruned(line)
	}

	if instructionStateRegex.MatchString(line) {
		return parseInstructionState(line)
	}

	if instructionRegex.MatchString(line) {
		return parseInstruction(line)
	}

	if recapStateRegex.MatchString(line) {
		return parseRecapState(line)
	}

	if branchEvaluationRegex.MatchString(line) {
		return parseBranchEvaluation(line)
	}

	if backTrackInstructionRegex.MatchString(line) {
		return parseBackTrackInstruction(line)
	}

	if backTrackingTrailerRegex.MatchString(line) {
		return parseBacktrackingTrailer(line)
	}

	if loadSuccessRegex.MatchString(line) {
		return parseLoadSuccess(line)
	}

	return &Unknown{Log: line}
}

// VerifierStatement is often a single line of the log.
type VerifierStatement interface {
	fmt.Stringer
	verifierStmt()
}

// For when we have no clue what a line is or means
type Unknown struct {
	Log string
}

func (u *Unknown) String() string {
	return u.Log
}

func (u *Unknown) verifierStmt() {}

// An error, something went wrong
type Error struct {
	Msg string
}

func (e *Error) String() string {
	return e.Msg
}

func (e *Error) Error() string {
	return e.Msg
}

func (e *Error) verifierStmt() {}

func parseComment(line string) *Comment {
	return &Comment{
		Comment: strings.TrimPrefix(line, "; "),
	}
}

// A comment, usually contains the original line of the source code
// Example: "; if (data + nh_off > data_end)"
type Comment struct {
	Comment string
}

func (c *Comment) String() string {
	return fmt.Sprintf("; %s", c.Comment)
}

func (c *Comment) verifierStmt() {}

var recapStateRegex = regexp.MustCompile(`^(\d+): ?(.*)`)

func parseRecapState(line string) VerifierStatement {
	match := recapStateRegex.FindStringSubmatch(line)
	if len(match) == 0 {
		return &Error{Msg: "recap state: no match"}
	}

	instNr, _ := strconv.Atoi(match[1])
	verifierState := parseVerifierState(match[2])

	return &RecapState{
		InstructionNumber: instNr,
		State:             *verifierState,
	}
}

// A recap of the current state of the verifier and its location, without indicating it evaluated an expression.
// This happens when the verifier switches state to evaluate another permutation.
// Example: "0: R1=ctx(id=0,off=0,imm=0) R10=fp0"
type RecapState struct {
	InstructionNumber int
	State             VerifierState
}

func (is *RecapState) String() string {
	return fmt.Sprintf("%d: %s", is.InstructionNumber, is.State.String())
}

func (is *RecapState) verifierStmt() {}

var instructionStateRegex = regexp.MustCompile(`^(\d+): \(([0-9a-f]{2})\)([^;]+);(.*)`)

func parseInstructionState(line string) VerifierStatement {
	match := instructionStateRegex.FindStringSubmatch(line)
	if len(match) == 0 {
		return &Error{Msg: "instruction state: no match"}
	}

	instNr, _ := strconv.Atoi(match[1])
	opcode, err := hex.DecodeString(match[2])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("decode opcode hex: %s", err)}
	}

	verifierState := parseVerifierState(match[4])

	return &InstructionState{
		Instruction: Instruction{
			InstructionNumber: instNr,
			Opcode:            asm.OpCode(opcode[0]),
			Assembly:          match[3],
		},
		State: *verifierState,
	}
}

// Instruction and verifier state. Logged when the verifier evaluates an instruction. The state is the state after the
// instruction was evaluated.
// Example: "0: (b7) r6 = 1; R6_w=invP1"
type InstructionState struct {
	Instruction
	State VerifierState
}

func (is *InstructionState) String() string {
	return fmt.Sprintf("%d: (%02x)%s; %s", is.InstructionNumber, byte(is.Opcode), is.Assembly, is.State.String())
}

func (is *InstructionState) verifierStmt() {}

var instructionRegex = regexp.MustCompile(`^(\d+): \(([0-9a-f]{2})\)([^;]+)`)

func parseInstruction(line string) VerifierStatement {
	match := instructionRegex.FindStringSubmatch(line)
	if len(match) == 0 {
		return &Error{Msg: "instruction state: no match"}
	}

	instNr, _ := strconv.Atoi(match[1])
	opcode, err := hex.DecodeString(match[2])
	if err != nil {
		return &Error{Msg: fmt.Sprintf("decode opcode hex: %s", err)}
	}
	return &Instruction{
		InstructionNumber: instNr,
		Opcode:            asm.OpCode(opcode[0]),
		Assembly:          match[3],
	}
}

func (is *Instruction) String() string {
	return fmt.Sprintf("%d: (%02x)%s", is.InstructionNumber, byte(is.Opcode), is.Assembly)
}

func (is *Instruction) verifierStmt() {}

// Instruction describes an instruction, is used by multiple statements.
// Example: "22: (85) call pc+4"
type Instruction struct {
	InstructionNumber int
	Opcode            asm.OpCode
	Assembly          string
}

func parseVerifierState(line string) *VerifierState {
	var state VerifierState
	line = strings.TrimSpace(line)

	if strings.HasPrefix(line, "frame") {
		line = strings.TrimPrefix(line, "frame")
		colon := strings.Index(line, ":")
		state.FrameNumber, _ = strconv.Atoi(line[:colon])
		line = strings.TrimSpace(line[colon+1:])
	}

	for {
		equal := strings.Index(line, "=")
		if equal == -1 {
			break
		}

		key := line[:equal]
		var value string

		line = line[equal+1:]
		bktDepth := 0
		i := 0
		for {
			i++
			if i >= len(line) {
				value = line
				line = line[i:]
				break
			}

			if line[i] == '(' {
				bktDepth++
				continue
			}

			if line[i] == ')' {
				bktDepth--
				continue
			}

			if line[i] == ' ' && bktDepth == 0 {
				value = line[:i]
				line = line[i+1:]
				break
			}
		}

		if strings.HasPrefix(key, "fp") {
			stackState := parseStackState(key, value)
			if stackState != nil {
				state.Stack = append(state.Stack, *stackState)
			}
		} else {
			regState := parseRegisterState(key, value)
			if regState != nil {
				state.Registers = append(state.Registers, *regState)
			}
		}
	}

	return &state
}

// VerifierState contains a description of the state of the verifier at a certain point. Used by a number of statements.
// Example: "frame1: R2_w=invP(id=0) R10=fp0 fp-16_w=mmmmmmmm"
type VerifierState struct {
	FrameNumber int
	Registers   []RegisterState
	Stack       []StackState
}

func parseRegisterState(key, value string) *RegisterState {
	var state RegisterState

	if strings.HasSuffix(key, "_r") {
		key = strings.TrimSuffix(key, "_r")
		state.Liveness = LivenessRead
	}

	if strings.HasSuffix(key, "_w") {
		key = strings.TrimSuffix(key, "_w")
		state.Liveness = LivenessWritten
	}

	if strings.HasSuffix(key, "_D") {
		key = strings.TrimSuffix(key, "_D")
		state.Liveness = LivenessDone
	}

	key = strings.Trim(key, "R")
	keyNum, _ := strconv.Atoi(key)
	state.Register = asm.Register(keyNum)

	if val := parseRegisterValue(value); val != nil {
		state.Value = *val
	}

	return &state
}

func (is *VerifierState) String() string {
	var sb strings.Builder
	if is.FrameNumber != 0 {
		fmt.Fprintf(&sb, "frame%d: ", is.FrameNumber)
	}

	for i, reg := range is.Registers {
		fmt.Fprint(&sb, reg)

		if i+1 < len(is.Registers) || len(is.Stack) > 0 {
			sb.WriteString(" ")
		}
	}

	for i, stackSlot := range is.Stack {
		fmt.Fprint(&sb, stackSlot.String())

		if i+1 < len(is.Stack) {
			sb.WriteString(" ")
		}
	}

	return sb.String()
}

// Liveness indicates the liveness of a register.
type Liveness int

const (
	LivenessNone Liveness = iota
	LivenessRead
	LivenessWritten
	LivenessDone
)

// RegType indicates the data type contained in a register
type RegType int

const (
	RegTypeNotInit RegType = iota
	RegTypeScalarValue
	RegTypePtrToCtx
	RegTypeConstPtrToMap
	RegTypeMapValue
	RegTypePtrToStack
	RegTypePtrToPacket
	RegTypePtrToPacketMeta
	RegTypePtrToPacketEnd
	RegTypePtrToFlowKeys
	RegTypePtrToSock
	RegTypePtrToSockCommon
	RegTypePtrToTCPSock
	RegTypePtrToTPBuf
	RegTypePtrToXDPSock
	RegTypePtrToBTFID
	RegTypePtrToMem
	RegTypePtrToBuf
	RegTypePtrToFunc
	RegTypePtrToMapKey
)

const (
	RegTypeBaseType RegType = 0xFF

	RegTypePtrMaybeNull RegType = 1 << (8 + iota)
	RegTypeMemReadonly
	RegTypeMemAlloc
	RegTypeMemUser
	RegTypeMemPreCPU
)

var rtToString = map[RegType]string{
	RegTypeNotInit:         "?",
	RegTypeScalarValue:     "scalar",
	RegTypePtrToCtx:        "ctx",
	RegTypeConstPtrToMap:   "map_ptr",
	RegTypePtrToMapKey:     "map_key",
	RegTypeMapValue:        "map_value",
	RegTypePtrToStack:      "fp",
	RegTypePtrToPacket:     "pkt",
	RegTypePtrToPacketMeta: "pkt_meta",
	RegTypePtrToPacketEnd:  "pkt_end",
	RegTypePtrToFlowKeys:   "flow_keys",
	RegTypePtrToSock:       "sock",
	RegTypePtrToSockCommon: "sock_common",
	RegTypePtrToTCPSock:    "tcp_sock",
	RegTypePtrToTPBuf:      "tp_buffer",
	RegTypePtrToXDPSock:    "xdp_sock",
	RegTypePtrToBTFID:      "ptr_",
	RegTypePtrToMem:        "mem",
	RegTypePtrToBuf:        "buf",
	RegTypePtrToFunc:       "func",
}

var stringToRT = map[string]RegType{
	"inv":         RegTypeScalarValue,
	"scalar":      RegTypeScalarValue,
	"ctx":         RegTypePtrToCtx,
	"map_ptr":     RegTypeConstPtrToMap,
	"map_key":     RegTypePtrToMapKey,
	"map_value":   RegTypeMapValue,
	"fp":          RegTypePtrToStack,
	"pkt":         RegTypePtrToPacket,
	"pkt_meta":    RegTypePtrToPacketMeta,
	"pkt_end":     RegTypePtrToPacketEnd,
	"flow_keys":   RegTypePtrToFlowKeys,
	"sock":        RegTypePtrToSock,
	"sock_common": RegTypePtrToSockCommon,
	"tcp_sock":    RegTypePtrToTCPSock,
	"tp_buffer":   RegTypePtrToTPBuf,
	"xdp_sock":    RegTypePtrToXDPSock,
	"ptr_":        RegTypePtrToBTFID,
	"mem":         RegTypePtrToMem,
	"buf":         RegTypePtrToBuf,
	"func":        RegTypePtrToFunc,
}

func (rt RegType) String() string {
	var sb strings.Builder

	if rt&RegTypeMemReadonly != 0 {
		sb.WriteString("rdonly_")
	}
	if rt&RegTypeMemAlloc != 0 {
		sb.WriteString("alloc_")
	}
	if rt&RegTypeMemUser != 0 {
		sb.WriteString("user_")
	}
	if rt&RegTypeMemPreCPU != 0 {
		sb.WriteString("per_cpu_")
	}

	sb.WriteString(rtToString[rt&RegTypeBaseType])

	if rt&RegTypePtrMaybeNull != 0 {
		if rt&RegTypeBaseType == RegTypePtrToBTFID {
			sb.WriteString("or_null_")
		} else {
			sb.WriteString("_or_null_")
		}
	}

	return sb.String()
}

// TNum is a tracked (or tristate) number. Relevant parts ported from linux kernel.
// https://elixir.bootlin.com/linux/v5.18.3/source/include/linux/tnum.h
// https://elixir.bootlin.com/linux/v5.18.3/source/kernel/bpf/tnum.c
type TNum struct {
	Value int64
	Mask  int64
}

func (t TNum) isConst() bool {
	return t.Mask == 0
}

func (t TNum) isUnknown() bool {
	return t.Mask == math.MaxInt64
}

func parseRegisterType(line string) (RegType, bool, string) {
	var typ RegType
	precise := false

	if strings.HasPrefix(line, "rdonly_") {
		typ = typ | RegTypeMemReadonly
		line = strings.TrimPrefix(line, "rdonly_")
	}

	if strings.HasPrefix(line, "alloc_") {
		typ = typ | RegTypeMemAlloc
		line = strings.TrimPrefix(line, "alloc_")
	}

	if strings.HasPrefix(line, "user_") {
		typ = typ | RegTypeMemUser
		line = strings.TrimPrefix(line, "user_")
	}

	if strings.HasPrefix(line, "per_cpu_") {
		typ = typ | RegTypeMemPreCPU
		line = strings.TrimPrefix(line, "per_cpu_")
	}

	if strings.HasPrefix(line, "P") {
		precise = true
		line = strings.TrimPrefix(line, "P")
	}

	// Process names from longest to shortest to avoid exiting early on a shorter match
	names := make([]string, 0, len(stringToRT))
	for name := range stringToRT {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		return len(names[i]) > len(names[j])
	})

	for _, name := range names {
		if strings.HasPrefix(line, name) {
			typ = typ | stringToRT[name]
			line = strings.TrimPrefix(line, name)
			break
		}
	}

	if strings.HasPrefix(line, "or_null_") {
		typ = typ | RegTypePtrMaybeNull
		line = strings.TrimPrefix(line, "or_null_")
	}

	if strings.HasPrefix(line, "_or_null_") {
		typ = typ | RegTypePtrMaybeNull
		line = strings.TrimPrefix(line, "_or_null_")
	}

	if strings.HasPrefix(line, "P") {
		precise = true
		line = strings.TrimPrefix(line, "P")
	}

	return typ, precise, line
}

func parseRegisterValue(line string) *RegisterValue {
	var val RegisterValue

	line = strings.TrimSpace(line)

	val.Type, val.Precise, line = parseRegisterType(line)

	if val.Type == RegTypeScalarValue {
		varOff, err := strconv.Atoi(line)
		if err == nil {
			val.VarOff.Value = int64(varOff)
			return &val
		}
	}

	line = strings.TrimSuffix(strings.TrimPrefix(line, "("), ")")
	for _, pair := range strings.Split(line, ",") {
		eq := strings.Index(pair, "=")
		if eq == -1 {
			continue
		}

		key := pair[:eq]
		valStr := pair[eq+1:]

		intVal, _ := strconv.ParseInt(valStr, 10, 64)
		uintVal, _ := strconv.ParseUint(valStr, 10, 64)

		switch key {
		case "id":
			val.ID = int(intVal)
		case "ref_obj_id":
			val.RefObjID = int(intVal)
		case "off":
			val.Off = int32(intVal)
		case "r":
			val.Range = int(intVal)
		case "ks":
			val.KeySize = int(intVal)
		case "vs":
			val.ValueSize = int(intVal)
		case "imm":
			val.VarOff.Value = intVal
		case "smin":
			val.SMinValue = intVal
		case "smax":
			val.SMaxValue = intVal
		case "umin":
			val.UMinValue = uintVal
		case "umax":
			val.UMaxValue = uintVal
		case "s32_min":
			val.S32MinValue = int32(intVal)
		case "s32_max":
			val.S32MaxValue = int32(intVal)
		case "u32_min":
			val.U32MinValue = uint32(uintVal)
		case "u32_max":
			val.U32MaxValue = uint32(uintVal)
		case "var_off":
			hexVal := valStr[1:strings.Index(valStr, ";")]
			hexMask := valStr[strings.Index(valStr, ";")+1 : strings.Index(valStr, ")")]
			val.VarOff.Value, _ = strconv.ParseInt(hexVal, 16, 64)
			val.VarOff.Value, _ = strconv.ParseInt(hexMask, 16, 64)
		}
	}

	return &val
}

// RegisterValue is the value part of the register state, the part after the =
// Example: "invP(id=2,umax_value=255,var_off=(0x0; 0xff))"
type RegisterValue struct {
	Type      RegType
	Off       int32
	ID        int
	RefObjID  int
	Range     int
	KeySize   int
	ValueSize int
	// if (!precise && SCALAR_VALUE) min/max/tnum don't affect safety
	Precise bool
	/* For scalar types (SCALAR_VALUE), this represents our knowledge of
	 * the actual value.
	 * For pointer types, this represents the variable part of the offset
	 * from the pointed-to object, and is shared with all bpf_reg_states
	 * with the same id as us.
	 */
	VarOff TNum
	/* Used to determine if any memory access using this register will
	 * result in a bad access.
	 * These refer to the same value as var_off, not necessarily the actual
	 * contents of the register.
	 */
	SMinValue   int64  /* minimum possible (s64)value */
	SMaxValue   int64  /* maximum possible (s64)value */
	UMinValue   uint64 /* minimum possible (u64)value */
	UMaxValue   uint64 /* maximum possible (u64)value */
	S32MinValue int32  /* minimum possible (s32)value */
	S32MaxValue int32  /* maximum possible (s32)value */
	U32MinValue uint32 /* minimum possible (u32)value */
	U32MaxValue uint32 /* maximum possible (u32)value */

	BTFName string
}

func (rv RegisterValue) String() string {
	var sb strings.Builder
	baseType := rv.Type & RegTypeBaseType

	// TODO make setting to determine to print the P before or after the inv
	if rv.Type == RegTypeScalarValue && rv.Precise {
		sb.WriteString("P")
	}

	if (rv.Type == RegTypeScalarValue || rv.Type == RegTypePtrToStack) && rv.VarOff.isConst() {
		if rv.Type == RegTypeScalarValue {
			fmt.Fprintf(&sb, "%d", rv.VarOff.Value+int64(rv.Off))
		} else {
			sb.WriteString(rv.Type.String())
		}
		return sb.String()
	}

	sb.WriteString(rv.Type.String())
	if baseType == RegTypePtrToBTFID {
		sb.WriteString(rv.BTFName)
	}
	sb.WriteString("(")

	var args []string
	if rv.ID != 0 {
		args = append(args, fmt.Sprintf("id=%d", rv.ID))
	}

	// reg_type_may_be_refcounted_or_null
	if baseType == RegTypePtrToSock || baseType == RegTypePtrToTCPSock || baseType == RegTypePtrToMem {
		args = append(args, fmt.Sprintf("ref_obj_id=%d", rv.RefObjID))
	}

	if baseType != RegTypeScalarValue {
		args = append(args, fmt.Sprintf("off=%d", rv.Off))
	}

	// type_is_pkt_pointer
	if baseType == RegTypePtrToPacket || baseType == RegTypePtrToPacketMeta {
		args = append(args, fmt.Sprintf("r=%d", rv.Range))
	} else if baseType == RegTypeConstPtrToMap || baseType == RegTypePtrToMapKey || baseType == RegTypeMapValue {
		args = append(args, fmt.Sprintf("ks=%d,vs=%d", rv.KeySize, rv.ValueSize))
	}

	if rv.VarOff.isConst() {
		args = append(args, fmt.Sprintf("imm=%d", rv.VarOff.Value))
	} else {
		if rv.SMinValue != int64(rv.UMinValue) && rv.SMinValue != math.MinInt64 {
			args = append(args, fmt.Sprintf("smin=%d", rv.SMinValue))
		}

		if rv.SMaxValue != int64(rv.UMaxValue) && rv.SMaxValue != math.MaxInt64 {
			args = append(args, fmt.Sprintf("smax=%d", rv.SMaxValue))
		}

		if rv.UMinValue != 0 {
			args = append(args, fmt.Sprintf("umin=%d", rv.SMaxValue))
		}

		if rv.UMaxValue != math.MaxUint64 {
			args = append(args, fmt.Sprintf("umin=%d", rv.SMaxValue))
		}

		if !rv.VarOff.isUnknown() {
			args = append(args, fmt.Sprintf("var_off=(%x; %x)", rv.VarOff.Value, rv.VarOff.Mask))
		}

		if int64(rv.S32MinValue) != rv.SMinValue && rv.S32MinValue != math.MinInt32 {
			args = append(args, fmt.Sprintf("s32_min=%d", rv.S32MinValue))
		}

		if int64(rv.S32MaxValue) != rv.SMaxValue && rv.S32MaxValue != math.MaxInt32 {
			args = append(args, fmt.Sprintf("s32_max=%d", rv.S32MaxValue))
		}

		if uint64(rv.U32MinValue) != rv.UMinValue && rv.U32MinValue != 0 {
			args = append(args, fmt.Sprintf("u32_min=%d", rv.S32MinValue))
		}

		if uint64(rv.U32MaxValue) != rv.UMaxValue && rv.U32MaxValue != math.MaxUint32 {
			args = append(args, fmt.Sprintf("u32_max=%d", rv.U32MaxValue))
		}
	}

	sb.WriteString(strings.Join(args, ","))
	sb.WriteString(")")

	return sb.String()
}

// RegisterState describes a single register and its state.
// Example: "R1_w=invP(id=2,umax_value=255,var_off=(0x0; 0xff))"
type RegisterState struct {
	Register asm.Register
	Liveness Liveness
	Value    RegisterValue
}

func (r RegisterState) String() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "R%d", r.Register)
	switch r.Liveness {
	case LivenessRead:
		fmt.Fprint(&sb, "_r")
	case LivenessWritten:
		fmt.Fprint(&sb, "_w")
	case LivenessDone:
		fmt.Fprint(&sb, "_D")
	}

	fmt.Fprintf(&sb, "=%s", r.Value.String())

	return sb.String()
}

func parseStackState(key, value string) *StackState {
	var state StackState

	if strings.HasSuffix(key, "_r") {
		key = strings.TrimSuffix(key, "_r")
		state.Liveness = LivenessRead
	}

	if strings.HasSuffix(key, "_w") {
		key = strings.TrimSuffix(key, "_w")
		state.Liveness = LivenessWritten
	}

	if strings.HasSuffix(key, "_D") {
		key = strings.TrimSuffix(key, "_D")
		state.Liveness = LivenessDone
	}

	key = strings.Trim(key, "fp-")
	keyNum, _ := strconv.Atoi(key)
	state.Offset = keyNum

	state.SpilledRegister.Type, state.SpilledRegister.Precise, value = parseRegisterType(value)
	if state.SpilledRegister.Type != RegTypeNotInit {
		// TODO Scalar value?
	} else {
		for i := 0; i < 8; i++ {
			if i >= len(value) {
				break
			}

			state.Slots[i] = StackSlot(value[i])
		}
	}

	// TODO refs
	// TODO callback

	return &state
}

// StackSlot describes the contents of a single byte within a stack slot
type StackSlot byte

const (
	StackSlotInvalid = '?'
	StackSlotSpill   = 'r'
	StackSlotMist    = 'm'
	StackSlotZero    = '0'
)

// StackState describes the state of a single stack slot.
// Example: `fp-8=m???????`
type StackState struct {
	Offset            int
	Liveness          Liveness
	SpilledRegister   RegisterValue
	Slots             [8]StackSlot
	AcquiredRefs      []string
	InCallbackFn      bool
	InAsyncCallbackFn bool
}

func (ss *StackState) String() string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "fp-%d", ss.Offset)

	switch ss.Liveness {
	case LivenessRead:
		fmt.Fprint(&sb, "_r")
	case LivenessWritten:
		fmt.Fprint(&sb, "_w")
	case LivenessDone:
		fmt.Fprint(&sb, "_D")
	}

	fmt.Fprint(&sb, "=")

	if ss.SpilledRegister.Type != RegTypeNotInit {
		// TODO Scalar type
		fmt.Fprint(&sb, rtToString[ss.SpilledRegister.Type])
		// TODO refs
		// TODO callback
	} else {
		fmt.Fprint(&sb, string(ss.Slots[:]))
	}

	return sb.String()
}

var subProgLocRegex = regexp.MustCompile(`^func#(\d+) @(\d+)`)

func parseSubProgLocation(line string) *SubProgLocation {
	match := subProgLocRegex.FindStringSubmatch(line)
	if len(match) != 3 {
		return nil
	}

	progId, _ := strconv.Atoi(match[1])
	instNum, _ := strconv.Atoi(match[2])
	return &SubProgLocation{
		ProgID:           progId,
		StartInstruction: instNum,
	}
}

// SubProgLocation states the location of a sub program.
// Example: "func#3 @85"
type SubProgLocation struct {
	ProgID           int
	StartInstruction int
}

func (spl *SubProgLocation) String() string {
	return fmt.Sprintf("func#%d @%d", spl.ProgID, spl.StartInstruction)
}

func (spl *SubProgLocation) verifierStmt() {}

func parsePropagatePrecision(line string) *PropagatePrecision {
	line = strings.TrimPrefix(line, "propagating ")
	if strings.HasPrefix(line, "r") {
		regInt, _ := strconv.Atoi(strings.TrimPrefix(line, "r"))
		reg := asm.Register(regInt)
		return &PropagatePrecision{
			Register: &reg,
		}
	}

	offset, _ := strconv.Atoi(strings.TrimPrefix(line, "fp-"))
	return &PropagatePrecision{
		Offset: offset,
	}
}

// PropagatePrecision indicates that the verifier is propagating the precision of a register or stack slot to another
// state. Example: "propagating r6"
type PropagatePrecision struct {
	Register *asm.Register
	Offset   int
}

func (pp *PropagatePrecision) String() string {
	if pp.Register != nil {
		return fmt.Sprintf("propagating r%d", uint8(*pp.Register))
	}

	return fmt.Sprintf("propagating fp-%d", pp.Offset)
}

func (pp *PropagatePrecision) verifierStmt() {}

var statePrunedRegex = regexp.MustCompile(`^(?:from )?(\d+)(?: to (\d+))?: safe`)

func parseStatePruned(line string) *StatePruned {
	match := statePrunedRegex.FindStringSubmatch(line)
	var (
		from int
		to   int
	)
	from, _ = strconv.Atoi(match[1])
	if match[2] != "" {
		to, _ = strconv.Atoi(match[2])
		return &StatePruned{
			From: from,
			To:   to,
		}
	}

	return &StatePruned{
		From: from,
		To:   from,
	}
}

// StatePruned means that the verifier considers a specific permutation to be safe and will prune the state from memory.
// Example: "25: safe" or "from 42 to 57: safe"
type StatePruned struct {
	From int
	To   int
}

func (sp *StatePruned) String() string {
	if sp.From == sp.To {
		return fmt.Sprintf("%d: safe", sp.From)
	}

	return fmt.Sprintf("from %d to %d: safe", sp.From, sp.To)
}

func (sp *StatePruned) verifierStmt() {}

var branchEvaluationRegex = regexp.MustCompile(`^from (\d+) to (\d+): (.*)`)

func parseBranchEvaluation(line string) *BranchEvaluation {
	match := branchEvaluationRegex.FindStringSubmatch(line)
	from, _ := strconv.Atoi(match[1])
	to, _ := strconv.Atoi(match[2])

	return &BranchEvaluation{
		From:  from,
		To:    to,
		State: parseVerifierState(match[3]),
	}
}

// BranchEvaluation means that the verifier switch state and is now evaluating another permutation.
// Example: "from 84 to 40: frame1: R0=invP(id=0) R6=pkt(id=0,off=38,r=38,imm=0) R7=pkt(id=0,off=0,r=38,imm=0) R8=invP18 R9=invP(id=2,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=pkt_end fp-16=mmmmmmmm"
type BranchEvaluation struct {
	From  int
	To    int
	State *VerifierState
}

func (be *BranchEvaluation) String() string {
	return fmt.Sprintf("from %d to %d: %s", be.From, be.To, be.State.String())
}

func (be *BranchEvaluation) verifierStmt() {}

var backTrackingHeaderRegex = regexp.MustCompile(`^last_idx (\d+) first_idx (\d+)`)

func parseBackTrackingHeader(line string) *BackTrackingHeader {
	match := backTrackingHeaderRegex.FindStringSubmatch(line)
	last, _ := strconv.Atoi(match[1])
	first, _ := strconv.Atoi(match[2])

	return &BackTrackingHeader{
		Last:  last,
		First: first,
	}
}

// BackTrackingHeader indicates that the verifier is back tracking, and is followed by BackTrackInstruction and
// BackTrackingTrailer statements. Example: "last_idx 26 first_idx 20"
type BackTrackingHeader struct {
	Last  int
	First int
}

func (bt *BackTrackingHeader) String() string {
	return fmt.Sprintf("last_idx %d first_idx %d", bt.Last, bt.First)
}

func (bt *BackTrackingHeader) verifierStmt() {}

var backTrackInstructionRegex = regexp.MustCompile(`^regs=([0-9a-fA-F]+) stack=(\d+) before (.*)`)

func parseBackTrackInstruction(line string) *BackTrackInstruction {
	match := backTrackInstructionRegex.FindStringSubmatch(line)
	regs, _ := hex.DecodeString(match[1])
	stack, _ := strconv.ParseInt(match[2], 10, 64)
	instruction := parseInstruction(match[3])

	return &BackTrackInstruction{
		Regs:        regs,
		Stack:       stack,
		Instruction: instruction.(*Instruction),
	}
}

// BackTrackInstruction indicates the verifier has back tracked an instruction.
// Example: "regs=4 stack=0 before 25: (bf) r1 = r0"
type BackTrackInstruction struct {
	Regs        []byte
	Stack       int64
	Instruction *Instruction
}

func (bt *BackTrackInstruction) String() string {
	return fmt.Sprintf("regs=%x stack=%d before %s", bt.Regs, bt.Stack, bt.Instruction.String())
}

func (bt *BackTrackInstruction) verifierStmt() {}

var backTrackingTrailerRegex = regexp.MustCompile(`parent (didn't have|already had) regs=([0-9a-fA-F]+) stack=(\d+) marks:? ?(.*)?`)

func parseBacktrackingTrailer(line string) *BackTrackingTrailer {
	match := backTrackingTrailerRegex.FindStringSubmatch(line)
	regs, _ := hex.DecodeString(match[2])
	stack, _ := strconv.ParseInt(match[3], 10, 64)
	state := parseVerifierState(match[4])

	return &BackTrackingTrailer{
		ParentMatch:   match[1] == "already had",
		Regs:          regs,
		Stack:         stack,
		VerifierState: state,
	}
}

// BackTrackingTrailer indicates the verifier is done backtracking.
// Example: `parent didn't have regs=4 stack=0 marks` or `parent already had regs=2a stack=0 marks`
type BackTrackingTrailer struct {
	ParentMatch   bool
	Regs          []byte
	Stack         int64
	VerifierState *VerifierState
}

func (bt *BackTrackingTrailer) String() string {
	if bt.ParentMatch {
		return fmt.Sprintf("parent already had regs=%x stack=%d marks: %s", bt.Regs, bt.Stack, bt.VerifierState.String())
	}

	return fmt.Sprintf("parent didn't have regs=%x stack=%d marks: %s", bt.Regs, bt.Stack, bt.VerifierState.String())
}

func (bt *BackTrackingTrailer) verifierStmt() {}

var loadSuccessRegex = regexp.MustCompile(`processed (\d+) insns \(limit (\d+)\) max_states_per_insn (\d+) total_states (\d+) peak_states (\d+) mark_read (\d+)`)

func parseLoadSuccess(line string) *VerifierDone {
	match := loadSuccessRegex.FindStringSubmatch(line)
	instProcessed, _ := strconv.Atoi(match[1])
	instLimit, _ := strconv.Atoi(match[2])
	maxStatesPerInst, _ := strconv.Atoi(match[3])
	totalStates, _ := strconv.Atoi(match[4])
	peekStates, _ := strconv.Atoi(match[5])
	markRead, _ := strconv.Atoi(match[6])

	return &VerifierDone{
		InstructionsProcessed: instProcessed,
		InstructionLimit:      instLimit,
		MaxStatesPerInst:      maxStatesPerInst,
		TotalStates:           totalStates,
		PeakStates:            peekStates,
		MarkRead:              markRead,
	}
}

// VerifierDone indicates the verifier is done and has failed or succeeded.
// Example: "processed 520 insns (limit 1000000) max_states_per_insn 1 total_states 46 peak_states 46 mark_read 7"
type VerifierDone struct {
	InstructionsProcessed int
	InstructionLimit      int
	MaxStatesPerInst      int
	TotalStates           int
	PeakStates            int
	MarkRead              int
}

func (ls *VerifierDone) String() string {
	return fmt.Sprintf(
		"processed %d insns (limit %d) max_states_per_insn %d total_states %d peak_states %d mark_read %d",
		ls.InstructionsProcessed,
		ls.InstructionLimit,
		ls.MaxStatesPerInst,
		ls.TotalStates,
		ls.PeakStates,
		ls.MarkRead,
	)
}

func (ls *VerifierDone) verifierStmt() {}

func parseFunctionCall(firstLine string, scan *bufio.Scanner) *FunctionCall {
	if strings.TrimSpace(firstLine) != "caller:" {
		return nil
	}

	if !scan.Scan() {
		return nil
	}

	callerState := parseVerifierState(scan.Text())

	if !scan.Scan() {
		return nil
	}

	if strings.TrimSpace(scan.Text()) != "callee:" {
		return nil
	}

	if !scan.Scan() {
		return nil
	}

	calleeState := parseVerifierState(scan.Text())

	return &FunctionCall{
		CallerState: callerState,
		CalleeState: calleeState,
	}
}

// FunctionCall indicates the verifier is following a bpf-to-bpf function call.
// For example:
// caller:
//   frame1: R6=pkt(id=0,off=54,r=74,imm=0) R7=pkt(id=0,off=0,r=74,imm=0) R8_w=pkt(id=0,off=74,r=74,imm=0) R9=invP6 R10=fp0 fp-8=pkt_end fp-16=mmmmmmmm
//  callee:
//   frame2: R1_w=pkt(id=0,off=54,r=74,imm=0) R2_w=invP(id=0) R10=fp0
type FunctionCall struct {
	CallerState *VerifierState
	CalleeState *VerifierState
}

func (fc *FunctionCall) String() string {
	return fmt.Sprintf("caller:\n%s\ncallee:\n%s", fc.CallerState.String(), fc.CalleeState.String())
}

func (fc *FunctionCall) verifierStmt() {}

var returnFuncCallRegex = regexp.MustCompile(`^to caller at (\d+):`)

func parseReturnFunctionCall(firstLine string, scan *bufio.Scanner) *ReturnFunctionCall {
	if strings.TrimSpace(firstLine) != "returning from callee:" {
		return nil
	}

	if !scan.Scan() {
		return nil
	}

	calleeState := parseVerifierState(scan.Text())

	if !scan.Scan() {
		return nil
	}

	match := returnFuncCallRegex.FindStringSubmatch(scan.Text())
	callsite, _ := strconv.Atoi(match[1])

	if !scan.Scan() {
		return nil
	}

	callerState := parseVerifierState(scan.Text())

	return &ReturnFunctionCall{
		CalleeState: calleeState,
		CallSite:    callsite,
		CallerState: callerState,
	}
}

// ReturnFunctionCall indicates the verifier is evaluating returning from a function call.
// Example:
// returning from callee:
//  frame2: R0=map_value(id=0,off=0,ks=1,vs=16,imm=0) R1_w=invP(id=0) R6=invP(id=31) R10=fp0 fp-8=m???????
// to caller at 156:
//   frame1: R0=map_value(id=0,off=0,ks=1,vs=16,imm=0) R6=pkt(id=0,off=54,r=54,imm=0) R7=pkt(id=0,off=0,r=54,imm=0) R8=invP14 R9=invP(id=30,umax_value=255,var_off=(0x0; 0xff)) R10=fp0 fp-8=pkt_end fp-16=mmmmmmmm
type ReturnFunctionCall struct {
	CallerState *VerifierState
	CallSite    int
	CalleeState *VerifierState
}

func (rfc *ReturnFunctionCall) String() string {
	return fmt.Sprintf(
		"returning from callee:\n%s\nto caller at %d:\n%s",
		rfc.CalleeState.String(),
		rfc.CallSite,
		rfc.CallerState.String(),
	)
}

func (rfc *ReturnFunctionCall) verifierStmt() {}
