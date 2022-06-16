package coverbee

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/davecgh/go-spew/spew"
	"github.com/dylandreimerink/coverbee/pkg/verifierlog"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/cover"
)

// InstrumentAndLoadCollection adds instrumentation instructions to all programs contained within the given collection.
// This "instrumentation" is nothing more than incrementing a 16-bit number within a map value, at an index unique
// to the location within the program(Block ID/index). After updating the program, it is loaded into the kernel, the
// loaded collection and a list of program blocks is returned. The index of the returned program blocks matches the
// index of blocks in the coverage map.
//
// Steps of the function:
//  1. Load the original programs and collect the verbose verifier log
//  2. Parse the verifier log, which tells us which registers and stack slots are occupied at any given time.
//  3. Convert the program into a CFG(Control Flow Graph)
//  4. At the start of each program and bpf-to-bpf function, load the cover-map's index 0 and store the map value in a
//     available slot on the stack.
//  5. At the start of each block, load an offset into the cover-map value, increment it, write it back. This requires 2
//     registers which can be clobbered. If only 1 or no registers are unused, store the register values to the stack
//     and restore values afterwards.
//  6. Move symbols of the original code to the instrumented code so jumps and functions calls first pass by the
//     instrumentation.
//  7. Load all modified program into the kernel.
func InstrumentAndLoadCollection(
	coll *ebpf.CollectionSpec,
	opts ebpf.CollectionOptions,
	logWriter io.Writer,
) (*ebpf.Collection, []*ProgBlock, error) {
	if logWriter != nil {
		fmt.Fprintln(logWriter, "=== Original program ===")
		for name, prog := range coll.Programs {
			fmt.Fprintln(logWriter, "---", name, "---")
			fmt.Fprintln(logWriter, prog.Instructions)
		}
	}

	// Clone the spec so we can load and unload without side effects
	clone := coll.Copy()
	clonedOpts := opts

	clonedOpts.Programs.LogLevel = 2
	clonedOpts.Programs.LogSize = 1 << 20

	const maxAttempts = 5
	var (
		cloneColl *ebpf.Collection
		err       error
	)
	for i := 0; i < maxAttempts; i++ {
		cloneColl, err = ebpf.NewCollectionWithOptions(clone, clonedOpts)
		if err != nil {
			const ENOSPC = syscall.Errno(0x1c)
			if errors.Is(err, ENOSPC) {
				// Increse size by the power of four, so going: 1, 4, 16, 64, 256
				clonedOpts.Programs.LogSize = clonedOpts.Programs.LogSize << 2
				continue
			}

			return nil, nil, fmt.Errorf("load program: %w", err)
		}
	}

	if logWriter != nil {
		fmt.Fprintln(logWriter, "=== Original verifier logs ===")
		for name, prog := range cloneColl.Programs {
			fmt.Fprintln(logWriter, "---", name, "---")
			fmt.Fprintln(logWriter, prog.VerifierLog)
		}

		fmt.Fprintln(logWriter, "\n=== Parsed verifier logs ===")
		for name, prog := range cloneColl.Programs {
			fmt.Fprintln(logWriter, "---", name, "---")
			for _, line := range verifierlog.ParseVerifierLog(prog.VerifierLog) {
				spew.Fdump(logWriter, line)
			}
		}
	}

	blockList := make([]*ProgBlock, 0)

	blockID := 0
	if logWriter != nil {
		fmt.Fprintln(logWriter, "\n=== Instrumentation ===")
	}
	for name, prog := range coll.Programs {
		mergedStates := verifierlog.MergedPerInstruction(cloneColl.Programs[name].VerifierLog)
		if logWriter != nil {
			fmt.Fprintln(logWriter, "---", name, "--- Merged states ---")
			for i, mergedState := range mergedStates {
				fmt.Fprintf(logWriter, "%5d: %s\n", i, mergedState.String())
			}
		}

		// TODO check per subprogram (it currently works, but uses way to much memory than is required)
		progMaxFPOff := 0
		for _, state := range mergedStates {
			for _, slot := range state.Stack {
				if slot.Offset > progMaxFPOff {
					progMaxFPOff = slot.Offset
				}
			}
		}
		coverMapPFOff := progMaxFPOff + 8
		regSave1FPOff := progMaxFPOff + 16
		regSave2FPOff := progMaxFPOff + 24

		if logWriter != nil {
			fmt.Fprintln(logWriter, "---", name, "--- Stack offset ---")
			fmt.Fprintln(logWriter, "Max used by prog:", progMaxFPOff)
			fmt.Fprintln(logWriter, "Cover map value:", coverMapPFOff)
			fmt.Fprintln(logWriter, "Reg save 1:", regSave1FPOff)
			fmt.Fprintln(logWriter, "Reg save 2:", regSave2FPOff)
		}

		blocks := ProgramBlocks(prog.Instructions)
		instn := 0

		if logWriter != nil {
			fmt.Fprintln(logWriter, "---", name, "--- Blocks ---")
			for i, block := range blocks {
				fmt.Fprint(logWriter, "Block ", i, ":\n")
				fmt.Fprintln(logWriter, block.Block)
			}
		}

		blockList = append(blockList, blocks...)

		newProgram := make([]asm.Instruction, 0, len(prog.Instructions)+2*len(blocks))

		subProgFuncs := make(map[string]bool)
		for _, inst := range prog.Instructions {
			if inst.IsFunctionCall() {
				subProgFuncs[inst.Reference()] = true
			}
		}

		for _, block := range blocks {
			instr := make(asm.Instructions, 0)

			blockSym := block.Block[0].Symbol()
			// At the start of each program/sub-program we need to lookup the the covermap value and store in in the
			// stack so we can access it while in the current stack frame.
			if subProgFuncs[blockSym] || name == blockSym {
				// 1. Get registers used by function
				var progFunc *btf.Func
				if err := coll.Programs[name].BTF.TypeByName(blockSym, &progFunc); err != nil {
					return nil, nil, fmt.Errorf("can't find Func for '%s' in '%s': %w", blockSym, name, err)
				}

				funcProto := progFunc.Type.(*btf.FuncProto)
				regCnt := len(funcProto.Params)

				// 2.1. Initialize all un-initialized registers
				// This allows us to assume we can always save a register to the stack
				instr = append(instr,
					asm.Mov.Imm(asm.R0, 0),
				)
				for i := asm.R1 + asm.Register(regCnt); i <= asm.R9; i++ {
					instr = append(instr,
						asm.Mov.Imm(i, 0),
					)
				}

				// 2.2. Store used registers in R6-R9 (and stack slot if all 5 regs are used)
				if regCnt == 5 {
					// We can store R1-R4 in R6-R9 but if a function uses all five registers we need to store
					// R5 on the stack.
					instr = append(instr,
						asm.StoreMem(asm.R10, -int16(regSave2FPOff), asm.R5, asm.DWord),
					)
					regCnt = 4
				}

				for i := asm.R1; i < asm.R1+asm.Register(regCnt); i++ {
					instr = append(instr,
						asm.Mov.Reg(i+5, i),
					)
				}

				instr = append(instr,
					// 3. Load map ptr
					asm.LoadMapPtr(asm.R1, 0).WithReference("coverbee_covermap"),
					// 4. Store key=0 in regSave1 slot
					asm.Mov.Reg(asm.R2, asm.R10),
					asm.Add.Imm(asm.R2, -int32(regSave1FPOff)),
					asm.StoreImm(asm.R2, 0, 0, asm.DWord),
					// 5. Lookup map value
					asm.FnMapLookupElem.Call(),
					// 6. Null check (exit on R0 = null)
					asm.Instruction{
						OpCode:   asm.OpCode(asm.JumpClass).SetJumpOp(asm.JNE).SetSource(asm.ImmSource),
						Dst:      asm.R0,
						Offset:   2,
						Constant: 0,
					},
					asm.Mov.Imm(asm.R0, -1),
					asm.Return(),
					// 7. Store map value on in coverMapFPOff
					asm.StoreMem(asm.R10, -int16(coverMapPFOff), asm.R0, asm.DWord),
				)

				// 8. Restore R1-R5
				for i := asm.R1; i < asm.R1+asm.Register(regCnt); i++ {
					instr = append(instr,
						asm.Mov.Reg(i, i+5),
					)
				}

				if len(funcProto.Params) == 5 {
					instr = append(instr,
						asm.LoadMem(asm.R5, asm.R10, -int16(regSave2FPOff), asm.DWord),
					)
				}
			}

			// Index which registers are sometimes used and which are never used
			var usedRegs [11]bool
			for _, reg := range mergedStates[instn].Registers {
				usedRegs[reg.Register] = true
			}

			var (
				unusedR1 asm.Register = 255
				unusedR2 asm.Register = 255
			)

			// Check each register, attempt to find two registers which are never used.
			for i := asm.R0; i <= asm.R9; i++ {
				if !usedRegs[i] {
					if unusedR1 == 255 {
						unusedR1 = i
						usedRegs[i] = true
						continue
					}
					if unusedR2 == 255 {
						unusedR2 = i
						break
					}
				}
			}

			// If we were unable to find an unused first register
			mapValR := unusedR1
			if mapValR == 255 {
				mapValR = asm.R8
				instr = append(instr,
					// Store R8 in stack for now
					asm.StoreMem(asm.R10, -int16(regSave1FPOff), mapValR, asm.DWord),
				)
			}

			// If we were unable to find an unused second register
			counterR := unusedR2
			if counterR == 255 {
				// In case we were able to use R9 as map val, we must pick R8 as counterR
				if mapValR == asm.R9 {
					counterR = asm.R8
				} else {
					counterR = asm.R9
				}
				instr = append(instr,
					// Store R9 in stack for now
					asm.StoreMem(asm.R10, -int16(regSave2FPOff), counterR, asm.DWord),
				)
			}

			instr = append(instr,
				// Load cover map value into `mapValR`
				asm.LoadMem(mapValR, asm.R10, -int16(coverMapPFOff), asm.DWord),
				// Get the current count of the blockID
				asm.LoadMem(counterR, mapValR, int16(blockID)*2, asm.Half),
				// Increment it
				asm.Add.Imm(counterR, 1),
				// Write it back
				asm.StoreMem(mapValR, int16(blockID)*2, counterR, asm.Half),
			)

			if unusedR1 == 255 {
				// Restore map value register if it was saved
				instr = append(instr,
					asm.LoadMem(mapValR, asm.R10, -int16(regSave1FPOff), asm.DWord),
				)
			}

			if unusedR2 == 255 {
				// Restore counter register if it was saved
				instr = append(instr,
					asm.LoadMem(counterR, asm.R10, -int16(regSave2FPOff), asm.DWord),
				)
			}

			// Move the symbol from head of the original code to the instrumented block so jumps and function calls
			// enter at the instrumented code first.
			newProgram = append(newProgram, instr[0].WithSymbol(block.Block[0].Symbol()))
			newProgram = append(newProgram, instr[1:]...)

			// Loop over all instruction in the original code block
			for i, inst := range block.Block {
				// Remove the symbol from the first instruction, it has been moved to the instrumented code
				if i == 0 {
					inst = inst.WithSymbol("")
				}

				// Record the names of sub programs.
				if inst.IsFunctionCall() {
					subProgFuncs[inst.Reference()] = true
				}

				// Add original instructions to the new program
				newProgram = append(newProgram, inst)

				if inst.OpCode.IsDWordLoad() {
					instn++
				}

				instn++
			}

			blockID++
		}

		if logWriter != nil {
			fmt.Fprintln(logWriter, "---", name, "--- Instrumented ---")
			fmt.Fprintln(logWriter, asm.Instructions(newProgram))
		}

		coll.Programs[name].Instructions = newProgram

		// TODO fix BTF
		coll.Programs[name].BTF = nil
	}

	cloneColl.Close()

	coverMap := ebpf.MapSpec{
		Name:       "covermap",
		Type:       ebpf.Array,
		KeySize:    4,
		MaxEntries: 1,
		ValueSize:  uint32(2 * (blockID + 1)),
		// Value: &btf.Datasec{},
		// TODO BTF
	}
	coll.Maps["coverbee_covermap"] = &coverMap

	if logWriter != nil {
		// Verbose
		opts.Programs.LogLevel = 2
	}

	loadedColl, err := ebpf.NewCollectionWithOptions(coll, opts)

	if logWriter != nil {
		fmt.Fprintln(logWriter, "=== Instrumented verifier logs ===")
		if loadedColl != nil {
			for name, prog := range loadedColl.Programs {
				fmt.Fprintln(logWriter, "---", name, "---")
				fmt.Fprintln(logWriter, prog.VerifierLog)
			}
		}
	}

	return loadedColl, blockList, err
}

// ProgramBlocks takes a list of instructions and converts it into a a CFG(Control Flow Graph).
// Which works as follows:
//  1. Construct a translation map from RawOffsets to the instructions(since index within the slice doesn't account for
//     LDIMM64 instructions which use two instructions).
//  2. Apply a label to every jump target and set that label as a reference in the branching instruction. This does two
//     things. First, it makes it easy to find all block boundaries since each block has a function name or jump label.
//     The second is that cilium/ebpf will recalculate the offsets of the jumps based on the symbols when loading, so
//     we can easily add instructions to blocks without fear of breaking offsets.
//  3. Loop over all instructions, creating a block at each branching instruction or symbol/jump label.
//  4. Build a translation map from symbol/jump label to block.
//  5. Loop over all blocks, using the map from step 4 to link blocks together on the branching and non-branching edges.
func ProgramBlocks(prog asm.Instructions) []*ProgBlock {
	prog = slices.Clone(prog)

	// Make a RawInstOffset -> instruction lookup which improves performance during jump labeling
	iter := prog.Iterate()
	offToInst := map[asm.RawInstructionOffset]*asm.Instruction{}
	for iter.Next() {
		offToInst[iter.Offset] = iter.Ins
	}

	iter = prog.Iterate()
	for iter.Next() {
		inst := iter.Ins

		// Ignore non-jump ops, or "special" jump instructions
		op := inst.OpCode.JumpOp()
		switch op {
		case asm.InvalidJumpOp, asm.Call, asm.Exit:
			continue
		}

		targetOff := iter.Offset + asm.RawInstructionOffset(inst.Offset+1)
		label := fmt.Sprintf("j-%d", targetOff)

		target := offToInst[targetOff]
		*target = target.WithSymbol(label)

		inst.Offset = -1
		*inst = inst.WithReference(label)
	}

	blocks := make([]*ProgBlock, 0)
	curBlock := &ProgBlock{}
	for _, inst := range prog {
		if inst.Symbol() != "" {
			if len(curBlock.Block) > 0 {
				newBlock := &ProgBlock{
					Index: curBlock.Index + 1,
				}
				curBlock.NoBranch = newBlock
				blocks = append(blocks, curBlock)
				curBlock = newBlock
			}
		}

		curBlock.Block = append(curBlock.Block, inst)

		// Continue on non-jump ops
		op := inst.OpCode.JumpOp()
		if op == asm.InvalidJumpOp {
			continue
		}

		newBlock := &ProgBlock{
			Index: curBlock.Index + 1,
		}

		if op != asm.Exit {
			// If the current op is exit, then the current block will not continue into the block after it.
			curBlock.NoBranch = newBlock
		}

		blocks = append(blocks, curBlock)
		curBlock = newBlock
	}

	symToBlock := make(map[string]*ProgBlock)
	for _, block := range blocks {
		sym := block.Block[0].Symbol()
		if sym != "" {
			symToBlock[sym] = block
		}
	}

	for _, block := range blocks {
		lastInst := block.Block[len(block.Block)-1]

		// Ignore non-jump ops and exit's
		op := lastInst.OpCode.JumpOp()
		switch op {
		case asm.InvalidJumpOp, asm.Exit:
			continue
		}

		block.Branch = symToBlock[lastInst.Reference()]
	}

	return blocks
}

type ProgBlock struct {
	Index int
	// The current block of code
	Block asm.Instructions

	// The next block of we don't branch
	NoBranch *ProgBlock
	// The next block if we do branch
	Branch *ProgBlock
}

// CFGToBlockList convert a CFG to a "BlockList", the outer slice indexed by BlockID which maps to an inner slice, each
// element of which is a reference to a specific block of code inside a source file. Thus the resulting block list
// can be used to translate blockID's into the pieces of source code to apply coverage mapping.
func CFGToBlockList(cfg []*ProgBlock) [][]CoverBlock {
	blockList := make([][]CoverBlock, 0, len(cfg))
	for blockID, block := range cfg {
		blockList = append(blockList, make([]CoverBlock, 0))
		for _, inst := range block.Block {
			src := inst.Source()
			if src == nil {
				continue
			}

			line, ok := src.(*btf.Line)
			if !ok {
				continue
			}

			blockList[blockID] = append(blockList[blockID], CoverBlock{
				Filename: filepath.Clean(line.FileName()),
				ProfileBlock: cover.ProfileBlock{
					StartLine: int(line.LineNumber()),
					StartCol:  2,
					EndLine:   int(line.LineNumber()),
					EndCol:    2000,
					NumStmt:   1,
				},
			})
		}
	}

	return blockList
}

// ApplyCoverMapToBlockList reads from the coverage map and applies the counts inside the map to the block list.
// The blocklist can be iterated after this to create a go-cover coverage file.
func ApplyCoverMapToBlockList(coverMap *ebpf.Map, blockList [][]CoverBlock) error {
	key := uint32(0)
	value := make([]byte, coverMap.ValueSize())

	err := coverMap.Lookup(&key, &value)
	if err != nil {
		return fmt.Errorf("error looking up coverage output: %w", err)
	}

	for blockID, lines := range blockList {
		blockCnt := nativeEndianess().Uint16(value[blockID*2 : (blockID+1)*2])
		for i := range lines {
			blockList[blockID][i].ProfileBlock.Count = int(blockCnt)
		}
	}

	return nil
}

var nativeEndian binary.ByteOrder

func nativeEndianess() binary.ByteOrder {
	if nativeEndian != nil {
		return nativeEndian
	}

	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
		return nativeEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
		return nativeEndian
	default:
		panic("Could not determine native endianness.")
	}
}