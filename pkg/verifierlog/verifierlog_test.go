package verifierlog

import (
	"reflect"
	"testing"

	"github.com/andreyvit/diff"
	"github.com/cilium/ebpf/asm"
	"github.com/davecgh/go-spew/spew"
)

var seedLog = []string{
	`func#4 @114
0: R1=ctx(id=0,off=0,imm=0) R10=fp0`,
	`; __be16 h_proto = eth->h_proto;
6: (71) r3 = *(u8 *)(r1 +12)      ; R1_w=pkt(id=0,off=0,r=14,imm=0) R3_w=invP(id=0,umax_value=255,var_off=(0x0; 0xff))`,
	`22: (85) call pc+4
reg type unsupported for arg#0 function handle_ipv4#23
caller:
 R6=invP2 R10=fp0
callee:
 frame1: R1=pkt(id=0,off=0,r=18,imm=0) R2=pkt_end(id=0,off=0,imm=0) R3=invP18 R4=invP8 R10=fp0`,
	`; static __noinline void handle_ipv4(void *data, void *data_end, __u64 nh_off)
27: (bf) r8 = r3                      ; frame1: R3=invP18 R8_w=invP18

`,
	`from 94 to 107: frame2: R0=map_value(id=0,off=0,ks=2,vs=16,imm=0) R6=invP(id=5) R10=fp0 fp-8=mm??????
; stats_ptr->pkts++;`,
	`from 57 to 23: R0=invP(id=0) R6=invP2 R10=fp0
; handle_ipv4(data, data_end, nh_off);
23: (05) goto pc+1
propagating r6
25: safe`,
	`26: (95) exit
processed 520 insns (limit 1000000) max_states_per_insn 1 total_states 46 peak_states 46 mark_read 7`,
}

func FuzzParseVerifierLog(f *testing.F) {
	for _, log := range seedLog {
		f.Add(log)
	}

	f.Fuzz(func(t *testing.T, log string) {
		ParseVerifierLog(log)
	})
}

func Test_parseStatement(t *testing.T) {
	tests := []struct {
		name string
		log  string
		want []VerifierStatement
	}{
		{
			name: "Backtrack instruction",
			log:  "regs=100 stack=0 before 1: (b7) r8 = 0",
			want: []VerifierStatement{
				&BackTrackInstruction{
					Regs:  []byte{0x1, 0x00},
					Stack: 0,
					Instruction: &Instruction{
						InstructionNumber: 1,
						Opcode:            asm.OpCode(0xb7),
						Assembly:          " r8 = 0",
					},
				},
			},
		},
		{
			name: "Instruction state #1",
			log:  "36: (69) r1 = *(u16 *)(r7 +46)        ; R1_w=inv(id=0,umax_value=65535,var_off=(0x0; 0xffff)) R7_w=map_value(id=0,off=0,ks=4,vs=100,imm=0)",
			want: []VerifierStatement{
				&InstructionState{
					Instruction: Instruction{
						InstructionNumber: 36,
						Opcode:            asm.OpCode(0x69),
						Assembly:          " r1 = *(u16 *)(r7 +46)        ",
					},
					State: VerifierState{
						Registers: []RegisterState{
							{
								Register: asm.R1,
								Liveness: LivenessWritten,
								Value: RegisterValue{
									Type:      RegTypeScalarValue,
									UMaxValue: 65535,
									VarOff: TNum{
										Mask:  0x0,
										Value: 0xffff,
									},
								},
							},
							{
								Register: asm.R7,
								Liveness: LivenessWritten,
								Value: RegisterValue{
									Type:      RegTypeMapValue,
									KeySize:   4,
									ValueSize: 100,
								},
							},
						},
					},
				},
			},
		},
		{
			name: "Backtracking trailer",
			log:  "parent didn't have regs=8 stack=0 marks: R0=inv(id=0) R1_w=inv(id=0,umax_value=65519,var_off=(0x0; 0xffef)) R2_w=inv(id=0) R3_rw=invP16 R6=map_value(id=0,off=56,ks=4,vs=8192,imm=0) R7_w=inv60 R8=pkt(id=0,off=0,r=34,imm=0) R9=map_value(id=0,off=0,ks=14,vs=56,imm=0) R10=fp0 fp-8=???????m fp-16=????mmmm fp-24=mmmmmmmm fp-32=mmmmmmmm fp-40=mmmmmmmm fp-48=mmmmmmmm fp-56=mmmmmmmm fp-64=mmmmmmmm fp-72=mmmmmmmm fp-80=mmmmmmmm fp-88=mmmmmmmm fp-96=??mmmmmm fp-104=mmmm0000 fp-112=map_value fp-120=ctx fp-128=map_ptr fp-136=inv fp-144=pkt_end fp-152=00000000 fp-160=00000000 fp-168=inv fp-176=00000000",
			want: []VerifierStatement{
				&BackTrackingTrailer{
					ParentMatch: false,
					Regs:        []byte{0x08},
					Stack:       0,
					VerifierState: &VerifierState{
						Registers: []RegisterState{
							// R0=inv(id=0)
							{
								Register: asm.R0,
								Value: RegisterValue{
									Type: RegTypeScalarValue,
								},
							},
							// R1_w=inv(id=0,umax_value=65519,var_off=(0x0; 0xffef))
							{
								Register: asm.R1,
								Liveness: LivenessWritten,
								Value: RegisterValue{
									Type:      RegTypeScalarValue,
									UMaxValue: 65519,
									VarOff: TNum{
										Mask:  0x0,
										Value: 0xffef,
									},
								},
							},
							// R2_w=inv(id=0)
							{
								Register: asm.R2,
								Liveness: LivenessWritten,
								Value: RegisterValue{
									Type: RegTypeScalarValue,
								},
							},
							// R3_rw=invP16
							{
								Register: asm.R3,
								Liveness: LivenessRead | LivenessWritten,
								Value: RegisterValue{
									Type:    RegTypeScalarValue,
									Precise: true,
									VarOff: TNum{
										Mask:  0,
										Value: 16,
									},
								},
							},
							// R6=map_value(id=0,off=56,ks=4,vs=8192,imm=0)
							{
								Register: asm.R6,
								Value: RegisterValue{
									Type:      RegTypeMapValue,
									Off:       56,
									KeySize:   4,
									ValueSize: 8192,
								},
							},
							// R7_w=inv60
							{
								Register: asm.R7,
								Liveness: LivenessWritten,
								Value: RegisterValue{
									Type: RegTypeScalarValue,
									VarOff: TNum{
										Mask:  0,
										Value: 60,
									},
								},
							},
							// R8=pkt(id=0,off=0,r=34,imm=0)
							{
								Register: asm.R8,
								Value: RegisterValue{
									Type:  RegTypePtrToPacket,
									Range: 34,
								},
							},
							// R9=map_value(id=0,off=0,ks=14,vs=56,imm=0)
							{
								Register: asm.R9,
								Value: RegisterValue{
									Type:      RegTypeMapValue,
									KeySize:   14,
									ValueSize: 56,
								},
							},
							// R10=fp0
							{
								Register: asm.R10,
								Value: RegisterValue{
									Type: RegTypePtrToStack,
								},
							},
						},
						Stack: []StackState{
							// fp-8=???????m
							{
								Offset: 8,
								Slots: [8]StackSlot{
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotMisc,
								},
							},
							// fp-16=????mmmm
							{
								Offset: 16,
								Slots: [8]StackSlot{
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-24=mmmmmmmm
							{
								Offset: 24,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-32=mmmmmmmm
							{
								Offset: 32,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-40=mmmmmmmm
							{
								Offset: 40,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-48=mmmmmmmm
							{
								Offset: 48,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-56=mmmmmmmm
							{
								Offset: 56,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-64=mmmmmmmm
							{
								Offset: 64,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-72=mmmmmmmm
							{
								Offset: 72,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-80=mmmmmmmm
							{
								Offset: 80,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-88=mmmmmmmm
							{
								Offset: 88,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-96=??mmmmmm
							{
								Offset: 96,
								Slots: [8]StackSlot{
									StackSlotInvalid,
									StackSlotInvalid,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
								},
							},
							// fp-104=mmmm0000
							{
								Offset: 104,
								Slots: [8]StackSlot{
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotMisc,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
								},
							},
							// fp-112=map_value
							{
								Offset: 112,
								SpilledRegister: RegisterValue{
									Type: RegTypeMapValue,
								},
							},
							// fp-120=ctx
							{
								Offset: 120,
								SpilledRegister: RegisterValue{
									Type: RegTypePtrToCtx,
								},
							},
							// fp-128=map_ptr
							{
								Offset: 128,
								SpilledRegister: RegisterValue{
									Type: RegTypeConstPtrToMap,
								},
							},
							// fp-136=inv
							{
								Offset: 136,
								SpilledRegister: RegisterValue{
									Type: RegTypeScalarValue,
								},
							},
							// fp-144=pkt_end
							{
								Offset: 144,
								SpilledRegister: RegisterValue{
									Type: RegTypePtrToPacketEnd,
								},
							},
							// fp-152=00000000
							{
								Offset: 152,
								Slots: [8]StackSlot{
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
								},
							},
							// fp-160=00000000
							{
								Offset: 160,
								Slots: [8]StackSlot{
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
								},
							},
							// fp-168=inv
							{
								Offset: 168,
								SpilledRegister: RegisterValue{
									Type: RegTypeScalarValue,
								},
							},
							// fp-176=00000000
							{
								Offset: 176,
								Slots: [8]StackSlot{
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
									StackSlotZero,
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseVerifierLog(tt.log); !reflect.DeepEqual(got, tt.want) {
				spew.Config.DisableMethods = true
				t.Errorf(
					"parseStatement() diff %s",
					diff.LineDiff(spew.Sdump(got), spew.Sdump(tt.want)),
				)
				spew.Config.DisableMethods = false
			}
		})
	}
}
