package verifierlog

import "testing"

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
