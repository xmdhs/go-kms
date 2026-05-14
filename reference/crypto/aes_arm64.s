//go:build arm64 && !purego && !noasm

#include "textflag.h"

TEXT ·aesEncryptBlockAsm(SB), NOSPLIT, $0-64
	MOVD rounds+0(FP), R9
	MOVD roundKeys+8(FP), R10
	MOVD dst_base+16(FP), R11
	MOVD input_base+40(FP), R12

	VLD1 (R12), [V0.B16]
	VLD1.P 16(R10), [V1.B16]
	AESE V1.B16, V0.B16
	AESMC V0.B16, V0.B16
	SUB $1, R9

enc_loop:
	CMP $1, R9
	BEQ enc_last
	VLD1.P 16(R10), [V1.B16]
	AESE V1.B16, V0.B16
	AESMC V0.B16, V0.B16
	SUB $1, R9
	B enc_loop

enc_last:
	VLD1.P 16(R10), [V1.B16]
	AESE V1.B16, V0.B16
	VLD1 (R10), [V1.B16]
	VEOR V0.B16, V1.B16, V0.B16
	VST1 [V0.B16], (R11)
	RET

TEXT ·aesDecryptBlockAsm(SB), NOSPLIT, $0-64
	MOVD rounds+0(FP), R9
	MOVD roundKeys+8(FP), R10
	MOVD dst_base+16(FP), R11
	MOVD input_base+40(FP), R12

	VLD1 (R12), [V0.B16]
	VLD1.P 16(R10), [V1.B16]
	AESD V1.B16, V0.B16
	AESIMC V0.B16, V0.B16
	SUB $1, R9

dec_loop:
	CMP $1, R9
	BEQ dec_last
	VLD1.P 16(R10), [V1.B16]
	AESD V1.B16, V0.B16
	AESIMC V0.B16, V0.B16
	SUB $1, R9
	B dec_loop

dec_last:
	VLD1.P 16(R10), [V1.B16]
	AESD V1.B16, V0.B16
	VLD1 (R10), [V1.B16]
	VEOR V0.B16, V1.B16, V0.B16
	VST1 [V0.B16], (R11)
	RET
