//go:build amd64 && !purego && !noasm

#include "textflag.h"

TEXT ·supportsAESASM(SB), NOSPLIT, $0-4
	MOVL $1, AX
	XORL CX, CX
	CPUID
	SHRL $25, CX
	ANDL $1, CX
	MOVL CX, ret+0(FP)
	RET

TEXT ·aesEncryptBlockAsm(SB), NOSPLIT, $0-64
	MOVQ rounds+0(FP), CX
	MOVQ roundKeys+8(FP), AX
	MOVQ dst_base+16(FP), DX
	MOVQ input_base+40(FP), BX

	MOVOU (BX), X0
	MOVOU (AX), X1
	PXOR X1, X0
	ADDQ $16, AX

enc_loop:
	CMPQ CX, $1
	JE enc_last
	MOVOU (AX), X1
	AESENC X1, X0
	ADDQ $16, AX
	DECQ CX
	JMP enc_loop

enc_last:
	MOVOU (AX), X1
	AESENCLAST X1, X0
	MOVOU X0, (DX)
	RET

TEXT ·aesDecryptBlockAsm(SB), NOSPLIT, $0-64
	MOVQ rounds+0(FP), CX
	MOVQ roundKeys+8(FP), AX
	MOVQ dst_base+16(FP), DX
	MOVQ input_base+40(FP), BX

	MOVOU (BX), X0
	MOVOU (AX), X1
	PXOR X1, X0
	ADDQ $16, AX

dec_loop:
	CMPQ CX, $1
	JE dec_last
	MOVOU (AX), X1
	AESDEC X1, X0
	ADDQ $16, AX
	DECQ CX
	JMP dec_loop

dec_last:
	MOVOU (AX), X1
	AESDECLAST X1, X0
	MOVOU X0, (DX)
	RET
