
	BITS 32

	mov	eax, 0x41424344
	nop

	cmp	byte [0x41424344], ah
	cmp	ah, bh
	nop

	xchg	word [bx], bx
	xchg	word [ebx], bx
	nop
	xchg	word [bx], bx
	xchg	word [bx + si], bx
	add	bx, word [bx + si]
	add	word [bx + si], si
	nop

	lgdt	[ebx]
	lldt	[ecx]
	lmsw	[edx]

	push	eax
	push	0x41
	push	0x41424344
	push	ds
	push	fs

	imul	ecx, ebx
	imul	ecx, 0x10203040
	imul	ecx
	imul	ebx, dword [0x41424344]
	imul	ecx, [eax], 100

	add	eax, [edx * 8 + eax]
	add	eax, 0x10203040
	add	[edx*2 + ecx + 0x41424344], ebx
	add	[eax*2+edx], ebx

	or	edx, dword [4*eax + 0x41424344]

	nop

	db	0x30
	db	0x0a
	nop

	db	0x9a
	dd	0x40414243
	dw	0x1234

	nop
	fstenv	[0x80818283]

	fstp	tword [0x81828384]
	fstp	st2
	fstsw	ax
	fstsw	word [0x41424344]
	fsub	st4, st0
	fsub	st4
	fsub	qword [0x81828384]
	fsubp	st4
	fsubr	dword [0x41424344]
	ftst
	fucom	st2
	fucomp	st1
	fucompp
	fucomi	st0
	fucomip	st6
	fxam
	fxch	st3
	fxtract
	fyl2x
	fyl2xp1
	fwait

	nop

	fld	tword [0x81828384]
	fld	st3
	fld1
	fldcw	word [0x41424344]
	fldenv	[0x81828384]
	fldl2e
	fldl2t
	fldlg2
	fldln2
	fldpi
	fldz
	fmul	dword [0x41424344]
	fmul	st3
	fmul	st3, st0
	fmulp	st3
	fnop
	fpatan
	fprem
	fprem1
	fptan
	frndint
	frstor	[0x41424344]
	fsave	[0x41424344]
	fscale
	fsin
	fsincos
	fsqrt
	fst	dword [0x81828384]
	fst	qword [0x41424344]
	fst	st3
	fstcw	word [0x41424344]

	nop

	finit
	nop

	fimul	word [0x41424344]
	fimul	dword [0x81828384]
	fincstp
	fist	word [0x41424344]
	fistp	qword [0x41424344]
	fisub	word [0x41424344]
	fisub	dword [ebx]
	fisubr	dword [0x80818283]

	nop

	fild	word [0x41424344]
	fild	dword [0x81828384]
	fild	qword [0xf0f1f3f4]

	nop

	xor	eax, byte -4

	ficomp	dword [0xf0f0f0f0]
	ficom	word [0x41424344]
	fidiv	word [0x41424344]
	fidiv	dword [0x41424344]

	nop

	fiadd	word [0x41424344]
	fiadd	dword [0x41424344]

	nop

	fdivrp	st4
	fdivp	st4
	ffree	st2

	nop

	fdivr	st0, st4
	fdivr	dword [0x41424344]
	fdivr	qword [0x41424344]

	fcomip	st1
	fcomi	st2
	fcos
	fdecstp
	fcompp
	fdiv	st0, st0
	fdiv	st0, st4
	fdiv	st4, st0
	fdiv	dword [0x41424344]
	fdiv	qword [0x41424344]

	nop

	fcom	st6
	fcom	dword [0x41424344]
	fcom	qword [0x41424344]

	fcmovb	st4

	nop

	fbld	tword [0x41424344]
	fbstp	tword [0x41424344]
	fchs
	fclex

	nop

	faddp	st4

	nop

	fadd	dword [0x41424344]
	fadd	qword [0x41424344]
	fadd	st0, st0
	fadd	st4, st0
	fadd	st0, st4
	f2xm1
	fabs

	nop

	db	0x75
	db	0x1d

	db	0x80
	db	0x65
	db	0xd0
	db	0xc0

	db	0x80
	db	0x7d
	db	0xd0
	db	0xc0


	db	0x83
	db	0xc4
	db	0x41
	add	ecx, 0x41424344


	punpckhdq	mm1, mm0
	psubd	mm1, mm0

	pslld	mm1, mm0
	psllq	mm1, 12

	db	0x0f
	db	0xf5
	db	0xc0

	pcmpeqd	mm1, mm0
	pand	mm0, mm1

	paddw	mm0, mm1

	packssdw	mm0, mm1

	nop

	movq	mm0, [0x40414243]
	int3

	emms
	movq	mm0, mm1
	movd	mm0, ecx

	nop


	mov	eax, dword [bx + si + 0x0102]

	mov	bx, word [ebx]
	mov	cx, dx

	wait
	wbinvd
	wrmsr
	xadd	eax, ebx
	xadd	dl, cl
	xchg	eax, edx
	xchg	byte [eax], dl
	xlat
	xor	ebx, 0x41424344
	xor	byte [0x41424344], 0xf0

	nop

	shld	edx, eax, 12
	shrd	ebx, ecx, cl
	shr	eax, cl
	stc
	std
	sti
	stosd
	sub	eax, 8
	sub	ecx, edx
	test	al, 0xff

	db	0x0f
	db	0x0b
	verr	[eax]

	nop

	ret
	ret	0x0102
	rol	eax, 1
	rol	edx, cl
	ror	eax, 12
	rsm
	sahf
	sbb	eax, edx
	sbb	dl, 10
	scasb
	setz	al
	shl	ebx, cl

	nop

;	pop	cs	; uhh ohh

	pop	ds
	pop	gs
	popa
	popf
	pusha
	pushf
	rcl	ebx, 1
	rcl	eax, cl
	rcl	edx, 4
	rcr	ebx, 3
	rdmsr
	rdpmc
	rdtsc

	nop

	movsx	eax, dl
	movsb
	movsd
	movzx	edx, byte [0x41424344]
	mul	edx
	neg	al
	nop
	not	dword [0x41424344]
	or	edx, dword [4*eax + 0x41424344]
	out	0x60, al
	out	dx, eax
	pop	eax
	pop	dword [0x41424344]


	nop

	mov	cs, eax
	mov	ebx, ds
	mov	cs, word [0x41424344]
	mov	word [0x46474849], es
	mov	ss, ecx

	nop

	mov	cr0, eax
	mov	eax, cr1
	mov	dr6, edx
	mov	ecx, dr7

	nop

	lsl	ebx, [eax]
	mov	ebx, eax
	mov	cl, ch
	mov	dl, 0x61
	mov	edx, 0x61616161
	mov	[0x41424344], eax
	mov	eax, [0x81828384]

	nop

	lahf
	lar	eax, ebx
	lar	ecx, [eax]
	lea	eax, [4*ecx]
	leave
	nop
	lodsb
	loop	label2

	nop

	jns	label2
label2:	jmp	eax

	db	0xea
	dd	0x01020304
	dw	0x4041
	nop
	jmp	[eax]
	jmp	dword [0x41424344]

	nop

	in	eax, 0x60
	in	eax, dx
	inc	eax
	nop
	int3
	int	0x80
	iret

	nop

	enter	0x100, 1
	nop

	div	dl
	div	dword [0x41424344]

	nop
	dec	eax
	dec	dword [eax]
	dec	byte [0x41424344]
	nop

	cmpsb
	cmpsd
	cmpxchg	eax, ebx
	cmpxchg8b	[0x41424344]

	nop

	cmp	eax, 0x10203040


	cmp	eax, ebx
	cmp	al, bl

	nop

	cmovns	eax, ebx

	nop

	cbw
	cdq
	clc
	cld
	cli
	clts
	cmc

	call	label
	nop

	call	dword 0x08048000

label:

	btc	eax, ebx

	bt	eax, ebx
	nop
	bt	eax, 0x7f

	nop


	bsf	eax, ebx
	nop
	bsf	eax, [edx * 8]
	nop
	bswap	eax

	nop


	nop
	nop
	mov	[eax], ebx


doexit:	mov	eax, 1
	xor	ebx, ebx	; exit with level 0
	int	0x80

filesize	equ	($ - $$)


