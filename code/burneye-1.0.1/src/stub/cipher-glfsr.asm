; minimalistic size-optimized cipher 'glfsr'
;
; using one single 32 bit galois linear feedback shifting register with a
; fixed tap sequence. can be broken easily but its better than the
; standard xor cipher and it looks neat, takes only ~25 bytes of code ;)

%ifdef IN_STUB
	GLOBAL	glent

glen:	dd	0x00000000
gkey:	dd	0x00000000
gnent:	dd	0x00000000

	db	'TEEE burneye - TESO ELF Encryption Engine'

glent:;	int3
	push	dword [gnent]
	pushf
	pusha
	mov	ecx, [glen]
	jmp	hunk
hret:	pop	esi
	mov	edi, esi
	mov	ebx, [gkey]

	or	ebx, ebx	; zero key = skip, used for SEAL mode
	jz	hcont
%else
	GLOBAL	glfsr_crypt	; glfsr_crypt (uchar *dst, uchar *src, int len, int key)

glfsr_crypt:
	push	ebp
	mov	ebp, esp
	pusha
	mov	edi, dword [ebp + 8]
	mov	esi, dword [ebp + 12]
	mov	ecx, dword [ebp + 16]
	mov	ebx, dword [ebp + 20]
%endif

; esi = source
; edi = dest (can overlap/be the same) with source
; ecx = number of bytes
; ebx = 32 bit key

	xor	edx, edx
glls:	mov	eax, 8
gll0:	shrd	edx, ebx, 1		; edx = >>output, ebx = |lfsr|
	shr	ebx, 1			; cf = lfsr[0]
	jnc	gll1			; == 1 ?
	xor	ebx, 0xc0000057		; binary tap sequence
gll1:	dec	eax
	jnz	gll0
	shr	edx, 32 - 8		; take highest 8 bits
	lodsb
	xor	al, dl
	stosb
	dec	ecx
	jnz	glls

%ifdef IN_STUB
hcont:	popa
	popf
	ret

hunk:	call	hret
%else
%ifdef CONSERVE_SPACE
	popa
	pop	ebp
	ret	16
%else
	popa
	pop	ebp			; only restore, no stack space
	ret
%endif
%endif


