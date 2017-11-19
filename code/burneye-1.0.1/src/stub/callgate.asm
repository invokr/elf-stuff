; call gate transition

	GLOBAL	cg_entry

	EXTERN	cg_decrypt
	EXTERN	cg_find


	struc	callgate
sav0:	resd	1
sav4:	resd	1
ra_sav:	resd	1
ar_beg:	resd	1
ar_len:	resd	1
keyptr:	resd	1
	endstruc

; the central call gate jump-point
;
; we are called by an encrypted function if we land here. we have to restore
; its encrypted state, then decrypt it. afterwards we optionally setup a trap
; return address that will return into a re-encryption function.
;

; 0x0000: 0x50				push	%eax	== gate address
; 0x0001: 0x60				pusha  
; 0x0002: 0x9c				pushf
; 0x0003: 0xe8 0x00 0x00 0x00 0x00	call	cg_entry

cg_entry:
;	int	0x03
	push	eax
	pusha
	pushf
	call	cg_foo
	ret
	nop
	nop

cg_foo:
	pop	esi
	sub	esi, 8

	push	esi
	call	cg_find			; in: esi, out: eax = struct *
	add	esp, dword 4

	; restore bytes taken by the gate
	mov	edx, [eax + sav0]
	mov	[esi], edx
	mov	edx, [eax + sav4]
	mov	[esi + 4], edx

	; save real return address, overwrite with encryption gate addr, yay!
	mov	edx, [esp + 0x28]
	mov	[eax + ra_sav], edx
	mov	[esp + 0x28], dword cg_encryptgate

	; decrypt the whole encrypted function
	push	eax
	call	cg_decrypt
	add	esp, dword 4

	mov	[esp + 0x24], esi	; overwrite dummy eax value
	popf
	popa
	ret

cg_encryptgate:
	ret

