
	BITS 32

	org	0x08048000

ehdr:					; Elf32_Ehdr
	db      0x7F, "ELF", 1, 1, 1	;  e_ident
	times 9	db	0
	dw	2			;  e_type
	dw	3			;  e_machine
	dd	1			;  e_version
	dd	_start			;  e_entry
	dd	phdr - $$		;  e_phoff
	dd	0			;  e_shoff
	dd	0			;  e_flags
	dw	ehdrsize		;  e_ehsize
	dw	phdrsize		;  e_phentsize
	dw	1			;  e_phnum
	dw	0			;  e_shentsize
	dw	0			;  e_shnum
	dw	0			;  e_shstrndx

ehdrsize	equ	($ - ehdr)

phdr:				; Elf32_Phdr
	dd	1		;  p_type
	dd	0		;  p_offset
	dd	$$		;  p_vaddr
	dd	$$		;  p_paddr
	dd	filesize	;  p_filesz
	dd	filesize	;  p_memsz
	dd	5		;  p_flags
	dd	0x1000		;  p_align

phdrsize	equ	($ - phdr)

; fd 0 = random file
; fd 1 = output file
_start:
;	int3

	mov	ebx, [esp + 4]	; pathname
	mov	ecx, 1		; mode = O_WRONLY
	xor	edx, edx	; flags = 0
	mov	eax, 5		; __NR_open
	int	0x80		; fd will be 1, hopefully

	; get output file length
	xor	ecx, ecx	; ecx = offset = 0
	mov	edx, 2		; edx = SEEK_END = 2
	mov	ebx, 1		; ebx = out_fd = 1
	mov	eax, 19		; __NR_lseek
	int	0x80

	shr	eax, 10		; / 1024
	inc	eax		; round up to next boundary
	push	eax		; file length / 1024

	mov	ebp, 0x07
cloop:	pop	eax
	push	eax
	push	eax		; create a copy of the file length
	; 1. overwrite
	; lseek (1, 0, SEEK_SET);
	xor	ecx, ecx	; ecx = offset = 0
	xor	edx, edx	; edx = SEEK_SET = 0
	mov	ebx, 1		; ebx = out_fd = 1
	mov	eax, 19		; __NR_lseek
	int	0x80

wloop:	sub	esp, 1024 + 4
	mov	ebx, 0		; ebx = in_fd = 0
	mov	ecx, esp	; temp space on stack
	mov	edx, 1024	; read 1024 bytes a time
	mov	eax, 3		; __NR_read
	int	0x80

	mov	ebx, 1		; ebx = out_fd = 1
	mov	ecx, esp	; buffer
	mov	edx, 1024	; edx = write 1024 bytes
	mov	eax, 4		; __NR_write
	int	0x80

	add	esp, 1024 + 4	; yea, fsck with the cache %-/

	pop	eax
	dec	eax		; remaining 2^10 pages to clear
	push	eax
	jnz	wloop

	pop	eax

	; 2. sync
	mov	eax, 36		; __NR_sync
	int	0x80

	; 3. loop
	dec	ebp		; number of remaining passes
	jnz	cloop

	pop	eax		; original file length / 1024

	; 4. unlink
	pop	eax		; argc (should be 2)
	pop	ebx		; ebx = unlink-stub
	push	ebx
	mov	eax, 10		; __NR_unlink
	int	0x80


	pop	edx		; pathname
	pop	ebx
	push	edx
	mov	eax, 10
	int	0x80

	pop	ecx		; newpath = pathname
	pop	ebx		; oldpath = .sl filename
	or	ebx, ebx
	jz	doexit
	mov	eax, 38
	int	0x80

doexit:	mov	eax, 1
	xor	ebx, ebx	; exit with level 0
	int	0x80

flen	dd	0
flenl	dd	0

filesize	equ	($ - $$)


