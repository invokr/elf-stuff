
OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)

ENTRY(entry_point)

PHDRS
{
	text PT_LOAD FILEHDR PHDRS FLAGS (0x0007);	/* PF_R | PF_W | PF_X */
	data PT_LOAD FLAGS (0x0006);			/* PF_R | PF_W */
}

SECTIONS
{
	. = 0x05371000 ;
	.text : {
		cipher-glfsr.o(.text)
		init.o(.text)
		*(.text)
		*(.data)
		*(.rodata)
		*(.bss)
		callgate.o(.text)

		PROVIDE (be_stubhdr_u = ABSOLUTE(.)) ;
		LONG (0x41012345) ;
	} : text


	/* dummy segment to set fixed brk(0) value in kernelspace */
	. = 0x08048000 ;
	.data : {
	} : data

	/* save calls to objcopy, huh */
	/DISCARD/ : {
		*(.eh_frame)
		*(.comment)
		*(.note)
	}
}
