/* ia32-decode.h - ia32 decoding library
 * include file
 *
 * by scut
 */

#ifndef	IA32_DECODE_H
#define	IA32_DECODE_H

#define	IA32_VERSION	"0.4.0"

/*** IA32 constants
 */

/* the register value used to denote direct memory access in the mod r/m byte
 */
#define	IA32_RM_SIB		0x04
#define	IA32_MOD00_RM_DIRECT	0x05

#define	IA32_REG_EAX	0x00
#define	IA32_REG_ECX	0x01
#define	IA32_REG_EDX	0x02
#define	IA32_REG_EBX	0x03
#define	IA32_REG_ESP	0x04
#define	IA32_REG_EBP	0x05
#define	IA32_REG_ESI	0x06
#define	IA32_REG_EDI	0x07
#define	IA32_REG_COUNT	8

#define	IA32_MMX_SIZE	64

#define	IA32_FPU_SIZE	80
#define	IA32_FPU_BYTE	8
#define	IA32_FPU_ST0	0

#define	IA32_WIDTH_SPECIAL	0
#define	IA32_WIDTH_8	8
#define	IA32_WIDTH_16	16
#define	IA32_WIDTH_HALF	IA32_WIDTH_16
#define	IA32_WIDTH_32	32
#define	IA32_WIDTH_WORD	IA32_WIDTH_32
#define	IA32_WIDTH_64	64
#define	IA32_WIDTH_DOUBLE	IA32_WIDTH_64
#define	IA32_WIDTH_80	80
#define	IA32_WIDTH_FPU	IA32_FPU_SIZE


/* status flags */
#define IA32_EFLAGS_CF	0x00000001
#define IA32_EFLAGS_PF	0x00000004
#define IA32_EFLAGS_AF	0x00000010
#define IA32_EFLAGS_ZF	0x00000040
#define IA32_EFLAGS_SF	0x00000080
#define IA32_EFLAGS_OF	0x00000800

/* combined masks for convenience */
#define	IA32_EFLAGS_CFAF	(IA32_EFLAGS_CF | IA32_EFLAGS_AF)
#define	IA32_EFLAGS_CFOF	(IA32_EFLAGS_CF | IA32_EFLAGS_OF)
#define	IA32_EFLAGS_PFZFSF	(IA32_EFLAGS_PF | IA32_EFLAGS_ZF | \
	IA32_EFLAGS_SF)
#define	IA32_EFLAGS_CFAFOF	(IA32_EFLAGS_CF | IA32_EFLAGS_AF | \
	IA32_EFLAGS_OF)
#define	IA32_EFLAGS_PFZFSFOF	(IA32_EFLAGS_PF | IA32_EFLAGS_ZF | \
	IA32_EFLAGS_SF | IA32_EFLAGS_OF)
#define	IA32_EFLAGS_PFAFZFSFOF (IA32_EFLAGS_PF | IA32_EFLAGS_AF | \
	IA32_EFLAGS_ZF | IA32_EFLAGS_SF | IA32_EFLAGS_OF)
#define	IA32_EFLAGS_CFPFAFZFSFOF (IA32_EFLAGS_CF | IA32_EFLAGS_PF | \
	IA32_EFLAGS_AF | IA32_EFLAGS_ZF | IA32_EFLAGS_SF | IA32_EFLAGS_OF)
#define	IA32_EFLAGS_CFPFAFZFSF (IA32_EFLAGS_CF | IA32_EFLAGS_PF | \
	IA32_EFLAGS_AF | IA32_EFLAGS_ZF | IA32_EFLAGS_SF)

/* control and system flags */
#define IA32_EFLAGS_TF	0x00000100
#define IA32_EFLAGS_IF	0x00000200
#define IA32_EFLAGS_DF	0x00000400
#define IA32_EFLAGS_IOPL	0x00003000
#define IA32_EFLAGS_NT	0x00004000
#define IA32_EFLAGS_RF	0x00010000
#define IA32_EFLAGS_VM	0x00020000
#define IA32_EFLAGS_AC	0x00040000
#define IA32_EFLAGS_VIF	0x00080000
#define IA32_EFLAGS_VIP	0x00100000
#define IA32_EFLAGS_ID	0x00200000


#define	IA32_COND_O	0x00
#define	IA32_COND_NO	0x01
#define	IA32_COND_B	0x02
#define	IA32_COND_NAE	IA32_COND_B
#define	IA32_COND_NB	0x03
#define	IA32_COND_AE	IA32_COND_NB
#define	IA32_COND_E	0x04
#define	IA32_COND_Z	IA32_COND_E
#define	IA32_COND_NE	0x05
#define	IA32_COND_NZ	IA32_COND_NE
#define	IA32_COND_BE	0x06
#define	IA32_COND_NA	IA32_COND_BE
#define	IA32_COND_NBE	0x07
#define	IA32_COND_A	IA32_COND_NBE
#define	IA32_COND_S	0x08
#define	IA32_COND_NS	0x09
#define	IA32_COND_P	0x0a
#define	IA32_COND_PE	IA32_COND_P
#define	IA32_COND_NP	0x0b
#define	IA32_COND_PO	IA32_COND_NP
#define	IA32_COND_L	0x0c
#define	IA32_COND_NGE	IA32_COND_L
#define	IA32_COND_NL	0x0d
#define	IA32_COND_GE	IA32_COND_NL
#define	IA32_COND_LE	0x0e
#define	IA32_COND_NG	IA32_COND_LE
#define	IA32_COND_NLE	0x0f
#define	IA32_COND_G	IA32_COND_NLE

/* helper definitions, do make code more readable. not the desired form of
 * code recognition ;)
 */
#define	IA32_COND_MASK	0x0f
#define	IA32_OPCODE_JCC	0x70
#define	IA32_OPCODE_JECXZ	0xe3
#define	IA32_OPCODE_JMPN	0xeb
#define	IA32_OPCODE_JMPF	0xe9
#define	IA32_OPCODE_LOOP	0xe2
#define	IA32_OPCODE_LOOPZ	0xe1
#define	IA32_OPCODE_LOOPNZ	0xe0
#define	IA32_OPCODE_INT3	0xcc
#define	IA32_OPCODE_NOP		0x90


#define	IA32_PREFIX_CODE_LOCK	0xf0
#define	IA32_PREFIX_CODE_REPNE	0xf2
#define	IA32_PREFIX_CODE_REP	0xf3
#define	IA32_PREFIX_CODE_CS	0x2e
#define	IA32_PREFIX_CODE_SS	0x36
#define	IA32_PREFIX_CODE_DS	0x3e
#define	IA32_PREFIX_CODE_ES	0x26
#define	IA32_PREFIX_CODE_FS	0x64
#define	IA32_PREFIX_CODE_GS	0x65
#define	IA32_PREFIX_CODE_OPER	0x66
#define	IA32_PREFIX_CODE_ADDR	0x67

#define	IA32_INSTRUCTION_MAXLEN	17

/*** structure definitions
 */

/* ia32_prefix_e - single table element. always static and readonly
 */
typedef struct {
	char *		name;	/* prefix name */
	unsigned char	code;

#define	RELACT_OVERRIDE	1
#define	RELACT_COMBINE	2
	unsigned int	relact;	/* action to take when encountering prefix */
#define	PFX_RELOFS(selem) ((unsigned int)(&(((ia32_prefix *)(0))->selem)))
#define	PFX_ABS(str,relofs) ((unsigned int *)(((char *)(str))+(relofs)))
	unsigned int	relptr;	/* relative pointer into ia32_prefix struct */
	unsigned int	relval;	/* value to operate with */
} ia32_prefix_e;


/* ia32_prefix - decoded prefix
 */
typedef struct {
	unsigned int	length;		/* overall prefix length */
#define	IA32_PREFIX_MAX	15
	ia32_prefix_e *	prefix[16];	/* ptrs into prefix tab, NULL termtd */

	unsigned int	lock;		/* lock prefix used */
#define	IA32_PREFIX_REPNE	1
#define	IA32_PREFIX_REPNZ	IA32_PREFIX_REPNE
#define	IA32_PREFIX_REP		2
	unsigned int	rep;		/* rep prefixes */
#define	IA32_SEG_CS	0x01
#define	IA32_SEG_SS	0x02
#define	IA32_SEG_DS	0x04
#define	IA32_SEG_ES	0x08
#define	IA32_SEG_FS	0x10
#define	IA32_SEG_GS	0x20
#define	IA32_SEG_SIZE	16
	unsigned int	seg;		/* segment prefixes */

	unsigned int	oper_size;	/* operand size override */
	unsigned int	addr_size;	/* address size override */
} ia32_prefix;


/* ia32_opcode_e - opcode table element. always static and readonly.
 */
typedef struct {
#ifdef	IA32_OP_NUMERIC
	unsigned int	opcode_num;	/* opcode number */
#else
	const char *	name;		/* name of instruction */
	unsigned int	opcode_num;	/* opcode number */
#endif

	/* width flag applies to only the target operand, else to both,
	 * source and target (OD_WTONLY: movsx, ..) */
#define	OD_WTONLY	(1 << 0)
#define	OD_JUMP		(1 << 1)
#define	OD_IMM		(1 << 2)
#define	OD_IMMSIZE_MASK	0070
#define	OD_IMMSIZE_SET(n)	((n) << 3)
#define	OD_IMMSIZE_GET(fl)	((fl) & OD_IMMSIZE_MASK)
#define	OD_IMMSIZE_8	OD_IMMSIZE_SET(001)
#define	OD_IMMSIZE_16	OD_IMMSIZE_SET(002)
#define	OD_IMMSIZE_32	OD_IMMSIZE_SET(003)
#define	OD_IMMSIZE_WORD	OD_IMMSIZE_SET(004)
	/* hardcoded target register eax */
#define	OD_REG_HARD_EAX	(1 << 6)
#define	OD_REG12_REV	(1 << 7)
	/* contains full displacement (like immediate), for call */
#define	OD_IMM_DISPL	(1 << 8)
#define	OD_IMM_DISPL_8	(1 << 9)
#define	OD_IMM_DISPL_16	(1 << 10)
#define	OD_IMM_DISPL_WORD	(1 << 11)
#define	OD_IMM_OFFSET	(1 << 12)
	/* immediate selector (16 bit) */
#define	OD_IMM_SELECT	(1 << 13)
	/* OD_WIDTH_LOCK = do not modify the length after instruction
	 * processing. this is used when the length is more complex and has to
	 * be processed seperatly within the decoder. eg. when segment
	 * registers are moved, this is used.
	 */
#define	OD_WIDTH_LOCK	(1 << 14)
	/* OD_WIDTH_WIDE = always assume operations on the current wide size,
	 * 16 or 32 bits that is, depending on the cpu state. this can be
	 * overriden with prefixes.
	 *
	 * OD_WIDTH_16 = explicit 16 bit length
	 */
#define	OD_WIDTH_16	(1 << 15)
#define	OD_WIDTH_HALF	OD_WIDTH_16
#define	OD_WIDTH_WIDE	(1 << 16)
	/* double wide (64 bit, edx:eax) */
#define	OD_WIDTH_DWIDE	(1 << 17)
	/* kludge: _LWIDE = extend the last target operand to wordsize, after
	 * all swapping has taken place. required for extension instructions,
	 * such as movsx and movzx
	 */
#define	OD_WIDTH_LWIDE	(1 << 18)
	/* _WIDTH_FPU = make the single operand the size of the
	 * FPU word (tword)
	 */
#define	OD_WIDTH_FPU	(1 << 19)
	/* _CR = the special registers in the opcode are CR regs */
#define	OD_CR		(1 << 20)
	/* _DR = the special registers in the opcode are DR regs */
#define	OD_DR		(1 << 21)
#define	OD_MMX		(1 << 22)
	/* reg in (mod mmxreg reg) is no MMX register
	 */
#define	OD_REGNOMMX	(1 << 23)
	/* OD_GG_* is only used when there is no OD_GG field within the
	 * instruction.
	 */
#define	OD_GG_GET(fl)	(((fl) >> 24) & 0x07)
#define	OD_GG_SET(m)	((m & 0x7) << 24)
#define	OD_GG_B		OD_GG_SET(0x00)
#define	OD_GG_W		OD_GG_SET(0x01)
#define	OD_GG_D		OD_GG_SET(0x02)
#define	OD_GG_Q		OD_GG_SET(0x03)
#define	OD_GG_IN_LOW	(1 << 27)
#define	OD_GG_IN_HI	(1 << 28)
	/* FPU related options
	 */
#define	OD_FPU		(1 << 29)
#define	OD_FPU_WITH_ST0	OD_REG_HARD_EAX

	/* _CONTROL = this instruction directly affects execution flow.
	 * included are gate and similar instructions, that also change context
	 */
#define	OD_CONTROL	(1 << 30)
	unsigned int	flags;

	/* main opcode encoding specifications
	 * structure:
	 *
	 * ++++.++++.++++.++++.++++.++++.++++.++++
	 * |                   <-cmask-> <-cval ->
	 * |
	 * |
	 * +--- OD_END marker, exclusivly set
	 */
	unsigned int	opc[8];
#define	OD_END		(1 << 31)
#define	OD_CMASK	0x0000ff00
#define	OD_CVAL		0x000000ff
#define	OD_CVAL_GET(o)	((o) & OD_CVAL)
#define	OD_CMASK_SET(m)	((m) << 8)
#define	OD_CMASK_GET(o)	(((o) & OD_CMASK) >> 8)
	/* common cases of masks */
#define	OD_FIX		OD_CMASK_SET(0xff)
#define	OD_FIX_2	OD_CMASK_SET(0xc0)
#define	OD_FIX_4	OD_CMASK_SET(0xf0)
#define	OD_FIX_5	OD_CMASK_SET(0xf8)
#define	OD_FIX_543	OD_CMASK_SET(0x38)
#define	OD_FIX_6	OD_CMASK_SET(0xfc)
#define	OD_FIX_7	OD_CMASK_SET(0xfe)
#define	OD_FIX_68	OD_CMASK_SET(0xfd)
#define	OD_FIX_N2	OD_CMASK_SET(0xfb)
#define	OD_TEST(o,f)	(((o) & (f)) == (f))
	/* has w flag (bit 0) */
#define	OD_W		(1 << 16)
#define	OD_W_MASK	0x01
	/* has w flag (as bit 3), eg. mov */
#define	OD_W3		(1 << 17)
#define	OD_W3_MASK	0x08
	/* has d flag (bit 1) */
#define	OD_D		(1 << 18)
#define	OD_D_MASK	0x02
	/* has s flag (bit 1) */
#define	OD_S		(1 << 19)
#define	OD_S_MASK	0x02
	/* has tttn flags (bits 3210) */
#define	OD_TTTN		(1 << 20)
#define	OD_TTTN_MASK	0x0f
	/* has mod specifier (bits 76) */
#define	OD_MOD		(1 << 21) 
#define	OD_MOD_MASK	0xc0
	/* has r/m specifier (bits 210) */
#define	OD_RM		OD_MOD
#define	OD_RM_MASK	0x07
	/* reg1 given (bits 543) */
#define	OD_REG1		(1 << 22)
	/* reg2 given (bits 210) */
#define	OD_REG2		(1 << 23)
#define	OD_REG2_MASK	0x07
#define	OD_REG12	(OD_REG1 | OD_REG2)
	/* lreg = lower register, for simple instructions, bits 210 */
#define	OD_LREG		OD_REG2
#define	OD_LREG_MASK	OD_REG2_MASK
	/* normal register position for mod reg r/m */
#define	OD_REG		OD_REG1
#define	OD_REG_MASK	0x38
#define	OD_REG_SHIFT	3
#define	OD_MODREGRM	(OD_MOD | OD_REG | OD_RM)
#define	OD_MODRM	(OD_MOD | OD_RM)

	/* sreg2, bits 43 */
#define	OD_SREG2	(1 << 24)
#define	OD_SREG2_MASK	0x18
#define	OD_SREG2_SHIFT	3
	/* sreg3, bits 543 */
#define	OD_SREG3	(1 << 25)
#define	OD_SREG3_MASK	OD_REG_MASK
#define	OD_SREG3_SHIFT	OD_SREG2_SHIFT
	/* special purpose register field, bits 543 */
#define	OD_EEE		(1 << 26)
#define	OD_EEE_MASK	0x38
#define	OD_EEE_SHIFT	3

	/*** MMX flags
	 * gg granularity field, bits 10
	 */
#define	OD_GG		(1 << 27)
#define	OD_GG_MASK	0x03

	/*** FPU flags
	 * d destination flag (0 = destination is ST(0), 1 = dest. is ST(i)),
	 * bit 2
	 */
#define	OD_FPU_D	(1 << 28)
#define	OD_FPU_D_MASK	0x04
#define	OD_FPU_D_SHIFT	2
#define	OD_FPU_R	(1 << 29)
#define	OD_FPU_R_MASK	0x08
#define	OD_FPU_R_SHIFT	3
	/* sti register selection, bits 210 */
#define	OD_FPU_STI	(1 << 30)
#define	OD_FPU_STI_MASK	0x07

	/* dataflow relevant information about instructions register usage.
	 *
	 * df_srctgt = usage/definition for source/destination operands
	 * df_implicit = instruction-implicit usage/definition of registers
	 */
#define	IA32_DF_DEF_SOURCE	(1 << 0)
#define	IA32_DF_USE_SOURCE	(1 << 1)
#define	IA32_DF_DEF_TARGET	(1 << 2)
#define	IA32_DF_USE_TARGET	(1 << 3)
#define	IA32_DF_USE_FLAGS_COND	(1 << 4)
	unsigned int	df_srctgt;
#define	IA32_DF_DEF(reg)	(1 << IA32_REG_##reg)
#define	IA32_DF_DEF_REGMASK(elem)	((elem) & 0xff)
#define	IA32_DF_DEF_FLAGS(efl)	((efl) << 8)
#define	IA32_DF_DEF_GET_FLAGS(impl)	((impl) >> 8)
	unsigned int	df_implicit_def;
#define	IA32_DF_USE(reg)	(1 << IA32_REG_##reg)
#define	IA32_DF_USE_FLAGS(efl)	((efl) << 8)
#define	IA32_DF_USE_GET_FLAGS(impl)	((impl) >> 8)
	unsigned int	df_implicit_use;
} ia32_opcode_e;

#define	OD_SET_COND(in,mask) ((((in) & (mask)) != 0) ? 1 : 0)


/* ia32_opcode - decoded opcode
 */
typedef struct {
	unsigned int	length;	/* total length, from opcode to next prefix */
	ia32_opcode_e *	opcode;	/* pointer into opcode table */

	/* stored here for convenience of lower level decoding functions
	 */
	unsigned char	modbyte,
			sibbyte;

#define	OP_SOURCE	(1 << 0)
#define	OP_TARGET	(1 << 1)
#define	OP_IMMEDIATE	(1 << 2)
#define	OP_DISPLACE	(1 << 3)
#define	OP_SIB		(1 << 4)
#define	OP_JUMP		(1 << 5)
#define	OP_COND		(1 << 6)
#define	OP_SELECTOR	(1 << 7)
#define	OP_CONTROL	(1 << 8)
	unsigned int	used;	/* what kind of elements from below are used */

	unsigned int	cond;	/* in case of a conditional instruction */

	/* when this is set, the order of source/target operands was reversed
	 * in the instruction. however, the source_* and target_* values below
	 * always denote the real source and target. this can be used for
	 * re-encoding the instruction though :)
	 */
	unsigned int	reversed;

	/* when a W flag was present in the instruction, this is copied over.
	 * this is necessary to not lose information when decoding instructions
	 * without explicit source/target operands, such as lods, movs, which
	 * could be lods[bd].
	 */
	unsigned int	wide;

#define	OP_TYPE_UNUSED	0x00
#define	OP_TYPE_REG	0x01
	/* _MEM = SIB addressing
	 * _MEMABS = one 32 bit offset
	 * _MEMREG = normal non-SIB addressing
	 */
#define	OP_TYPE_MEM	0x02
#define	OP_TYPE_MEMABS	0x03
#define	OP_TYPE_MEMREG	0x04
	/* _IMM = immediate data
	 * _DISPL = displacement, for call/jump
	 * _OFFSET = wide offset in immidiate
	 * _SPECIAL = special register or other
	 */
#define	OP_TYPE_IMM	0x05
#define	OP_TYPE_DISPL	0x06
#define	OP_TYPE_OFFSET	0x07
	/* _CR = control registers (cr0-cr4)
	 * _DR = debug registers (dr0-dr7)
	 * _SEG = segment registers (0-7, es,cs,ss,ds,fs,gs,reserved,reserved
	 */
#define	OP_TYPE_SPEC_CR	0x08
#define	OP_TYPE_SPEC_DR	0x09
#define	OP_TYPE_SPEC_SEG	0x0a
#define	OP_TYPE_SPEC_MMX	0x0b
#define	OP_TYPE_FPU	0x0c
	unsigned int	source_type;	/* source operand type */
	unsigned int	source_reg;
	unsigned int	source_width;	/* 32, 16 or 8 (bits) */
	unsigned int	target_type;
	unsigned int	target_reg;
	unsigned int	target_width;	/* 32, 16 or 8 (bits) */

	/* SIB byte, addr = base + (scale * index) */
	unsigned int	scale;		/* 0,1,2,3 */
	unsigned int	index;		/* index used? 0/1 */
	unsigned int	index_reg;	/* index = 1: register number */
	unsigned int	base;		/* base used? 0/1 */
	unsigned int	base_reg;	/* base = 1: register number */

	/* displacement */
	unsigned int	displ_size;
	unsigned int	displ_value;
	unsigned short	selector;	/* 16 bit word selector */

	/* immediate data, also used for offset (32) and levels (8 bit) */
	unsigned int	imm_size;
	unsigned int	imm_value;
} ia32_opcode;


/* ia32_instruction - one single instruction, made up from a prefix and an
 * opcode
 */
typedef struct {
	void *		user;	/* user-data pointer, never touched, except on
				 * initialization
				 */
	int		length;	/* pfx->length + opc->length */
	ia32_prefix	pfx;
	ia32_opcode	opc;
} ia32_instruction;


#ifdef	IA32_OP_NUMERIC
#define	IA32_OP(name)	IA32_OP_##name
#else
#define	IA32_OP(name)	#name, IA32_OP_##name
#endif


/*** function prototypes
 */

/* ia32_decode_instruction
 *
 * decode a single instruction at `input'. when `new' is non-NULL it will be
 * recycled, otherwise one ia32_instruction structure is allocated.
 *
 * return pointer to decoded structure on success
 * return NULL on failure
 */

ia32_instruction *
ia32_decode_instruction (unsigned char *input, ia32_instruction *new);


/* ia32_decode_prefix
 *
 * decode the beginning of an instruction at `input', trying to locate prefix
 * bytes. when `new' is NULL, a new structure will be allocated, else the old
 * one will be recycled, the old data is lost.
 *
 * return a pointer to the prefix structure on success
 * return NULL when no prefix has been found
 */

ia32_prefix *
ia32_decode_prefix (unsigned char *input, ia32_prefix *new);


/* ia32_decode_opcode
 *
 * decode the opcode part of an instruction at `input' into an ia32_opcode
 * structure. if `new' is non-NULL it will be resetted and recycled, else
 * a new structure is allocated. the prefix part of the instruction can be
 * passed through the `pfx' pointer, and is used to obey size prefixes. when
 * NULL is passed, the default lengths are used.
 *
 * return a pointer to the decoded opcode structure
 */

ia32_opcode *
ia32_decode_opcode (unsigned char *input, ia32_opcode *new,
	ia32_prefix *pfx);


/* ia32_decode_value
 *
 * decode immediate data at `input' into a host-independant integer at `value'.
 * the data read from `input' is `bits' bits long. the only correct values are
 * 8, 16 or 32.
 *
 * return number of bytes processed
 */

unsigned int
ia32_decode_value (unsigned char *input, unsigned int bits,
	unsigned int *value);


/* ia32_encode_value
 *
 * encode the number `value' within `bits' number of bits to `output'.
 *
 * return in any case
 */

void
ia32_encode_value (unsigned char *output, unsigned int bits,
	unsigned int value);


/* ia32_has_immediate
 *
 * same as _has_displacement, just for immediate values.
 * look through the instruction `inst' for immediate values, writing the size
 * of the immediate in bits to `imm_size', when non-NULL.
 *
 * return 0 if there is no immediate present in the instruction
 * return the position of the immediate relative to the beginning of the
 *   instruction (0 is not legal, 1 is the second byte of the instruction)
 */

unsigned int
ia32_has_immediate (ia32_instruction *inst, unsigned int *imm_size);


/* ia32_has_displacement
 *
 * look through the instruction `inst' for displacements, writing the size of
 * the displacement in bits to `displ_size', when non-NULL.
 *
 * return 0 if there is no displacement present in the instruction
 * return the position of the displacement relative to the beginning of the
 *   instruction (0 is not legal, 1 is the second byte of the instruction)
 */

unsigned int
ia32_has_displacement (ia32_instruction *inst, unsigned int *displ_size);


/* ia32_extend_signed
 *
 * extend the number `value', from which only the least significant
 * `value_bits' bits are used to a 32 bit unsigned number. extend the sign
 * properly (msb of value with only value_bits).
 *
 * return the number in any case.
 */

unsigned int
ia32_extend_signed (unsigned int value, unsigned int value_bits);


/* ia32_eflags_mask_from_cond
 *
 * given the 4 bit condition code `cond' (tttn form), find the status flags
 * that are considered during evaluation.
 *
 * return mask of status flags that is part of the evaluation
 */

unsigned int
ia32_eflags_mask_from_cond (unsigned int cond);


/* ia32_eflags_eval
 *
 * evaluate condition code `cond' and extended flag register `eflags'.
 *
 * return 1 if the condition would be true with that eflags
 * return 0 if it would be false
 */

int
ia32_eflags_eval (unsigned int eflags, unsigned int cond);


/* ia32_bit_to_byte
 *
 * simple utility function. conversion of `bits' into number of bytes. only
 * values of 32, 16 and 8 are supported.
 *
 * return number of bytes for `bits'
 */

unsigned int
ia32_bit_to_byte (unsigned int bits);


/* ia32_opcode_find_bynum
 *
 * find the first opcode structure belonging to `opcode'.
 *
 * return NULL on failure
 * return opcode structure pointer on success
 */

ia32_opcode_e *
ia32_opcode_find_bynum (unsigned int opcode);


/* ia32_instruction_count
 *
 * count the number of instructions assigned to `opcode'.
 *
 * return the count
 */

unsigned int
ia32_instruction_count (unsigned int opcode);


/* ia32_instruction_length
 *
 * utility function, determine the length of the instruction at `mem'.
 *
 * return the length in any case
 */

unsigned int
ia32_instruction_length (unsigned char *mem);


/* ia32_instruction_advance
 *
 * advance `count' instructions starting from `mem' by disassembling each
 * instruction and skipping over it. utility function for easier instruction
 * level access.
 *
 * return pointer to `count'th instruction behind `mem'
 */

unsigned char *
ia32_instruction_advance (unsigned char *mem, unsigned int count);


/* ia32_opnum_index
 *
 * return the relative opcode index for the opcode number `opcode' on success
 * return -1 on failure
 */

int
ia32_opnum_index (unsigned int opcode);


/* ia32_opcode_has_immediate
 *
 * return 1 if there is an encoding for `opcode' that provides immediate
 *    values using a width between `min_size' and `max_size'
 * return 0 if there is no such encoding
 */

int
ia32_opcode_has_immediate (unsigned int opcode, unsigned int min_size,
	unsigned int max_size);


#ifndef	IA32_OP_NUMERIC

/* ia32_opnum_name
 *
 * find the mnemonical name of the opcode index `opnum'.
 *
 * return name on success
 * return NULL on failure
 */

const char *
ia32_opnum_name (unsigned int opnum);

#endif

/* ia32_print
 *
 * print a string representation of the instruction `inst' to stdout.
 *
 * return number of characters printed (like printf does)
 */

int
ia32_print (ia32_instruction *inst);


/* ia32_sprint
 *
 * print a string representation of the instruction `inst' to string buffer
 * `buf', which is `buf_len' bytes long.
 *
 * return number of bytes used within `buf'
 */

unsigned int
ia32_sprint (ia32_instruction *inst, char *buf, unsigned int buf_len);

#endif


