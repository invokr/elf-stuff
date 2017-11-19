/* ia32-encode.c - ia32 instruction encoding
 *
 * by scut
 *
 * XXX: note, this is just very basic at the moment
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <ia32-decode.h>
#include <ia32-encode.h>

#include <ia32_opcodes.h>

/* from ia32-decode.c */
extern ia32_opcode_e ia32_opcode_table[];


/*** STATIC PROTOTYPES */

/* ia32_encode_instruction_try
 *
 * try encoding the instruction `inst' to memory `dest'.
 *
 * return zero on failure
 * return length of complete instruction (prefix and opcode) on success
 */

static unsigned int
ia32_encode_instruction_try (ia32_instruction *inst, unsigned char *dest);


/*** IMPLEMENTATION */

unsigned int
ia32_encode_instruction (unsigned int inst_num, ia32_instruction *inst,
	unsigned char *dest)
{
	unsigned int	in,	/* instruction list walker */
			len;

	if (inst_num == IA32_OP_rcr || inst_num == IA32_OP_rcl)
		printf ("foo\n");

	for (in = 0 ; ia32_opcode_table[in].opcode_num != 0 ; ++in) {
		if (ia32_opcode_table[in].opcode_num != inst_num)
			continue;

		inst->opc.opcode = &ia32_opcode_table[in];
		len = ia32_encode_instruction_try (inst, dest);
		if (len > 0)
			return (len);
	}

	printf ("failed at opcode %d, \"%s\" (t: %d, s: %d)\n",
		inst_num, inst->opc.opcode->name, inst->opc.target_reg,
		inst->opc.source_reg);

	return (0);
}


/* rather incomplete. will grow over time
 */
static unsigned int
ia32_encode_instruction_try (ia32_instruction *inst, unsigned char *dest)
{
	unsigned int	dn = 0,	/* relative dest buffer offset */
			bp;
	int		did_source = 0,
			did_target = 0;
	unsigned int	source_reg,
			target_reg;
	ia32_opcode_e *	oel = inst->opc.opcode;

	/* 1. prefix
	 */
	if (inst->pfx.lock)
		dest[dn++] = IA32_PREFIX_CODE_LOCK;

	switch (inst->pfx.rep) {
	case (IA32_PREFIX_REPNE):
		dest[dn++] = IA32_PREFIX_CODE_REPNE;
		break;
	case (IA32_PREFIX_REP):
		dest[dn++] = IA32_PREFIX_CODE_REP;
		break;
	default:
		break;
	}

	if (inst->pfx.oper_size)
		dest[dn++] = IA32_PREFIX_CODE_OPER;

	if (inst->pfx.addr_size)
		dest[dn++] = IA32_PREFIX_CODE_ADDR;

	/* 2. TODO: set displacement/immediate size according to prefix */

	if ((OD_TEST (oel->flags, OD_IMM) == 0 &&
		inst->opc.source_type == OP_TYPE_IMM) ||
		(OD_TEST (oel->flags, OD_IMM) &&
		inst->opc.source_type != OP_TYPE_IMM))
	{
		return (0);
	}

	if (OD_TEST (oel->flags, OD_IMM_DISPL) ||
		OD_TEST (oel->flags, OD_IMM_OFFSET) ||
		OD_TEST (oel->flags, OD_IMM_OFFSET) ||
		OD_TEST (oel->flags, OD_CONTROL))
		return (0);

	if (OD_TEST (oel->flags, OD_REG_HARD_EAX)) {
		if (inst->opc.target_reg != IA32_REG_EAX)
			return (0);

		did_target = 1;
	}
	if (inst->opc.source_type == OP_TYPE_IMM) {
		if (inst->opc.imm_size != IA32_WIDTH_32)
			return (0);

		inst->opc.wide = 1;
	}

	if (OD_TEST (oel->flags, OD_REG12_REV)) {
		inst->opc.reversed = 1;
		source_reg = inst->opc.target_reg;
		target_reg = inst->opc.source_reg;
	} else {
		source_reg = inst->opc.source_reg;
		target_reg = inst->opc.target_reg;
	}

	assert (inst->opc.target_type == OP_TYPE_REG &&
		(inst->opc.source_type == OP_TYPE_REG ||
		inst->opc.source_type == OP_TYPE_IMM));

	for (bp = 0 ; oel->opc[bp] != OD_END ; ++bp) {
		unsigned int	oc;
		unsigned char	db;

		oc = oel->opc[bp];
		db = (oc & 0xff) & ((oc & 0xff00) >> 8);

		if (OD_TEST (oc, OD_W))
			db |= inst->opc.wide ? OD_W_MASK : 0x00;
		else if (OD_TEST (oc, OD_W3))
			db |= inst->opc.wide ? OD_W3_MASK : 0x00;

		/* TODO: S flag */
		/* TODO: D flag */

		if (OD_TEST (oc, OD_LREG)) {
			if (OD_TEST (oel->flags, OD_REG_HARD_EAX)) {
				db |= source_reg;
				did_source = 1;
			} else {
				db |= target_reg;
				did_target = 1;
			}
		}

		if (OD_TEST (oc, OD_MOD)) {
			if (inst->opc.source_type == OP_TYPE_IMM) {
				db |= OD_MOD_MASK;	/* 11b = reg/reg */
				if (OD_TEST (oc, OD_REG)) {
					db |= source_reg << OD_REG_SHIFT;
					did_source = 1;
				}
			} else {
				db |= OD_MOD_MASK;	/* 11b = reg/reg */
				if (OD_TEST (oc, OD_REG)) {
					db |= source_reg << OD_REG_SHIFT;
					did_source = 1;
				}
			}

			/* set bits 210 (OD_REG2) */
			db |= target_reg;
			did_target = 1;
		}

		dest[dn++] = db;
	}

	if (inst->opc.source_type == OP_TYPE_IMM) {
		ia32_encode_value (&dest[dn], inst->opc.imm_size,
			inst->opc.imm_value);
		dn += ia32_bit_to_byte (inst->opc.imm_size);
	}
#if 0
	if (did_source == 0 || did_target == 0)
		return (0);
#endif

	return (dn);
}


