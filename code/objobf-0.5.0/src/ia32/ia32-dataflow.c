/* ia32-dataflow.c - ia32 dataflow analysis
 *
 * by scut
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <common.h>
#include <ia32-decode.h>
#include <ia32-trace.h>
#include <ia32-function.h>
#include <ia32-dataflow.h>
#include <ia32_opcodes.h>


ia32_df_abi_hook_type ia32_df_abi_hook = (void *) NULL;

static void
ia32_df_add_source_to_set (unsigned int *dest, ia32_instruction *inst);

static void
ia32_df_add_target_to_set (unsigned int *dest, ia32_instruction *inst);

static void
ia32_df_add_target_to_set_def (unsigned int *dest, ia32_instruction *inst);


static int
ia32_df_regmask_oper_def (unsigned int oper_type, unsigned int reg,
	unsigned int oper_width, ia32_instruction *inst);

static int
ia32_df_regmask_oper_use (unsigned int oper_type, unsigned int reg,
	unsigned int oper_width, ia32_instruction *inst);

extern char * ia32_regs_wide[];


/*** main dataflow (live register) analysis functions */


void
ia32_df_bbtree_live (ia32_function *func, ia32_bblock *root)
{
	int		changed,
			bbn,	/* basic block index walker */
			succn;	/* sucessor basic block index walker */
	ia32_bblock **	all;
	unsigned int	all_count;
	unsigned char *	bb_mem;
	unsigned int	un_succ_in;	/* union of successors in sets */
	ia32_df_set *	succ_first;


	all = ia32_br_get_all (root, &all_count);

	/* free live register data
	 */
	if (func->livereg_available) {
		return;
#if 0
		for (bbn = 0 ; bbn < all_count ; ++bbn) {
			assert (all[bbn]->user != NULL);
			ia32_df_bblock_destroy
				((ia32_df_bblock *) all[bbn]->user->dfb);
			all[bbn]->user->dfb = NULL;
		}
#endif
	}

	do {
		changed = 0;

		for (bbn = 0 ; bbn < all_count ; ++bbn) {
			bb_mem = func->mem - func->start + all[bbn]->start;

			/* build union of successors in sets
			 */
			un_succ_in = 0;
			for (succn = 0 ; succn < all[bbn]->endbr_count ; ++succn) {

				/* do not process external basic blocks
				 */
				if (all[bbn]->endbr_external != NULL &&
					all[bbn]->endbr_external[succn] != 0)
				{
					continue;
				}

				succ_first = ia32_df_bblock_first
					(all[bbn]->endbr[succn]);
				if (succ_first)
					un_succ_in |= succ_first->in;
			}

			if (ia32_df_bblock_live (all[bbn], un_succ_in, bb_mem))
				changed = 1;
		}
	} while (changed);

	func->livereg_available = 1;

	free (all);
}


int
ia32_df_bblock_live (ia32_bblock *bb, unsigned int last, unsigned char *mem)
{
	int			changed,
				once_changed = 0;	/* return value */
	ia32_df_bblock *	dfb;
	unsigned int		inst_idx;	/* instruction index */


	assert (bb != NULL);
	dfb = (ia32_df_bblock *) bb->user->dfb;
	if (dfb == NULL) {
		dfb = ia32_df_bblock_new (bb, mem);
		bb->user->dfb = (void *) dfb;
	}

	/* algorithm 10.4 (live variable analysis) from "compilers" (the
	 * dragon book)
	 */
	do {
		changed = 0;

		for (inst_idx = 0 ; inst_idx < dfb->df_count ; ++inst_idx) {
			unsigned int	next_in,
					old_in;

			/* the last element of the instruction array?
			 */
			if ((inst_idx + 1) == dfb->df_count)
				next_in = last;
			else
				next_in = dfb->df[inst_idx + 1].in;

			dfb->df[inst_idx].out = next_in;

			old_in = dfb->df[inst_idx].in;
			dfb->df[inst_idx].in = dfb->df[inst_idx].use |
				(dfb->df[inst_idx].out & ~dfb->df[inst_idx].def);

			/* in changed, mark this so propagation can continue
			 */
			if (old_in != dfb->df[inst_idx].in)
				changed = 1;
		}

		if (changed)
			once_changed = 1;

	} while (changed);

	return (once_changed);
}


ia32_df_bblock *
ia32_df_bblock_copy (ia32_df_bblock *dfb)
{
	ia32_df_bblock *	new;


	if (dfb == NULL)
		return (NULL);

	new = xcalloc (1, sizeof (ia32_df_bblock));
	new->df_count = dfb->df_count;
	new->df = xcalloc (new->df_count, sizeof (ia32_df_set));
	memcpy (new->df, dfb->df, new->df_count * sizeof (ia32_df_set));

	return (new);
}


ia32_df_bblock *
ia32_df_bblock_split (ia32_df_bblock *dfb, unsigned int split_point)
{
	ia32_df_bblock *	new;


	if (dfb == NULL)
		return (NULL);

	assert (split_point <= dfb->df_count);

	new = xcalloc (1, sizeof (ia32_df_bblock));
	new->df_count = dfb->df_count - split_point;
	new->df = xcalloc (new->df_count, sizeof (ia32_df_set));
	memcpy (new->df, &dfb->df[split_point],
		new->df_count * sizeof (ia32_df_set));

	dfb->df_count -= new->df_count;
	dfb->df = xrealloc (dfb->df, dfb->df_count * sizeof (ia32_df_set));

	return (new);
}


void
ia32_df_bblock_destroy (ia32_df_bblock *dfb)
{
	if (dfb == NULL)
		return;

	if (dfb->df != NULL)
		free (dfb->df);

	free (dfb);
}


ia32_df_bblock *
ia32_df_bblock_new (ia32_bblock *bb, unsigned char *mem)
{
	unsigned int	icount = 0;	/* instructions in basic block */
	int		membytes;	/* bytes in basic block */
	unsigned char *	mem_orig = mem;
	ia32_df_bblock *	new;

	assert (bb != NULL);
	membytes = bb->end - bb->start;

	while (membytes > 0) {
		ia32_instruction *	inst,
					inst_s;

		inst = ia32_decode_instruction (mem, &inst_s);
		assert (inst != NULL);
		icount += 1;

		mem += inst->length;
		membytes -= inst->length;
	}

	new = xcalloc (1, sizeof (ia32_df_bblock));
	new->df_count = icount;
	new->df = xcalloc (icount, sizeof (ia32_df_set));

	/* initialize def/use sets
	 */
	mem = mem_orig;
	for (icount = 0 ; icount < new->df_count ; ++icount) {
		ia32_instruction *	inst,
					inst_s;

		inst = ia32_decode_instruction (mem, &inst_s);
		ia32_df_set_from_instruction (inst, &new->df[icount]);
		mem += inst->length;
	}

	return (new);
}


void
ia32_df_bblock_append_instruction (ia32_df_bblock *dfb, unsigned char *mem)
{
	unsigned int		cur;
	ia32_instruction *	inst,
				inst_s;

	cur = dfb->df_count;
	dfb->df_count += 1;
	dfb->df = xrealloc (dfb->df, dfb->df_count * sizeof (ia32_df_set));
	memset (&dfb->df[cur], 0x00, sizeof (ia32_df_set));

	inst = ia32_decode_instruction (mem, &inst_s);
	ia32_df_set_from_instruction (inst, &dfb->df[cur]);

	if (cur == 0) {
		dfb->df[cur].out = dfb->df[cur].in = IA32_DF_ALL;
	} else
		dfb->df[cur].out = dfb->df[cur].in = dfb->df[cur - 1].out;
}


ia32_df_set *
ia32_df_set_new (void)
{
	return (xcalloc (1, sizeof (ia32_df_bblock)));
}


ia32_df_set *
ia32_df_bblock_first (ia32_bblock *bb)
{
	ia32_df_bblock *	dfb;

	dfb = (ia32_df_bblock *) bb->user->dfb;
	if (dfb == NULL)
		return (NULL);

	/* in case the block is zero bytes long this is almost always the
	 * result of an unusual function termination, such as calling exit()
	 * or calling another function that never return.
	 */
	if (dfb->df_count == 0 && bb->endtype == BR_END_INVALID)
		return (NULL);

	assert (dfb->df_count > 0);
	return (&dfb->df[0]);
}


ia32_df_set *
ia32_df_bblock_last (ia32_bblock *bb)
{
	ia32_df_bblock *	dfb;

	dfb = (ia32_df_bblock *) bb->user->dfb;
	if (dfb == NULL)
		return (NULL);

	assert (dfb->df_count > 0);
	return (&dfb->df[dfb->df_count - 1]);
}


/* helper functions
 */

void
ia32_df_set_print (ia32_df_set *df)
{
	char	buf[256];

	ia32_df_set_snprint (df, buf, sizeof (buf));
	printf ("%s", buf);
}

static const char *	out_reg_short[] =
	{ "a", "c", "d", "b", "s", "p", "1", "2" };

void
ia32_df_set_snprint (ia32_df_set *df, char *buf, unsigned int len)
{
	unsigned int	regid;
	char		dbuf[256];

	unsigned int	out_idx;
	static const char *	out_str[] =
		{ "D: ", "U: ", "I: ", "O: ", NULL };
	unsigned int *	out_val[4];

	out_val[0] = &df->def; out_val[1] = &df->use;
	out_val[2] = &df->in; out_val[3] = &df->out;

	memset (buf, 0x00, len);
	memset (dbuf, 0x00, sizeof (dbuf));

	for (out_idx = 0 ; out_str[out_idx] != NULL ; ++out_idx) {
		unsigned int	reg_count;
		strcat (dbuf, out_str[out_idx]);

		reg_count = 0;
		for (regid = IA32_REG_EAX ; regid <= IA32_REG_EDI ; ++regid) {
			if (IA32_DF_GET_REG (*out_val[out_idx], regid)) {
				/* if (reg_count++ > 0)
					strcat (dbuf, ", "); */

				/* strcat (dbuf, ia32_regs_wide[regid]);*/
				strcat (dbuf, out_reg_short[regid]);
			} else
				strcat (dbuf, "-");
		}
		strcat (dbuf, " ");
	}

	dbuf[sizeof (dbuf) - 1] = '\0';
	memcpy (buf, dbuf, sizeof (dbuf) > len ? len : sizeof (dbuf));
	buf[len - 1] = '\0';

	return;
}


void
ia32_df_set_snprint_single (unsigned int regmask, char *buf)
{
	unsigned int	regid;

	*buf = '\0';

	for (regid = IA32_REG_EAX ; regid <= IA32_REG_EDI ; ++regid) {
		if (IA32_DF_GET_REG (regmask, regid)) {
			strcat (buf, out_reg_short[regid]);
		} else
			strcat (buf, "-");
	}
}


ia32_df_set *
ia32_df_set_from_instruction (ia32_instruction *inst, ia32_df_set *df_place)
{
	ia32_df_set *	df;


	assert (inst != NULL);

	df = df_place;
	if (df == NULL)
		df = malloc (sizeof (ia32_df_set));

	memset (df, 0x00, sizeof (ia32_df_set));

	if (OD_TEST (inst->opc.opcode->df_srctgt, IA32_DF_DEF_SOURCE) &&
		OD_TEST (inst->opc.used, OP_SOURCE))
	{
		ia32_df_add_source_to_set (&df->def, inst);
	}

	if (OD_TEST (inst->opc.used, OP_SOURCE)) {
		if (OD_TEST (inst->opc.opcode->df_srctgt, IA32_DF_USE_SOURCE) ||
			inst->opc.source_type != OP_TYPE_REG)
		{
			ia32_df_add_source_to_set (&df->use, inst);
		}
	}

	if (OD_TEST (inst->opc.opcode->df_srctgt, IA32_DF_DEF_TARGET) &&
		OD_TEST (inst->opc.used, OP_TARGET))
	{
		ia32_df_add_target_to_set_def (&df->def, inst);
	}

	if (OD_TEST (inst->opc.used, OP_TARGET)) {
		if (OD_TEST (inst->opc.opcode->df_srctgt, IA32_DF_USE_TARGET) ||
			inst->opc.target_type != OP_TYPE_REG)
		{
			ia32_df_add_target_to_set (&df->use, inst);
		}
	}

	if (OD_TEST (inst->opc.opcode->df_srctgt, IA32_DF_USE_FLAGS_COND) &&
		OD_TEST (inst->opc.used, OP_COND))
	{
		df->use = IA32_DF_SET_FLAGS (df->use,
			ia32_eflags_mask_from_cond (inst->opc.cond));
	}

	/* or in the instruction-implicit definition and use masks.
	 */
	df->def |= inst->opc.opcode->df_implicit_def;
	df->use |= inst->opc.opcode->df_implicit_use;

	/* special prefix handling, only the rep* prefixes are imporant
	 * see IA32 Ref. Man. Vol. 2, "rep" instruction
	 */
	if (inst->pfx.rep != 0) {
		if (inst->opc.opcode->opcode_num == IA32_OP_scas ||
			inst->opc.opcode->opcode_num == IA32_OP_cmps)
		{
			df->use |= IA32_DF_USE_FLAGS (IA32_EFLAGS_ZF);
		}

		df->use |= IA32_DF_USE (ECX);
		df->def |= IA32_DF_DEF (ECX);
	}

	if (ia32_df_abi_hook != NULL)
		ia32_df_abi_hook (inst, df);

	/* we cannot know yet
	 */
	df->in = 0;
	df->out = 0;

	return (df);
}


static void
ia32_df_add_source_to_set (unsigned int *dest, ia32_instruction *inst)
{
	*dest |= ia32_df_regmask_oper_use (inst->opc.source_type,
		inst->opc.source_reg, inst->opc.source_width, inst);
}


static void
ia32_df_add_target_to_set (unsigned int *dest, ia32_instruction *inst)
{
	*dest |= ia32_df_regmask_oper_use (inst->opc.target_type,
		inst->opc.target_reg, inst->opc.target_width, inst);
}


static void
ia32_df_add_target_to_set_def (unsigned int *dest, ia32_instruction *inst)
{
	*dest |= ia32_df_regmask_oper_def (inst->opc.target_type,
		inst->opc.target_reg, inst->opc.target_width, inst);
}

static int map_8bit_to_32bit_regs[] =
	{ IA32_REG_EAX, IA32_REG_ECX, IA32_REG_EDX, IA32_REG_EBX ,
		IA32_REG_EAX, IA32_REG_ECX, IA32_REG_EDX, IA32_REG_EBX };

static int
ia32_df_regmask_oper_def (unsigned int oper_type, unsigned int reg,
	unsigned int oper_width, ia32_instruction *inst)
{
	unsigned int	mask = 0;

	switch (oper_type) {
	case (OP_TYPE_REG):
		if (oper_width == IA32_WIDTH_8)
			reg = map_8bit_to_32bit_regs[reg];
		mask |= 1 << reg;
		break;
	default:
		break;
	}

	return (mask);
}


static int
ia32_df_regmask_oper_use (unsigned int oper_type, unsigned int reg,
	unsigned int oper_width, ia32_instruction *inst)
{
	unsigned int	mask = 0;
	static const unsigned int mod10_16bit_address_xlat[] =
		{ (1 << IA32_REG_EBX) | (1 << IA32_REG_ESI),
			(1 << IA32_REG_EBX) | (1 << IA32_REG_EDI),
			(1 << IA32_REG_EBP) | (1 << IA32_REG_ESI),
			(1 << IA32_REG_EBP) | (1 << IA32_REG_EDI),
			(1 << IA32_REG_ESI),
			(1 << IA32_REG_EDI),
			(1 << IA32_REG_EBP),
			(1 << IA32_REG_EBX), };

	switch (oper_type) {
	case (OP_TYPE_MEMREG):
		/* when an address size prefix is encountered, we have to
		 * apply extra magic. (see intel developer manual, vol.2,
		 * "instruction formats and encodings", table 36-1, Mod "10".
		 * anyway, its a relict from long ago, but its not too
		 * complicated to implement.
		 */
		if (inst->pfx.addr_size == 0) {
			mask |= 1 << reg;
			break;
		}

		/* do magic
		 */
		mask |= mod10_16bit_address_xlat[reg];
		break;
	case (OP_TYPE_REG):
		if (oper_width == IA32_WIDTH_8)
			reg = map_8bit_to_32bit_regs[reg];

		mask |= 1 << reg;
		break;
	case (OP_TYPE_MEM):
		/* SIB decoding */
		if (inst->opc.base)
			mask |= 1 << inst->opc.base_reg;

		if (inst->opc.index)
			mask |= 1 << inst->opc.index_reg;
		break;
	default:
		break;
	}

	return (mask);
}


void
ia32_df_abi_sysvlinux (ia32_instruction *inst, ia32_df_set *df)
{
	if (inst->opc.opcode->opcode_num == IA32_OP_call) {
		/* possibly return values and clobbered regs
		 */
		df->def |= IA32_DF_DEF (EAX) | IA32_DF_DEF (ECX) |
			IA32_DF_DEF (EDX);
	} else if (inst->opc.opcode->opcode_num == IA32_OP_ret ||
		inst->opc.opcode->opcode_num == IA32_OP_retf)
	{
		/* use'ing eax is a kludge: eax is used as return value, but
		 * without global dataflow analysis we cannot tell whether the
		 * function returns anything. so assume it does in any case.
		 */
		df->use |= IA32_DF_USE (EAX);

		/* system v i386 abi: call preserved registers
		 */
		df->use |= IA32_DF_USE (EBX) | IA32_DF_USE (EBP) |
			IA32_DF_USE (ESI) | IA32_DF_USE (EDI);
	} else if (inst->opc.opcode->opcode_num == IA32_OP_int &&
		inst->opc.target_type == OP_TYPE_IMM &&
		inst->opc.imm_value == IA32_LINUX_SYSCALLINT)
	{
		/* for system calls, we assume it is a syscall_5, where all
		 * registers are clobbered, except ebp and esp.
		 */
		df->use |= IA32_DF_USE (EAX) | IA32_DF_USE (EBX) |
			IA32_DF_USE (ECX) | IA32_DF_USE (EDX) |
			IA32_DF_USE (ESI) | IA32_DF_USE (EDI);

		/* return value is in eax
		 */
		df->def |= IA32_DF_DEF (EAX);
	}
}


