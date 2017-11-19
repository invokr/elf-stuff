/* codegen.c - generic code generation functions
 *
 * by scut
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <common.h>
#include <utility.h>

#include <ia32/ia32_opcodes.h>
#include <ia32/ia32-decode.h>
#include <ia32/ia32-function.h>
#include <ia32/ia32-dataflow.h>
#include <codegen.h>
#include <objwriter.h>

#define	CODEGEN_MAX_INST_TRIES	256

/* from ia32-decode.c */
extern ia32_opcode_e ia32_opcode_table[];
extern char * ia32_regs_wide[];


/*** GLOBALS */

unsigned int codegen_operands[] = {
	IA32_OP_aaa, IA32_OP_aad, IA32_OP_aam, IA32_OP_aas,
	IA32_OP_adc, IA32_OP_add, IA32_OP_and, IA32_OP_bsf, IA32_OP_bsr,
	IA32_OP_bswap, IA32_OP_bt, IA32_OP_btc, IA32_OP_bts, IA32_OP_cbw,
	IA32_OP_daa, IA32_OP_das, IA32_OP_dec, IA32_OP_imul, IA32_OP_inc,
	/* IA32_OP_lea, */ IA32_OP_mov, IA32_OP_neg,
	/* IA32_OP_nop, */ IA32_OP_not, IA32_OP_or, IA32_OP_rcl1, IA32_OP_rcr1,
	IA32_OP_sbb, IA32_OP_sub, IA32_OP_test, IA32_OP_xadd, IA32_OP_xchg,
	IA32_OP_xor, 0 };

unsigned int codegen_operands_length =
	(sizeof (codegen_operands) / sizeof (unsigned int)) - 1;

double * codegen_operands_prob = NULL;
unsigned int codegen_operands_prob_count;


/*** IMPLEMENTATION */

void
codegen_operands_prob_build (instuse_profile *iprof)
{
	unsigned int	cgn;

	if (codegen_operands_prob != NULL)
		return;

	codegen_operands_prob = xcalloc (codegen_operands_length,
		sizeof (double));
	codegen_operands_prob_count = codegen_operands_length;

	for (cgn = 0 ; codegen_operands[cgn] != 0 ; ++cgn) {
		codegen_operands_prob[cgn] =
			iprof->inst_use[ia32_opnum_index (codegen_operands[cgn])];
	}
}


ia32_instruction *
codegen_generate_instruction (unsigned int opcode, unsigned int used_mask,
	ia32_instruction *place, int source_clobbered, reguse_profile *prof)
{
	int	imm_source;

	memset (place, 0x00, sizeof (ia32_instruction));

	place->opc.used = OP_SOURCE | OP_TARGET;
	place->opc.wide = 1;

	place->opc.source_reg = place->opc.target_reg = 0;

	place->opc.target_width = IA32_WIDTH_32;
	place->opc.target_type = OP_TYPE_REG;
	place->opc.target_reg = codegen_getreg (used_mask, 1, prof, -1);

	imm_source = be_random_coin (0.5);
	if (imm_source && ia32_opcode_has_immediate (opcode,
		IA32_WIDTH_32, IA32_WIDTH_32))
	{
		place->opc.imm_size = IA32_WIDTH_32;
		place->opc.imm_value = be_random (UINT_MAX);
		place->opc.source_type = OP_TYPE_IMM;

		place->opc.source_reg = place->opc.target_reg;
	} else {
		place->opc.source_width = IA32_WIDTH_32;
		place->opc.source_type = OP_TYPE_REG;

		place->opc.source_reg = codegen_getreg (used_mask,
			source_clobbered, prof, place->opc.target_reg);
	}

	/* hardwire to EAX in case its the only possible way (aaa, aam, aas,
	 * das, ..) instructions
	 */
	if (ia32_instruction_count (opcode) == 1) {
		ia32_opcode_e *	opc = ia32_opcode_find_bynum (opcode);
		assert (opc != NULL);

		if (OD_TEST (opc->flags, OD_REG_HARD_EAX))
			place->opc.target_reg = IA32_REG_EAX;

		if ((1 << IA32_REG_EAX) & used_mask)
			return (NULL);
	}

	if (place->opc.source_reg == -1 || place->opc.target_reg == -1)
		return (NULL);

	return (place);
}


/* this code is a bit messy
 */

int
codegen_getreg (unsigned int used_mask, int clobber, reguse_profile *prof,
	int reg_avoid)
{
	int	reg_order[] = {
		IA32_REG_EAX, IA32_REG_EDX, IA32_REG_EBX, IA32_REG_ECX,
		IA32_REG_ESI, IA32_REG_EDI, IA32_REG_EBP, IA32_REG_ESP, -1 };
	unsigned int	regmask = IA32_DF_GET_REG_MASK (used_mask),
			reg_idx,
			prob_tries;
	double		prof_sum;
	double		reg_use[IA32_REG_COUNT];
	int		reg_tried[IA32_REG_COUNT],
			reg_tried_count = 0;


	/* do register picking based on probabilities
	 */
	if (prof != NULL) {
		reg_tried_count = 0;
		memset (reg_tried, 0x00, sizeof (reg_tried));

		/* for completely unused registers, at least put some basic
		 * chance in.
		 */
		prof_sum = prof->sum;
		memcpy (reg_use, prof->reg_use, sizeof (reg_use));
		for (reg_idx = 0 ; reg_idx < IA32_REG_COUNT ; ++reg_idx) {
			if (reg_use[reg_idx] == 0.0) {
				reg_use[reg_idx] = 0.10;
				prof_sum += 0.10;
			}
		}
	}

	for (prob_tries = 0 ;
		prof != NULL && reg_tried_count < IA32_REG_COUNT &&
		prob_tries < 64 ; ++prob_tries)
	{
		reg_idx = be_random_prob (IA32_REG_COUNT, reg_use);

		if (reg_avoid >= 0 && prob_tries == (64 - 1))
			reg_idx = reg_avoid;

		if (reg_tried[reg_idx])
			continue;

		if (reg_avoid < 0 || reg_idx != reg_avoid) {
			reg_tried[reg_idx] = 1;
			reg_tried_count += 1;
		}

		/* try to avoid a register if desired and at all possible
		 */
		if (prob_tries < (64 - 1) && reg_avoid >= 0 &&
			reg_idx == reg_avoid)
			continue;

		if (clobber && (((1 << reg_idx) & regmask) == 0))
			return (reg_idx);

		if (clobber == 0 && ((1 << reg_idx) & regmask))
			return (reg_idx);
	}

	/* do the register picking based on fixed order
	 */
	for (reg_idx = 0 ; reg_order[reg_idx] != -1 ; ++reg_idx) {
		if (reg_avoid >= 0 && reg_idx == reg_avoid)
			continue;

		if (clobber && (((1 << reg_order[reg_idx]) & regmask) == 0))
			return (reg_order[reg_idx]);

		if (clobber == 0 && ((1 << reg_order[reg_idx]) & regmask))
			return (reg_order[reg_idx]);
	}

	/* fallback: if there is no used register, select eax
	 */
	if (clobber == 0)
		return (IA32_REG_EAX);

	return (-1);
}


unsigned int
codegen_generate_operation (unsigned int used_mask, int *source_clobbered,
	instuse_profile *iprof)
{
	unsigned int	efl_used = IA32_DF_GET_FLAGS (used_mask),
			efl_def,
			reg_used = IA32_DF_GET_REG_MASK (used_mask),
			reg_def;
	unsigned int	oper,
			in,
			inst_tries = 0;
	ia32_opcode_e *	oel;


	if (iprof != NULL)
		codegen_operands_prob_build (iprof);

	do {
loop_cont:
		if (inst_tries >= CODEGEN_MAX_INST_TRIES)
			break;

		oel = NULL;
		if (iprof != NULL) {
			oper = codegen_operands[be_random_prob
				(codegen_operands_prob_count,
				codegen_operands_prob)];
		} else {
			oper = codegen_operands[be_random
				(codegen_operands_length)];
		}

		for (in = 0 ; ia32_opcode_table[in].opcode_num != 0 ; ++in) {
			oel = NULL;
			if (ia32_opcode_table[in].opcode_num != oper)
				continue;

			oel = &ia32_opcode_table[in];

			/* in case registers get clobbered, try next encoding
			 */
			reg_def = IA32_DF_DEF_REGMASK (oel->df_implicit_def);
			if ((reg_def & reg_used) != 0) {
#ifdef CODEGEN_DEBUG
				printf ("skipping \"%s\" due to: "
					"d:0x%02x & u:0x%02x\n",
					oel->name, reg_def, reg_used);
#endif
				oel = NULL;
				continue;
			}
			if (OD_TEST (oel->df_srctgt, IA32_DF_DEF_SOURCE))
				*source_clobbered = 1;
			else
				*source_clobbered = 0;

			if (OD_TEST (oel->flags, OD_REG_HARD_EAX) &&
				(reg_used & IA32_REG_EAX))
			{
#ifdef CODEGEN_DEBUG
				printf ("skipping \"%s\" due to eax "
					"clobber\n", oel->name);
#endif
				oel = NULL;
				continue;
			}

			break;
		}

		/* no encoding found, continue search for proper opcode
		 */
		inst_tries += 1;

		if (oel == NULL)
			goto loop_cont;

		efl_def = IA32_DF_DEF_GET_FLAGS (oel->df_implicit_def);
	} while ((efl_def & efl_used) != 0);

	if (inst_tries >= CODEGEN_MAX_INST_TRIES)
		oper = IA32_OP_nop;

#ifdef CODEGEN_DEBUG
	printf ("  == choosing \"%s\"\n", oel->name);
#endif

	return (oper);
}


void
codegen_reguse_profile_print (reguse_profile *prof)
{
	unsigned int	rn;	/* register walker */

	printf ("register usage profile\n\n");
	printf (" reg | percentage\n"
		"-----+-------------\n");
	for (rn = 0 ; rn < IA32_REG_COUNT ; ++rn) {
		printf (" %s | %6.2lf\n", ia32_regs_wide[rn],
			100.0 * prof->reg_use[rn]);
	}

	printf ("-----+-------------\n"
		" sum | %6.2lf, made up from %u instructions\n",
		100.0 * prof->sum, prof->lines);
	printf ("     '\n");
}


reguse_profile *
codegen_reguse_profile_create (ia32_function **flist, unsigned int flist_count)
{
	ia32_bblock **		all;
	unsigned int		all_count,
				bn,	/* basic block walker */
				in,	/* instruction walker */
				bitn;	/* use bit test walker */
	ia32_df_bblock *	dfb;
	reguse_profile *	prof;


	all = obj_bblist_build (flist, flist_count, &all_count);
	assert (all != NULL);

	prof = xcalloc (1, sizeof (reguse_profile));

	for (bn = 0 ; bn < all_count ; ++bn) {
		assert (all[bn]->user != NULL && all[bn]->user->dfb != NULL);
		dfb = (ia32_df_bblock *) all[bn]->user->dfb;

		for (in = 0 ; in < dfb->df_count ; ++in) {
			for (bitn = 0 ; bitn < IA32_REG_COUNT ; ++bitn) {
				if (dfb->df[in].use & (1 << bitn))
					prof->reg_use[bitn] += 1;
			}
			prof->lines += 1;
		}
	}

	assert (prof->lines > 0);
	for (bitn = 0 ; bitn < IA32_REG_COUNT ; ++bitn)
		prof->reg_use[bitn] /= (double) prof->lines;

	prof->sum = 0.0;
	for (bitn = 0 ; bitn < IA32_REG_COUNT ; ++bitn)
		prof->sum += prof->reg_use[bitn];

	free (all);
	return (prof);
}


void
codegen_instuse_profile_print (instuse_profile *iprof, int machine)
{
	unsigned int	on;


	if (machine == 0) {
		printf ("instruction usage profile\n\n");
		printf ("    pct |    abs | mnemonic\n"
			"--------+--------+---------------------------------\n");
	}

	for (on = 0 ; on < IA32_OPNUM_COUNT ; ++on) {
		if (iprof->inst_use[on] == 0.0)
			continue;

		if (machine) {
			printf ("%s,%lf # INSTUSE\n", ia32_opnum_name (on),
				iprof->inst_use[on] * 100.0);
		} else {
			printf (" %6.2lf | %6.0lf | %s\n",
				iprof->inst_use[on] * 100.0,
				(double) (iprof->inst_use[on] * iprof->lines),
				ia32_opnum_name (on));
		}
	}

	if (machine == 0) {
		printf ("--------+--------+---------------------------------\n"
			"        | %6u instructions considered\n"
			"        '\n", iprof->lines);
	}
}


instuse_profile *
codegen_instuse_profile_create (ia32_function **flist, unsigned int flist_count)
{
	ia32_bblock **		all;
	unsigned int		all_count,
				bn,
				on;	/* opcode number walker */
	unsigned int		mwlk;
	int			idx;
	instuse_profile *	iuse;
	ia32_instruction *	inst,
				inst_s;


	all = obj_bblist_build (flist, flist_count, &all_count);
	assert (all != NULL);
	iuse = xcalloc (1, sizeof (instuse_profile));

	for (bn = 0 ; bn < all_count ; ++bn) {
		mwlk = 0;

		while (mwlk < (all[bn]->end - all[bn]->start)) {
			inst = ia32_decode_instruction (&all[bn]->mem[mwlk],
				&inst_s);
			assert (inst != NULL);

			idx = ia32_opnum_index (inst->opc.opcode->opcode_num);
			assert (idx != -1);
			iuse->inst_use[idx] += 1.0;
			iuse->lines += 1;

			mwlk += inst->length;
		}
	}
	free (all);

	for (on = 0 ; on < IA32_OPNUM_COUNT ; ++on)
		iuse->inst_use[on] /= (double) iuse->lines;

	return (iuse);
}


instr_array *
codegen_instr_array_copy (instr_array *ia)
{
	instr_array *	new;

	if (ia == NULL)
		return (NULL);

	new = xcalloc (1, sizeof (instr_array));
	new->in_count = ia->in_count;

	new->in_points = xcalloc (new->in_count, sizeof (ia32_instruction *));
	memcpy (new->in_points, ia->in_points,
		new->in_count * sizeof (ia32_instruction *));

	new->in_points_opcode = xcalloc (new->in_count,
		sizeof (unsigned int *));
	memcpy (new->in_points_opcode, ia->in_points_opcode,
		new->in_count * sizeof (unsigned int *));

	new->in_points_icount = xcalloc (new->in_count, sizeof (unsigned int));
	memcpy (new->in_points_icount, ia->in_points_icount,
		new->in_count * sizeof (unsigned int));

	return (new);
}


instr_array *
codegen_instr_array_split (instr_array *ia, unsigned int split_point)
{
	instr_array *	new;

	if (ia == NULL)
		return (NULL);

	assert (split_point <= ia->in_count);

	new = xcalloc (1, sizeof (instr_array));
	new->in_count = ia->in_count - split_point;

	/* duplicate data, using duplicate code ;-)
	 */
	new->in_points = xcalloc (new->in_count, sizeof (ia32_instruction *));
	memcpy (new->in_points, &ia->in_points[split_point],
		new->in_count * sizeof (ia32_instruction *));

	new->in_points_opcode = xcalloc (new->in_count,
		sizeof (unsigned int *));
	memcpy (new->in_points_opcode, &ia->in_points_opcode[split_point],
		new->in_count * sizeof (unsigned int *));

	new->in_points_icount = xcalloc (new->in_count, sizeof (unsigned int));
	memcpy (new->in_points_icount, &ia->in_points_icount[split_point],
		new->in_count * sizeof (unsigned int));

	ia->in_count -= new->in_count;
	ia->in_points = xrealloc (ia->in_points,
		ia->in_count * sizeof (ia32_instruction *));
	ia->in_points_opcode = xrealloc (ia->in_points_opcode,
		ia->in_count * sizeof (unsigned int *));
	ia->in_points_icount = xrealloc (ia->in_points_icount,
		ia->in_count * sizeof (unsigned int));

	return (new);
}


