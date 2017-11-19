/* codegen.h - generic code generation functions, include file
 *
 * by scut
 */

#ifndef	CODEGEN_H
#define	CODEGEN_H

#include <ia32/ia32-decode.h>
#include <ia32/ia32_opcodes.h>


typedef struct {
	/* overall number of instructions in the basic block
	 */
	unsigned int		in_count;

	/* .a ins1 .b ins2 .c ins3 .d ins4 ...
	 *
	 * ins[123..] are the original basic block instructions. ".a", ".b",
	 * ".c", ... are points right before the instructions. in_points[.a]
	 * (.a is zero, .b one, ..) is a list of instructions to be inserted
	 * at point .a. at this point in_points_icount[.a] instructions will
	 * be inserted.
	 */
	ia32_instruction **	in_points;
	unsigned int **		in_points_opcode;
	unsigned int *		in_points_icount;
} instr_array;


typedef struct {
	/* number of dataflow analysed machine instructions analysed for this
	 * profile.
	 */
	unsigned int		lines;

	/* sum of all probabilities. always greater-equal 1.0
	 */
	double			sum;

	/* percentages (values between 0.0 and 1.0) for each register. indexed
	 * using IA32_REG_*.
	 */
	double			reg_use[IA32_REG_COUNT];
} reguse_profile;


typedef struct {
	/* number of instructions considered
	 */
	unsigned int		lines;

	/* opnum-indexed array of percentages (values between 0.0 and 1.0) for
	 * every mnemonic
	 */
	double			inst_use[IA32_OPNUM_COUNT];
} instuse_profile;


/* codegen_operands_prob_build
 *
 * generate the probability table codegen_operands_prob from codegen_operands
 * and the instruction usage profile `iprof'. this is necessary to reuse the
 * random functions in utility.c.
 *
 * return in any case
 */

void
codegen_operands_prob_build (instuse_profile *iprof);


/* codegen_generate_instruction
 *
 * generate an ia32_instruction structure for `opcode' that does not clobber
 * any memory, but only registers and eflags not used in `used_mask' (which is
 * defined as ia32-dataflow does it). write the instruction structure to
 * `place'. if `source_clobbered' is non-zero, the source operand will be
 * overwritten by the instruction. if `prof' is non-NULL, registers are picked
 * according to the profile.
 *
 * return NULL on failure
 * return place on success
 */

ia32_instruction *
codegen_generate_instruction (unsigned int opcode, unsigned int used_mask,
	ia32_instruction *place, int source_clobbered, reguse_profile *prof);


/* codegen_getreg
 *
 * generate a register number. if `clobber' is true, a register will be
 * generated that does not touch any of the ones in `used_mask'. if `clobber'
 * is false, a register from `used_mask' is generated. if `prof' is non-NULL,
 * the register will be choosen by its probability. if `reg_avoid' is
 * non-negative, the picking tries to avoid the register with number
 * `reg_avoid'.
 *
 * return -1 on failure
 * return register index on success (0-7)
 */

int
codegen_getreg (unsigned int used_mask, int clobber, reguse_profile *prof,
	int reg_avoid);


/* codegen_generate_operation
 *
 * generate a IA32 opcode number (from ia32_opcodes.h) to be used for a new
 * instruction. the generated opcode will not clobber any eflags used in
 * `used_mask', which is defined as in ia32-dataflow. `source_clobbered' is
 * overwritten with either zero or non-zero, depending on whether the source
 * operand of the generated opcode is overwritten by the instruction. if
 * `iprof' is non-NULL, the instructions will be picked according to the
 * statistical distribution of `iprof'.
 *
 * return opcode number in any case
 */

unsigned int
codegen_generate_operation (unsigned int used_mask, int *source_clobbered,
	instuse_profile *iprof);


/* codegen_reguse_profile_create
 *
 * create a register use profile from the function list `flist'
 * and `flist_count', which all need to have passed a dataflow analysis.
 *
 * return NULL on failure
 * return register usage profile on success
 */

reguse_profile *
codegen_reguse_profile_create (ia32_function **flist, unsigned int flist_count);


/* codegen_reguse_profile_print
 *
 * print the profile `prof' to stdout.
 *
 * return in any case
 */

void
codegen_reguse_profile_print (reguse_profile *prof);


/* codegen_instuse_profile_print
 *
 * print an instruction usage profile `iprof'. if `machine' is non-zero, a
 * machine parsable format will be used.
 *
 * return in any case
 */

void
codegen_instuse_profile_print (instuse_profile *iprof, int machine);


/* codegen_instuse_profile_create
 *
 * create an instruction usage profile for all functions in `flist', which is
 * `flist_count' items long.
 *
 * return the profile in any case
 */

instuse_profile *
codegen_instuse_profile_create (ia32_function **flist, unsigned int flist_count);


/* codegen_instr_array_copy
 *
 * create a deep copy of the instruction array `ia'.
 *
 * return new array on success
 * return NULL if there was nothing to copy
 */

instr_array *
codegen_instr_array_copy (instr_array *ia);


/* codegen_instr_array_split
 *
 * split the instruction array `ia' at the `split_point'th instruction into a
 * new array. shorten `ia' appropiatly. this is the pendant to
 * ia32_df_bblock_split and they both act similar to a copy constructor. they
 * are required for basic block splitting.
 *
 * return new instruction array (lieing directly behind `ia')
 */

instr_array *
codegen_instr_array_split (instr_array *ia, unsigned int split_point);

#endif


