/* ia32-dataflow.h - ia32 dataflow analysis
 * include file
 *
 * by scut
 *
 * this is an additional module which hooks into the ia32_bblock.user pointer
 * to provide dataflow analysis information for a function. it provides
 * def, use, in and out register and sets at instruction granularity.
 *
 * see chapter 10.6, pp 631 of the dragon book (live variable analysis, we do
 * live register analysis, but the process is the same).
 */

#ifndef	IA32_DATAFLOW_H
#define	IA32_DATAFLOW_H

#include <ia32-decode.h>
#include <ia32-trace.h>


/* ia32_df_set
 *
 * a set describing the register behaviour of a statement. a statement could
 * be a whole function, a basic block or a single instruction (or any amount
 * of code). with this information you can know which registers are unused
 * before (all \ in) and after (all \ out) the statement is executed, which
 * ones are overwritten (gen) in the statement and which registers are used
 * (use) by the statement.
 */
typedef struct {
	unsigned int	def;
	unsigned int	use;

	unsigned int	in;
	unsigned int	out;
#define	IA32_DF_ALL	0xffffffff
#define	IA32_DF_SET_REG(elem,regid) ((elem) | (1 << (regid)))
#define	IA32_DF_GET_REG(elem,regid) (((elem) & (1 << (regid))) == (1 << (regid)))
#define	IA32_DF_GET_REG_MASK(elem) ((elem) & 0xff)
#define	IA32_DF_SET_FLAGS(elem,eflmask) ((elem) | ((eflmask) << 8))
#define	IA32_DF_GET_FLAGS(elem) (((elem) & 0xffffff00) >> 8)
#define	IA32_DF_IS_FLAGS_SET(elem,eflmask) (((elem) & ((eflmask) << 8)) == ((eflmask) << 8))
} ia32_df_set;


/* ia32_df_bblock
 *
 * convenience structure, holding one ia32_df_set for each instruction within
 * a basic block.
 */
typedef struct {
	unsigned int	df_count;	/* number of instructions in bblock */
	ia32_df_set *	df;		/* dataflow sets */
} ia32_df_bblock;


/* ia32_df_abi_hook_type, used to emulate abi behaviour
 */
typedef void (* ia32_df_abi_hook_type)(ia32_instruction *, ia32_df_set *);


/* ia32_df_bbtree_live
 *
 * do a live variable dataflow analysis on all reachable (non-external marked)
 * basic block from `root'. `func' is used for in-memory location, but does
 * not take part in the analysis.
 *
 * return in any case.
 */

void
ia32_df_bbtree_live (ia32_function *func, ia32_bblock *root);


/* ia32_df_bblock_live
 *
 * do the live register analysis for one basic block `bb'. the basic block
 * could be a live-variable virgin, so we fill in everything, in this case
 * `last' should be set to zero. it could also be already processed and we
 * will update it according to `last' mask, which should be set to the union
 * of all following blocks' in set. `mem' is the first byte of the basic
 * block.
 *
 * return zero in case the "first" set has not changed
 * return non-zero in case something backpropped to change "first"
 */

int
ia32_df_bblock_live (ia32_bblock *bb, unsigned int last, unsigned char *mem);


/* ia32_df_bblock_copy
 *
 * create a deep copy of the dataflow basic block information `dfb'.
 *
 * return the copy on success
 * return NULL if there was nothing to copy
 */

ia32_df_bblock *
ia32_df_bblock_copy (ia32_df_bblock *dfb);


/* ia32_df_bblock_split
 *
 * split the dataflow information `dfb' at the `split_point'th instruction
 * into a new block. shorten `dfb' appropiatly.
 *
 * return the new dataflow set (lieing directly behind `dfb').
 */

ia32_df_bblock *
ia32_df_bblock_split (ia32_df_bblock *dfb, unsigned int split_point);


/* ia32_df_bblock_destroy
 *
 * free all memory associated with `dfb'.
 *
 * return in any case
 */

void
ia32_df_bblock_destroy (ia32_df_bblock *dfb);


/* ia32_df_bblock_new
 *
 * create a new ia32_df_bblock structure for the basic block `bb', which
 * starts at `mem'.
 *
 * return the new structure.
 */

ia32_df_bblock *
ia32_df_bblock_new (ia32_bblock *bb, unsigned char *mem);


/* ia32_df_bblock_append_instruction
 *
 * append a single instruction at `mem' unconditionally to dataflow basic
 * block set `dfb' as new dataflow set.
 *
 * return in any case
 */

void
ia32_df_bblock_append_instruction (ia32_df_bblock *dfb, unsigned char *mem);


/* ia32_df_set_new
 *
 * allocate a new df set. any allocations for df sets should be routed through
 * this function.
 *
 * return a pointer to the new allocated set.
 */

ia32_df_set *
ia32_df_set_new (void);


/* ia32_df_bblock_first
 *
 * convenience function locating the first ia32_df_set of a basic block `bb'.
 *
 * return the first df set of the basic block on success
 * return NULL when there is no df set
 */

ia32_df_set *
ia32_df_bblock_first (ia32_bblock *bb);


/* ia32_df_bblock_last
 *
 * convenience function locating the last ia32_df_set of a basic block `bb'.
 *
 * return the last df set of the basic block on success
 * return NULL when there is no df set
 */

ia32_df_set *
ia32_df_bblock_last (ia32_bblock *bb);


/* ia32_df_set_printf
 *
 * print a text representation of the dataflow set `df' to stdout.
 *
 * return in any case
 */

void
ia32_df_set_print (ia32_df_set *df);


/* ia32_df_set_snprintf
 *
 * print a text representation of the dataflow set `df' into `buf', being at
 * most `len' bytes long. it will always be terminated with a NUL byte.
 *
 * return in any case
 */

void
ia32_df_set_snprint (ia32_df_set *df, char *buf, unsigned int len);

void
ia32_df_set_snprint_single (unsigned int regmask, char *buf);

/* ia32_df_set_from_instruction
 *
 * generate a dataflow set for a single instruction. the instruction must be
 * completely decoded and given in `inst'. when `df_place' is non-NULL, the
 * ia32_df_set structure is generated there, otherwise it is mallocated. note,
 * that df.in and df.out are zero in any case.
 *
 * return NULL on failure
 * return pointer to created ia32_df_set structure on success
 */

ia32_df_set *
ia32_df_set_from_instruction (ia32_instruction *inst, ia32_df_set *df_place);


/*** ABI emulation functions, for now only i386-linux */


/* ia32_df_abi_sysvlinux
 *
 * handle special instructions for dataflow analysis, such as system calls and
 * calling conventions.
 *
 * return in any case
 */

void
ia32_df_abi_sysvlinux (ia32_instruction *inst, ia32_df_set *df);

#endif

