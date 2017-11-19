/* ia32-trace.h - ia32 control flow tracer include file
 *
 * by scut
 */

#ifndef	IA32_TRACE_H
#define	IA32_TRACE_H

#define	IA32_TRACE_VERSION	"0.4.0"

#include <ia32-decode.h>


/* XXX: clash */
/* #include <elf-glue.h>*/


typedef struct {
	void *	dfb;		/* dataflow block information */
	void *	instr_insert;	/* instruction insertion array */
} ia32_bb_user;


/* ia32_bblock
 *
 * one 'bblock', which we use in the sense of "one continous block of code"
 * here. a bblock is always executed from top to bottom, without any
 * conditions. at the end of a bblock a new bblock is choosen to continue
 * with, or the bblock terminates. what happens is defined by `endtype',
 * where we possibly go by `endrb', which is `endbr_count' items long.
 *
 * functions that operate on bblockes are ia32_br_*
 */
typedef struct ia32_bblock {
	int		passed;		/* 0 (not processed yet), 1 (done) */
	unsigned int	start;		/* virt. start address */
	unsigned int	end;		/* virt. end address (if passed = 1) */

	unsigned int	last_ilen;	/* length of last instruction */
	int		last_unused;	/* if extended, the free space @ end */

	ia32_bb_user *	user;		/* user data pointer, free to use */
	unsigned char *	mem;		/* start in mem, can be NULL */
	int		mem_allocated;	/* 1 if .mem is on the dynamic heap */

	/* _END_INVALID =
	 * the control flow tracer could not successfully continue, most likely
	 * an instruction could not be decoded
	 */
#define	BR_END_INVALID	0
	/* _END_RET = INTER, UNCOND, PASS
	 * a normal return from the function
	 */
#define	BR_END_RET	1
	/* _END_IF = INTRA, COND, PASS
	 * an if statement within the function
	 * also the `cond' field is used when _END_IF is endtype.
	 * when the condition evaluates to true then the second bblock is
	 * choosen (endbr[1]), else the first.
	 */
#define	BR_END_IF	2
	/* _END_PASS =
	 * there is only one end bblock, and we unconditionally go with it.
	 * this happens when a bblock is split due to another bblock
	 * referencing into it. it can also happen for control flow
	 * instructions we cannot predict or that we intentionally ignore,
	 * such as: call r/m, int, ..
	 */
#define	BR_END_PASS	3
	/* _END_TRANSFER =
	 * similar to _END_PASS, this unconditionally transfers control to
	 * another position within the function. the difference to _END_PASS
	 * is that it does change the control flow, while _END_PASS continues
	 * at the instruction right after the bblock.
	 */
#define	BR_END_TRANSFER	4
	/* _END_CALL
	 * similar to _END_PASS, this resumes execution. the difference is
	 * that it always resumes directly after the current instruction,
	 * which is call to another function.
	 */
#define	BR_END_CALL	5
	/* _END_IF_INTER
	 * like if, but a conditional jump refering to outside of the function
	 * itself. rarely used, but libc uses it for example to cope faster
	 * with error conditions (__syscall_error)
	 */
#define	BR_END_IF_INTER	6
	/* _END_TRANSFER_INTER
	 * like _END_IF_INTER, but unconditional
	 */
#define	BR_END_TRANSFER_INTER	7
	/* _END_SWITCH
	 * switchtable, with arbitrary number of cases
	 */
#define	BR_END_SWITCH	8
	/* _END_FUNCPTR
	 * function pointer, volatile register jump
	 */
#define	BR_END_FUNCPTR_CALL	9
#define	BR_END_FUNCPTR_JUMP	10
	/* _END_CALL_MEM
	 * volatile absolute-memory-location calls. (function pointer calls
	 * directed through memory instead of registers). note when this is
	 * the end type, memabs_pos must be greater zero and one branch end is
	 * used (the one after the call).
	 */
#define	BR_END_CALL_MEM		11
	/* _END_CALL_MEMREG
	 * volatile [reg + displ] calls. (function pointer calls redirected
	 * through memory, most likely some function parameters). when this is
	 * used, memreg_displ and memreg_callreg must be set.
	 */
#define	BR_END_CALL_MEMREG	12
	/* _END_CALL_MEMSIB
	 * the most complicated memory indirected call type. involves scale,
	 * index, base and often displacement. the respective elements
	 * memsib_* have all to be set properly in case this is used.
	 * what a true mess ia32 is. yes, we could translate the sib code into
	 * linear code, but this is troublesome for three reasons:
	 *   1. to not confuse the internal relocation system, we would have to
	 *      add proper relocations for the new code, too (displacement!).
	 *   2. we would have to spill registers in order not to clobber them
	 *   3. the more specific we are about emulating instructions instead
	 *      of linearizing them, the more complicated the be2 analysis
	 *      will become ;)
	 */
#define	BR_END_CALL_MEMSIB	13
	/* _END_CTRL_SYSCALL_END
	 * ends with a system call that will never return (eg sigreturn
	 * variants). normal returning system calls are handled as normal
	 * passing instructions.
	 */
#define	BR_END_CTRL_SYSCALL_END	14
	/* _END_CTRL_SYSCALL
	 * normally we could just jump over system calls at all (they return
	 * anyway). but there are cases syscalls could mess with out
	 * emulation, namely when system calls that affect the global process
	 * behaviour are called. for now, this are signal handling calls that
	 * change SIGTRAP behaviour. we have to skip any system call that
	 * would change this.
	 */
#define	BR_END_CTRL_SYSCALL	15
	/* _END_CALL_EXTERN
	 * a call we cannot dereference. within emulation, the call is just
	 * skipped, so it behaves like _END_PASS. still we distinguish this to
	 * create a proper relocation for the call when writing an ELF object.
	 */
#define	BR_END_CALL_EXTERN	16
	/* _END_UNPREDICT
	 * is used when we hit a control flow instruction that we cannot
	 * predict statically and that does not return. this rather marks
	 * a bblock end more than it affects any control flow (we just run the
	 * instruction and see what happens).
	 */
#define	BR_END_UNPREDICT	17

	int		endtype;

	unsigned int	cond;

	unsigned int	other_xref_count;
	void *		other_xref;	/* type: (ia32_xref **) */

	void *		switchtab;	/* in case of endtype BR_END_SWITCH */
	void *		interrupt;	/* in case of endtype BR_END_CTRL_SYSCALL_END */
	unsigned int	call_reg;	/* register for BR_END_FUNCPTR */

	/* BR_END_CALL_MEM type, the number of bytes into the instruction
	 * where the absolute memory location is stored. must be greater zero.
	 */
	unsigned int	memabs_pos;

	/* BR_END_CALL_MEMREG type, the register/displacement in
	 * [reg + instr[displ]]. the displacement can be negative.
	 */
	unsigned int	memreg_callreg;
	int		memreg_displ;

	/* BR_END_CALL_MEMSIB type, full sib support plus optional
	 * displacement.
	 *
	 * scale is 0-3.
	 * index is flag, when 1, indexreg is used
	 * base is flag, when 1, basereg is used
	 * displpos > 0: position into last instruction where displacement is
	 *
	 * the real call is this:
	 *    call dword [(2^scale * index) + base + displ]
	 *
	 * note that there may be relocations for displ's position.
	 */
	unsigned int	memsib_scale;
	unsigned int	memsib_index;
	unsigned int	memsib_indexreg;
	unsigned int	memsib_base;
	unsigned int	memsib_basereg;
	unsigned int	memsib_displpos;

	/* endbr[] is an array of bblockes possibly taken at the end of this
	 * bblock. there are endbr_count bblockes (which should not exceed 2)
	 *
	 * for endbr_count = 0, endbr is guaranteed to be NULL.
	 */
	unsigned int		endbr_count;
	struct ia32_bblock **	endbr;

	/* when non-NULL, this array contains zero or non-zero values, one for
	 * each endbr[] entry. if the entry is non-zero, the basic block maps
	 * to outside the function. this is important for basic-block walking
	 * functions, such as ia32_br_get_all.
	 */
	unsigned int *		endbr_external;

	/* codeflow analysis stuff, optionally used.
	 *
	 * `dom_count' gives the number of basic blocks this block is the
	 * dominator of. the blocks are listed within `dom'.
	 */
	unsigned int		dom_count;
	struct ia32_bblock **	dom;

	/* if NULL: this block is not within any loop or loop analysis has not
	 *    been done
	 * if non-NULL: pointer to the loop this block is directly contained
	 *    in (innermost loop)
	 * real type: (ia32_loop *)
	 */
	void *		innermost;
} ia32_bblock;


/*** function prototypes
 */

/* ia32_br_new
 *
 * create a new bblock structure.
 *
 * return pointer to new structure
 */

ia32_bblock *
ia32_br_new (void);


/* ia32_br_dump
 *
 * dump current bblock tree starting at `root' in a linear fashion, sorted by
 * start address to stdout. when `name' is non-NULL it is used as function
 * name.
 *
 * return in any case
 */

void
ia32_br_dump (char *name, ia32_bblock *root);


/* ia32_br_get_unpassed
 *
 * walk through bblock list `all', which is `all_count' items long, and check
 * for non-processed bblockes.
 *
 * return the first unpassed bblock found on success
 * return NULL when all bblockes have been processed
 */

ia32_bblock *
ia32_br_get_unpassed (ia32_bblock **all, unsigned int all_count);


/* ia32_br_split
 *
 * split the bblock `br' at `vaddr', which has to be inbetween br->start and
 * br->end. hence the bblock should be processed already, else the result is
 * undefined.
 *
 * return the second bblock, which was just created due to the splitting
 */

ia32_bblock *
ia32_br_split (ia32_bblock *br, unsigned int vaddr);


/* ia32_br_get_all
 *
 * walk all bblockes recursivly from `root', collecting pointers to all
 * bblockes. store the number of unique bblockes found into `br_count'.
 *
 * return array of pointers to bblockes, which is `br_count' entries long
 */

ia32_bblock **
ia32_br_get_all (ia32_bblock *root, unsigned int *count);


/* ia32_br_predecessor_is
 *
 * predicate, true if `from' is a predecessor of `to'.
 *
 * return non-zero if there is an end branch from `from' to `to'
 * return zero if there is no such path
 */

int
ia32_br_predecessor_is (ia32_bblock *from, ia32_bblock *to);


/* ia32_br_find
 *
 * find the correct bblock which starts at `vaddr', traveling the parse tree
 * down from the root bblock `root'. if a bblock is found that covers the
 * address, but does not start there, the bblock is automatically split. when
 * this is done, `br_split' is set to one, otherwise to zero. if `br_all' is
 * given non-NULL, the `root' node is ignored and the already collected
 * bblock list is taken from `br_all', being `br_count' items long.
 *
 * return pointer to bblock starting at `vaddr' on success
 * return NULL if no bblock has been found (you have to create a new one) on
 *     failure
 */

ia32_bblock *
ia32_br_find (ia32_bblock *root, unsigned int vaddr,
	ia32_bblock **br_all, unsigned int br_count, int *br_split);


/* ia32_brl_find
 *
 * utility function, locate `br' in bblock list `list', which is `list_len'
 * items long.
 *
 * return index into `list' on success
 * return -1 on failure
 */

int
ia32_brl_find (ia32_bblock **list, unsigned int list_len, ia32_bblock *br);


/* ia32_trace_range
 *
 * test whether `ref' lies inbetween `start' and `end'.
 *
 * return 0 if it is outside of [start - end[
 * return != 0 if it is within
 */

int
ia32_trace_range (unsigned int start, unsigned int end, unsigned int ref);


/* ia32_trace_return_is
 *
 * tries to figure whether the already decoded instruction `inst' at `inst_src'
 * is a return instruction.
 *
 * return 0 in case it is not
 * return 1 in case it is
 */

int
ia32_trace_return_is (ia32_instruction *inst, unsigned char *inst_src);


/* ia32_trace_control
 *
 * decode the control flow instruction `inst' which was found at virtual
 * address `cur'. the instruction was found in memory at `inst_src'.
 * try to tell the destination of the control instruction as a virtual address
 * control will be transfered. for conditional instructions, the condition is
 * always assumed true. `resume' contains 0 or 1 after the function returns,
 * where 1 means the control flow will resume after the instruction at some
 * point (i.e. call), where 0 denotes that no information about control
 * transfer origin is kept. `resume' can be NULL, then this information is
 * not passed to the caller. `ctrl_volatile' tags runtime-dependant
 * instructions, such as "call eax" and "call [0x0804826c]", etc.
 *
 * return absolute virtual address control may be passed to on success
 * return 0xffffffff on failure
 */

unsigned int
ia32_trace_control (ia32_instruction *inst, unsigned char *inst_src,
	unsigned int cur, int *resume, int *ctrl_volatile);


/* ia32_br_instruction_count
 *
 * utility function that counts the number of real instructions in basic block
 * `bb'.
 *
 * return the number of instructions counted
 */

unsigned int
ia32_br_instruction_count (ia32_bblock *bb);


#include <ia32-function.h>


/* ia32_vcg_br_output
 *
 * output all basic blocks reachable from `root' from the function `func_2'
 * (type: (ia32_function *)) in the GDL (graph description language) format to
 * file `fp'. the output is readable by the VCG toolkit (visualization of
 * compiler graphs, see http://rw4.cs.uni-sb.de/users/sander/html/gsvcg1.html).
 *
 * return in any case
 */

void
ia32_vcg_br_output (FILE *fp, ia32_bblock *root, void *func_2);


/* ia32_vcg_br_output_node
 *
 * output a single node `br' of the control flow graph of function `func'
 * (type: (ia32_function *)) to file `fp'. if `attributes' is non-NULL the
 * attributes will be assigned to the node.
 *
 * return in any case
 */

void
ia32_vcg_br_output_node (FILE *fp, void *func_v, ia32_bblock *br,
	const char *color);


/* ia32_graphviz_br_output
 *
 * output a bblock tree starting at `root' in graphviz format to the file
 * mapped by `fp', which has to be open and will remain open. the bblock is
 * within `func'. when `digraph' is not zero, a digraph is created, else
 * a subgraph.
 *
 * return in any case
 */
#if 0
void
ia32_graphviz_br_output (FILE *fp, ia32_bblock *root, ia32_function *func);
#endif

/* FIXME: find a cleaner way to work around header file deps
 */
void
ia32_graphviz_br_output (FILE *fp, ia32_bblock *root, void *func);

#endif


