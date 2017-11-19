/* ia32-function.h - ia32 function abstraction layer, include file
 *
 * by scut
 */

#ifndef	IA32_FUNCTION_H
#define	IA32_FUNCTION_H

#define	IA32_FUNCTION_VERSION	"0.4.0"

#include <elf.h>
#include <ia32-trace.h>


/* ia32_xref
 *
 * cross reference structure used for any "a references b" kind of
 * relationships, with 'a' being the `from', 'b' the `to'.
 *
 * functions that operate on crossreferences are not bound to prefixes.
 */
typedef struct {
	/* when set to one, .orig holds the original relocation structure */
	int		original_relocation;
	Elf32_Rel	orig;	/* original relocation entry */

	unsigned int	from;	/* address: from where its referenced */
	unsigned int	addend;	/*   real reloc is at from + addend */

	unsigned int	to;	/* address: referenced address (target) */
	unsigned int	rel_addend;	/* relocation addend (A) */

#define	IA32_XREF_INVALID	0
#define	IA32_XREF_FUNCTION	1
#define	IA32_XREF_FUNCEXTERN	2
#define	IA32_XREF_OTHER		3
	int		to_type;	/* type of target reference */

#define	IA32_XREF_O_UNKNOWN		0
	/* _O_FUNCTIONINTERN, is a .text relocated offset to within the
	 * current function. normally, compilers generate a jmp <reg>
	 * instruction somewhere after it, but we cannot know and have
	 * to relocate in runtime to the basic block the `to' offset is
	 * pointing to.
	 */
#define	IA32_XREF_O_FUNCTIONINTERN	1
	int		other_subtype;

	/* to_data = pointer to structure defining the target. can be one
	 * of the following types:
	 *    ia32_function (IA32_XREF_FUNCTION)
	 *    elf_reloc (IA32_XREF_OTHER)
	 */
	void *		to_data;

	/* inter section cross reference. (0/1), normally 0
	 */
	int		inter_section;
} ia32_xref;

/* ia32_function
 *
 * central function definition. every function can be defined through one of
 * this structures (and usually just one should be used).
 *
 * functions that operate on function structures are ia32_func_*
 */
typedef struct ia32_function {
	int		passed;		/* 0 = not analyzed, 1 = done */
	char *		name;		/* name of function, or NULL */
	unsigned char *	mem;		/* address of function, if loaded */

	unsigned int	section_idx;	/* the section this function is
					 * located in */

	int		traced_bounds,	/* guessed/traced address bounds */
			is_nested,	/* this is an inner function */

	/* is_pos_curious flags whether the function tries to obtain its own
	 * position by means of "call next; next: pop reg" tricks. this
	 * happens in some special PIC code and may be of value to
	 * postprocessing steps, hence mark it here. normally its set to zero.
	 */
			is_pos_curious,

	/* if the symbol table entry for a function is invalid length-wise
	 * (such as __write, __read, _start, in glibc), we mark this, as we
	 * have to slightly change our behaviour to some more "traced bounds"
	 * one when analyzing the rest of the function. zero normally.
	 */
			is_symdamaged,
	/* some functions do not end with a return instruction. we do not
	 * check for "ret must be the last instruction", but whether the
	 * codeflow could escape the function bounds. we cannot guarantee by
	 * static analysis that it will not escape when the last instruction
	 * is a call for example. this is common for init/bail/failure/lose
	 * functions, such as __libc_start_main, __pthread_do_exit, lose, ..
	 * as long as only such functions are detected as abnormal everything
	 * is fine. but then there are difficult cases, especially when
	 * invalid symbol table entries or traced-bounds are active. we try
	 * our best, but one should manually check that only the desired
	 * functions are caught.
	 */
			is_abnormal_end,

	/* this function is an alias of another function and was just
	 * shallow-copied. be careful when this is set.
	 */
			is_copy;

	unsigned int	start;		/* virtual start address */
	unsigned int	end;		/* virtual end address */

	/* toggle flag, can be set to non-zero when livereg analysis has been
	 * done (does not happen automatically though).
	 */
	int		livereg_available;

	ia32_bblock *	br_root;	/* root bblock (func entry point) */

	/* function cross references: list of functions this function calls
	 * XXX: notice that control flow instructions that refer to other
	 *      functions have the vaddr of the instruction requiring the
	 *      address as `from', while data references to functions (function
	 *      pointers that is) have the exact address the relocation has to
	 *      be filled in.
	 */
	unsigned int	func_xref_count;/* number of calls */
	ia32_xref **	func_xref;	/* calls to other functions */

	unsigned int	other_xref_count;
	ia32_xref **	other_xref;

	/* relocations do be processed within this function body */
	unsigned int	reloc_count;	/* number of relocations */
	/* relocations themselves */
	void *		reloc;		/* cast: struct elf_reloc ** reloc; */
} ia32_function;


/* specific complex execution constructs
 */
typedef struct {
	unsigned int	entries;	/* number of entries */
	unsigned int	vaddr_start;	/* relative address the table is at
					 * within its section */
	unsigned int	vaddr_loc;	/* location of vaddr in code */
	unsigned int *	mem_start;	/* where the table is in memory (mapped now) */

	unsigned int	idx_reg;	/* register used to index */
	unsigned int	idx_scale;	/* scale (0, 1, 2 for *1, *2, *4) */

	void *		reloc;		/* (type: (elf_reloc_list *) */
} ia32_switchtable;


#define	IA32_LINUX_SYSCALLINT	0x80
#define	IA32_LINUX_MAXSYSCALL	512

typedef struct {
	unsigned int	syscall;	/* system call number */
	int		resume;		/* 1 = mangles control flow */
} ia32_linux_interrupt;



#include <elf_reloc.h>


/* ia32_xref_new
 *
 * create a new cross reference structure.
 *
 * return pointer to new structure
 */

ia32_xref *
ia32_xref_new (void);


/* ia32_func_xref_find
 *
 * find crossreferences from `vaddr_from' within function body `func'.
 *
 * return pointer to xref found on success
 * return NULL on failure
 */

ia32_xref *
ia32_func_xref_findfrom (ia32_function *func, unsigned int vaddr_from);


/* ia32_func_new
 *
 * create a new function structure.
 *
 * return pointer to new structure
 */

ia32_function *
ia32_func_new (void);


/* ia32_func_get_unpassed
 *
 * get the first function which is not passed yet. walk through `flist', which
 * is `flist_count' items long. only functions which lie in the section
 * indexed by `sidx' are considered.
 *
 * return pointer to unpassed function on success
 * return NULL on failure
 */

ia32_function *
ia32_func_get_unpassed (ia32_function **flist, unsigned int flist_count,
	unsigned int sidx);


/* ia32_func_br_end
 *
 * find the end bblock for the function `func'.
 *
 * return bblock pointer on success
 * bail on failure (every function must have an end bblock)
 */

ia32_bblock *
ia32_func_br_end (ia32_function *func);


/* ia32_func_v2real
 *
 * convert a virtual address `vaddr' that lies within the function `func' to
 * the real memory address this address is mapped to in our process space.
 *
 * return the real address on success
 * bail on failure
 */

unsigned char *
ia32_func_v2real (ia32_function *func, unsigned int vaddr);


/* ia32_func_r2virt
 *
 * convert the real address `real' from within the mapped function `func's body
 * to a relative to the function start address.
 *
 * return address on success
 * bail on failure
 */

unsigned int
ia32_func_r2virt (ia32_function *func, unsigned int real);


/* ia32_func_findcopy
 *
 * search the - possibly unpassed - function list `flist' for aliased and
 * already processed copies of the `func' function. that is, functions that
 * occupy the same space within the .text section, but are mapped to a
 * different function name. the function list is `flist_count' entries long.
 *
 * return alias function on success
 * return NULL if no aliased function can be found
 */

ia32_function *
ia32_func_findcopy (ia32_function *func,
	ia32_function **flist, unsigned int flist_count);


/* ia32_func_treeplain
 *
 * bblock-analyse all unpassed functions in `flist', which is `flist_count'
 * items long. make them passed afterwards. to reference function call
 * addresses, optionally use `rel_code' and `rel_rodata'. either can be NULL.
 * when non-NULL it is the * relocation list for the section the functions are
 * located in (.text for `rel_code' and .rodata for `rel_rodata'). the .rodata
 * relocations are needed to weed out switch tables.
 * note that both `flist' and `flist_count' can be modified along when hidden
 * functions are detected. when `code_idx' is non-zero, only functions are
 * processed which lie in the section indexed by `code_idx'.
 *
 * return in any case
 */

void
ia32_func_treeplain (ia32_function ***flist, unsigned int *flist_count,
	elf_reloc_list *rel_code, elf_reloc_list *rel_rodata,
	unsigned int code_idx);


/* ia32_func_list_is_covered
 *
 * check whether the address `vaddr' is covered by any of the functions within
 * the list `flist', which is `flist_count' items long.
 *
 * return the first covered function if there is an overlap
 * return NULL if there is no function covering the address
 */

ia32_function *
ia32_func_list_is_covered (unsigned int vaddr, ia32_function **flist,
	unsigned int flist_count);


/* ia32_func_breakup
 *
 * break a function into a bblock tree, starting at `func->start'. use
 * `rel_code' and `rel_rodata' * when non-NULL, like in ia32_func_treedown.
 *
 * return bblock root node for function on success
 * should not fail
 */

ia32_bblock *
ia32_func_breakup (ia32_function *func, elf_reloc_list *rel_code,
	elf_reloc_list *rel_rodata);


/* ia32_func_switchtable_decode
 *
 * decode a switchtable identified by the tracer. the switching jump
 * instruction is within `func', within `this', exactly at `vaddr'. it has
 * been decoded already to `inst'. `root' is the bblock tree already
 * discovered.
 *
 * return a pointer to the processed switchtable structure on success
 * return NULL on failure
 */

ia32_switchtable *
ia32_func_switchtable_decode (ia32_function *func, ia32_bblock *root,
	ia32_bblock *this, unsigned int vaddr, ia32_instruction *inst);


/* ia32_linux_interrupt_decode
 *
 * decode a linux system call instruction "int 0x80" at `vaddr' within the
 * function `func'. starting at the basic block tree root node `root', walk
 * up instructions upward until system call number is found. the current
 * basic block is `this', the current instruction (int) is `inst'.
 *
 * return NULL when no system call number can be obtained
 * return linux interrupt definition for this system call on success
 */

ia32_linux_interrupt *
ia32_linux_interrupt_decode (ia32_function *func, ia32_bblock *root,
	ia32_bblock *this, unsigned int vaddr, ia32_instruction *inst);


/* ia32_func_inst_traceup
 *
 * attempt to collect the last `backcount' executed instructions backwards,
 * starting from `end_vaddr' within bblock `cur'. trace the bblockes up that
 * lead to the `cur' bblock, when there is only one forward reference. stop
 * early when there are multiple forward references. to trace the flow
 * backwards, `func', the current function and `root', the bblock root tree
 * have to be given. the number of instructions collected is returned through
 * `inst_count'. the number is always less or equal to `backcount'. note that
 * the returned list is a list of structures, unlike what most of the other
 * functions return.
 *
 * return list of instruction structures, `inst_count' items long
 *
 * XXX: note that we do not make any checks on what instructions are executed
 *      before. that is, if you know for sure there have been `backcount'
 * instructions executed before, then we guarantee that those were the ones we
 * return to you. but we do not guarantee that there were infact `backcount'
 * instructions executed. also note that if you have not completely parsed the
 * function `func' yet, and only a partial tree is available to us through
 * `root', then there may be cases in which we cannot provide a correct answer
 * to you. for normal flow graphs which fullfil the subcontainment criteria
 * (i.e. no goto's to within loops, only out of), then we most likely give you
 * the correct answer, when you build the tree using the _breakup functions.
 */

ia32_instruction *
ia32_func_inst_traceup (int backcount, int *inst_count, ia32_function *func,
	ia32_bblock *root, ia32_bblock *cur, unsigned int end_vaddr);


/* ia32_func_inst_count
 *
 * count number of instructions between the virtual address `vstart' and `vend'
 * within function `func'.
 *
 * return number of instructions counted
 */

unsigned int
ia32_func_inst_count (ia32_function *func, unsigned int vstart,
	unsigned int vend);


/* ia32_func_bblock_backrefs
 *
 * create a list of the bblockes that may lead to `cur'. do this by walking
 * all bblockes starting from `root'. `br_count' is where the number of
 * bblockes found is stored.
 *
 * return the bblock list on success, which is `br_count' items long
 *    when `br_count' is zero, the return value may be NULL.
 */

ia32_bblock **
ia32_func_bblock_backrefs (int *br_count, ia32_bblock *root, ia32_bblock *cur);


/* ia32_func_br_mustexec
 *
 * locate the bblockes of the function `func' that must be executed in any
 * possible execution path. `br_count' must be non-NULL.
 *
 * return list of bblockes, `br_count' items long.
 */

ia32_bblock **
ia32_func_br_mustexec (ia32_function *func, unsigned int *br_count);


/* ia32_func_br_sp_list
 *
 * search the function `func' for one of the shortest execution path between
 * `source' and `dest'. `brl_len' can be NULL, then just the list is returned,
 * which cannot be walked, only used as a "is there a path" indicator.
 *
 * return the path list, which is `brl_len' items long on success
 * return NULL on failure
 */

ia32_bblock **
ia32_func_br_sp_list (ia32_function *func, unsigned int *brl_len,
	ia32_bblock *source, ia32_bblock *dest);


/* ia32_func_br_sp
 *
 * compute the shortest path array for the bblock list `brl', which is
 * `brl_length' items long. use the `brl_source' item as path source and store
 * the edge-length array into `patharray'. when there is no path to a node,
 * the path array entry will contain (-1).
 *
 * return list of bblockes in one of the shortest pathes, `br_count' items long
 */

void
ia32_func_br_sp (ia32_bblock **brl, unsigned int brl_length,
	unsigned int brl_source, int *patharray);


/* ia32_func_xref_count
 *
 * count the number of cross references of type `xref_type' appearing in the
 * whole function list `flist', which is `flist_count' items long.
 *
 * return number of cross references counted (zero if none)
 */

unsigned int
ia32_func_xref_count (ia32_function **flist, unsigned int flist_count,
	int xref_type);


/* ia32_func_oxref_findfrom
 *
 * same as ia32_func_xref_findfrom, just for other crossreferences.
 */

ia32_xref *
ia32_func_oxref_findfrom (ia32_function *func, unsigned int vaddr_from);


/* ia32_func_oxref_add
 *
 * add other cross reference to function `func' at relative function body
 * index `relofs'. all further info is pulled from `rel'.
 *
 * return in any case
 */

void
ia32_func_oxref_add (ia32_function *func, unsigned int relofs, elf_reloc *rel);


/* ia32_func_xref_add
 *
 * add a cross reference into the function `func'. the xref was found at `at',
 * goes to `to', and is referencing to the function `called', which can be
 * NULL. do not check whether the xref is already existant in `func'. the type
 * of the reference added is given by `totype'. `addend' + `at' is where the
 * real relocation happens. when `rel' is non-NULL the original Elf32_Rel
 * structure is copied from there into the xref. when `inter_section' is
 * non-zero, the reference crosses section boundaries (which limits further
 * processing, such as hidden function analysis).
 *
 * return a pointer to the newly created structure (can be ignored normally)
 */

ia32_xref *
ia32_func_xref_add (ia32_function *func, int totype,
	unsigned int at, unsigned int addend, unsigned int to,
	ia32_function *called, Elf32_Rel *rel, int inter_section);


/* ia32_func_find_bblock_byrelofs
 *
 * find the bblock that covers the relative offset `relofs' from function body
 * start of function `func'.
 *
 * return found bblock on success
 * return NULL on failure
 */

ia32_bblock *
ia32_func_find_bblock_byrelofs (ia32_function *func, unsigned int relofs);


/* br_xref_fromfunc
 *
 * sort in all other relocations happening within function `func' into the
 * corresponding bblockes for easier/faster access on bblock level.
 *
 * return in any case
 */

void
ia32_func_oxref_fromfunc (ia32_function *func);


/* ia32_func_list_find_bymem
 *
 * find a function by its position in memory. look through the list `flist',
 * which is `flist_count' items long, for the functino that is at `memstart'
 * within the current process.
 *
 * return NULL on failure
 * return function on success
 */

ia32_function *
ia32_func_list_find_bymem (ia32_function **flist, unsigned int flist_count,
	unsigned char *memstart);


/* ia32_func_list_find_bystart
 *
 * find a function starting at address `start' from the list `flist', which is
 * `flist_count' items long.
 *
 * return ia32_function * pointer on success
 * return NULL on failure
 */

ia32_function *
ia32_func_list_find_bystart (ia32_function **flist, unsigned int flist_count,
	unsigned int start);


/* ia32_func_list_walk
 *
 * call function `walk' for any function within the function list `flist',
 * which is `flist_count' items long.
 *
 * return in any case
 */

void
ia32_func_list_walk (ia32_function **flist, unsigned int flist_count,
	void (* walk)(ia32_function *));


/* ia32_func_list_find_byname
 *
 * find the functio named `fname' from the function list `flist', which is
 * `flist_count' items long.
 *
 * return pointer to ia32_function structure on success
 * return NULL on failure
 */

ia32_function *
ia32_func_list_find_byname (ia32_function **flist, unsigned int flist_count,
	char *fname);


/* ia32_func_list_find_index
 *
 * convenience function, find the function `func' in the function list `flist',
 * which is `flist_count' items long.
 *
 * return index found on success
 * return -1 on failure
 */

int
ia32_func_list_find_index (ia32_function **flist, unsigned int flist_count,
	ia32_function *func);


/* ia32_func_list_dump
 *
 * dump the function list `flist' to stdout. the list is `flist_count' entries
 * long.
 *
 * return in any case
 */

void
ia32_func_list_dump (ia32_function **flist, unsigned int flist_count);


/* ia32_graphviz_func_out
 *
 * output the function dependancy relationships described by `flist', which is
 * `flist_count' items long in .dot graphviz format. output to file identified
 * with file pointer `fp', which has to be open already, and will remain open
 * when this function returns. `reloc_text' can be NULL, if it is given, then
 * external references can be displayed seperatly with referenced symbol name.
 *
 * return in any case
 */

void
ia32_graphviz_func_out (FILE *fp, ia32_function **flist,
	unsigned int flist_count, elf_reloc_list *reloc_text);


/* ia32_graphviz_func_out_calltree
 *
 * like ia32_graphviz_func_out, but only consider the calltrees reaching down
 * to function `interest'.
 *
 * return in any case
 */

void
ia32_graphviz_func_out_calltree (FILE *fp, ia32_function **flist,
	unsigned int flist_count, ia32_function *interest);

#endif

