/* objwriter.c - ELF relocateable/relinkable object file writing code
 * include file
 *
 * by scut / teso
 */

#ifndef	OBJWRITER_H
#define	OBJWRITER_H

#include <elf/elf_base.h>
#include <ia32/ia32-function.h>


/* parameters passing structure used when doing obfuscation. will grow over
 * time.
 */
typedef struct {
	/* entangle_basic = flag, when set, basic blocks of functions are
	 * randomized in order, thus making the functions overlapping. will
	 * break basic cfg analysis for code which is suspected to be compiler
	 * generated. the cfg's are not merged though, and are easily
	 * seperateable with a more hostile-orientied cfg analysis.
	 */
	unsigned int	entangle_basic;

	/* insert junk instructions between instructions
	 * junk_rate is the instruction spill rate.
	 */
	unsigned int	junk_instructions;
	double		junk_rate;

	/* if non-zero, junk instructions are marked by prepending a nop
	 * before each one
	 */
	unsigned int	junk_debug;

	/* if non-zero, random basic block splitting will be done
	 */
	unsigned int	split_blocks;

	/* if 'split_blocks' is non-zero, this factor gives the rate at which
	 * splitting will be done for each split step. it is in the range of
	 * 0.0 to 1.0, where 0.0 means no blocks will be split and 1.0 means
	 * every block will be split.
	 */
	double		split_factor;

	/* for every split a coin with probability 'split_opaque_cond_copy' is
	 * thrown. if it hits, the rest of the otherwise splitted basic block
	 * is duplicated and a random conditional jump is inserted.
	 */
	int		split_opaque_cond_copy_set;
	double		split_opaque_cond_copy;

	/* for every basic block the number of possible instruction swaps are
	 * considered if 'instruction_swap' is non-zero. then, of all possible
	 * swaps, 'instruction_swap_rate' exchanges are performed.
	 */
	int		instruction_swap;
	double		instruction_swap_rate;
} obfuscation_param;


/* obj_write
 *
 * create a new ELF object file. the center of this operation is the correct
 * writeout of the functions listed in `flist' (and only those will be written
 * out). also the data segments, given through `base', will be written out. a
 * minimal but working symbol table is created. this is intended for small
 * link-time objects only, not for entire self-contained binary-like objects.
 * the file will be created as `filename'.
 *
 * return 0 in case of success
 * return non-zero in case of failure
 */

int
obj_write (char *filename, elf_base *base,
	ia32_function **flist, unsigned int flist_count,
	obfuscation_param *obf);


/* obj_bblist_build
 *
 * build a list of all basic blocks for all functions in `flist'. return the
 * size of the created list through `count'.
 *
 * return the list on success
 * return NULL on failure
 */

ia32_bblock **
obj_bblist_build (ia32_function **flist, unsigned int flist_count,
	unsigned int *count);

/* obj_write_func
 *
 * write a single broken up function `func' to the file `fp'. use `base' as
 * helper information. note that we clobber stuff in both the function header
 * and the basic block headers. `code_sec_start' is the absolute file position
 * this code section starts at.
 *
 * return zero on success
 * return non-zero on failure
 */

int
obj_write_func (FILE *fp, elf_base *base, ia32_function *func,
	unsigned int code_sec_start);


/* obj_flist_memlift
 *
 * lift all basic blocks in all functions `flist', which is `flist_count'
 * items long. this allocates memory for all basic blocks, so they can be
 * freely moved.
 *
 * return in any case
 */

void
obj_flist_memlift (ia32_function **flist, unsigned int flist_count);


/* obj_write_funclist
 *
 * pedant to obj_write_func, but for multiple functions. this function
 * streamlines all the functions mentioned in `flist', with the basic block
 * order randomized. `flist' is `flist_count' items long. also, the symbol
 * entry for each function will be set to the correct function entry point,
 * but with a zero size, as there are no clear function borders anymore.
 * the functions are written to `fp'. the current position of `fp' within the
 * current code section is given by `code_sec_start'.
 *
 * return zero on success
 * return non-zero on failure
 */

int
obj_write_funclist (FILE *fp, elf_base *base, ia32_function **flist,
	unsigned int flist_count, unsigned int code_sec_start,
	obfuscation_param *obf);


/* obj_bblock_copy_reloc
 *
 * copy all other_xref relocations of basic block `bb' over to a new array.
 *
 * return the new array on success
 * return NULL if there was nothing to copy
 */

ia32_xref **
obj_bblock_copy_reloc (ia32_bblock *bb);


/* obj_bblock_split_reloc
 *
 * if `bb1' was just shortened and still holds relocation information
 * belonging to `bb2', the relocations are distributed among `bb1' and `bb2'.
 *
 * return in any case
 */

void
obj_bblock_split_reloc (ia32_bblock *bb1, ia32_bblock *bb2);


/* obj_bblock_move_reloc
 *
 * move all relocations of the basic block `bb' that lie inbetween `i_start'
 * and `i_start' + `i_len' by `move_offset' bytes to the left/right. if
 * `dont_touch' is non-NULL, an integer boolean like array is kept and
 * relocations with non-zero at their index in the bb->other_xref array will
 * be ignored. a non-zero value will be stored in the array for each
 * relocation moved.
 *
 * return in any case
 */

void
obj_bblock_move_reloc (ia32_bblock *bb, unsigned int i_start,
	unsigned int i_len, int move_offset, int *dont_touch);


/* obj_func_find_syment
 *
 * find the symbol table entry of function `func' within the elf object
 * `base'.
 *
 * return the direct in-section-memory pointer to the matching symbol table
 *    entry.
 */

Elf32_Sym *
obj_func_find_syment (elf_base *base, ia32_function *func);


/* obj_ia32_instruction_expand
 *
 * grow the displacement part of the instruction found at `mem' to full 32
 * bits. when simple expansion is impossible, translate instructions to
 * equivalent ones. then store the displacement. the basic block `bb' is given
 * to correct its information upon translation, such as the last instruction
 * length. the new displacement `displ_new' is corrected and stored into
 * memory.
 *
 * return the positive number of bytes grown on success.
 * return the negative number of bytes needed in case there is not enough
 *    room.
 */

int
obj_ia32_instruction_expand (ia32_bblock *bb, unsigned char *mem,
	int displ_new);


/* obj_calculate_bblock_mem
 *
 * insert the ia32_bblock.mem element into each basic block of every function
 * within `flist', which is `flist_count' items long.
 *
 * return in any case
 */

void
obj_calculate_bblock_mem (ia32_function **flist, unsigned int flist_count);

#endif


