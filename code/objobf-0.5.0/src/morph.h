/* morph.h - burneye code morphing functionality, include file
 *
 * by scut
 */

#ifndef	MORPH_H
#define	MORPH_H

#define	MORPH_VERSION	"0.0.1"


typedef struct {
	ia32_function **	flist;
	unsigned int		flist_count;

	ia32_function *		func;
	ia32_bblock *		bblock;
} morph;


/* morph_abstract
 *
 * move all functions and bblockes to extra allocated memory blocks.
 *
 * return number of bytes allocated
 */

unsigned int
morph_abstract (morph *mr);


/* morph_br_extend
 *
 * extend the current morphed bblock in `mr' by `len' bytes at its end.
 *
 * XXX: note that the last extended bytes are set to nop (0x90), hence you have
 *	to modify them directly afterwards, else further bblock morphing
 *	operations will not work.
 * return in any case
 */

void
morph_br_extend (morph *mr, int len);


/* morph_br_fix
 *
 * fix the current bblock of `mr' within the function `func' to correct all
 * bblock mappings (i.e. convert abstract bblock pointers to instruction level)
 *
 * return in any case
 */

void
morph_br_fix (morph *mr, ia32_function *func);


/* morph_func_sort
 *
 * sort the function list array within `mr' by virtual start addresses
 *
 * return in any case
 */

void
morph_func_sort (morph *mr);


/* morph_br_sort
 *
 * sort bblock array `brlist', which is `br_len' items long by the virtual
 * start address
 *
 * return in any case
 */

void
morph_br_sort (ia32_bblock **brlist, unsigned int br_len);


/* morph_displ_boundcheck
 *
 * check whether the displacement value `displ_val' will fit into an
 * instruction displacement encoding of `displ_size' bits.
 *
 * return 0 if it does fit
 * return 1 if it is out of bounds
 */

int
morph_displ_boundcheck (int displ_val, unsigned int displ_size);

#endif

