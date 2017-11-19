/* morph.c - burneye code morphing functionality
 *
 * by scut
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <common.h>
#include <ia32-decode.h>
#include <ia32-function.h>
#include <morph.h>


/*** static prototypes
 */

static void
morph_br_fix_front (morph *mr, ia32_function *func, ia32_bblock *br);

static void
morph_br_fix_inst (ia32_function *func, ia32_bblock *br, int endbr_num);

static int
morph_func_sort_2 (void *e1, void *e2);

static int
morph_br_sort_2 (void *e1, void *e2);


/*** implementation
 */

unsigned int
morph_abstract (morph *mr)
{
	unsigned int	n;
	unsigned int	newsize,
			allsize = 0;
	unsigned char *	newdata;


	for (n = 0 ; n < mr->flist_count ; ++n) {
		newsize = mr->flist[n]->end - mr->flist[n]->start;

		newdata = xcalloc (1, newsize);
		memcpy (newdata, mr->flist[n]->mem, newsize);
		mr->flist[n]->mem = newdata;

		allsize += newsize;
	}

	return (allsize);
}


void
morph_br_extend (morph *mr, int len)
{
	unsigned int	n,	/* temporary index */
			bn,	/* bblock index into bblock array (pivot) */
			fn;	/* function index into array (pivot) */
	ia32_function *	func;	/* function that contains the morphed bblock */
	ia32_bblock **	brl;	/* bblock list of function, brl_count items */
	unsigned int	brl_count;


	if (len == 0)
		return;

	morph_func_sort (mr);
	assert (mr->flist_count < 2 || mr->flist[0]->start <= mr->flist[1]->start);

	for (fn = 0 ; fn < mr->flist_count &&
		ia32_trace_range (mr->flist[fn]->start, mr->flist[fn]->end,
		mr->bblock->start) == 0 ; ++fn)
		;
	assert (fn < mr->flist_count);

	/* now we have located the function the bblock-extension is occuring
	 * in, lets get all bblockes and find the modified one
	 */
	func = mr->flist[fn];
	brl = ia32_br_get_all (func->br_root, &brl_count);
	morph_br_sort (brl, brl_count);

	for (bn = 0 ; bn < brl_count && ia32_trace_range (brl[bn]->start,
		brl[bn]->end, mr->bblock->start) == 0 ; ++bn)
		;
	assert (bn < brl_count);

	/* extend current bblock, zero extended space and then move all
	 * bblockes that come after it
	 */
	if (len > 0)
		func->mem = xrealloc (func->mem,
			func->end - func->start + len);

	memmove (&func->mem[mr->bblock->end - func->start + len],
		&func->mem[mr->bblock->end - func->start],
		func->end - mr->bblock->end);

	if (len > 0)
		memset (&func->mem[mr->bblock->end - func->start],
			0x90, len);


	mr->bblock->end += len;
	assert (mr->bblock->start < mr->bblock->end);
	mr->bblock->last_unused = len;

	for (n = bn + 1 ; n < brl_count ; ++n) {
		brl[n]->start += len;
		brl[n]->end += len;
	}

	/* the bblockes are relocated for now, but still dangle by instruction.
	 * first move all following functions, then fixup first the bblockes,
	 * then all functions.
	 */
	for (n = fn + 1 ; n < mr->flist_count ; ++n) {
		mr->flist[n]->start += len;
		mr->flist[n]->end += len;
	}

	morph_br_fix (mr, func);
/*FIXME	morph_func_fix (mr); */

	free (brl);

	return;
}


void
morph_br_fix (morph *mr, ia32_function *func)
{
	unsigned int	n,
			bn;
	ia32_bblock **	brl;	/* bblock list of function, brl_count items */
	unsigned int	brl_count;


	brl = ia32_br_get_all (func->br_root, &brl_count);
	morph_br_sort (brl, brl_count);

	for (bn = 0 ; bn < brl_count && ia32_trace_range (brl[bn]->start,
		brl[bn]->end, mr->bblock->start) == 0 ; ++bn)
		;
	assert (bn < brl_count);

	for (n = 0 ; n < brl_count ; ++n) {
		if (n == bn && brl[bn]->last_unused < 0) {
			fprintf (stderr, "cannot fix last instruction, negative dangling\n");
			continue;
		}

		morph_br_fix_front (mr, func, brl[n]);
	}
}


static void
morph_br_fix_front (morph *mr, ia32_function *func, ia32_bblock *br)
{
	switch (br->endtype) {
	case (BR_END_IF):
		morph_br_fix_inst (func, br, 1);
		break;

	case (BR_END_TRANSFER):
		morph_br_fix_inst (func, br, 0);
		break;

	/* cases we can safely ignore
	 * BR_END_IF_INTER we can ignore because the control flow change
	 *   happens to another function, not at bblock level
	 */
	case (BR_END_RET):
	case (BR_END_PASS):
	case (BR_END_CALL):
	case (BR_END_FUNCPTR_CALL):
	case (BR_END_FUNCPTR_JUMP):
	case (BR_END_IF_INTER):
	case (BR_END_TRANSFER_INTER):
	case (BR_END_UNPREDICT):
	case (BR_END_CTRL_SYSCALL):
	case (BR_END_CTRL_SYSCALL_END):
	default:
		break;
	}
}


static void
morph_br_fix_inst (ia32_function *func, ia32_bblock *br, int endbr_num)
{
	unsigned char *		dest;
	unsigned int		vaddr_inst;
	unsigned int		daddr_current,
				daddr_correct;
	ia32_instruction *	inst,
				inst_s;
	unsigned int		displ_relofs,
				displ_size;
	int			displ_new;


	vaddr_inst = br->end - br->last_unused - br->last_ilen;
	dest = &func->mem[vaddr_inst - func->start];
	inst = ia32_decode_instruction (dest, &inst_s);
	assert (inst != NULL);

	daddr_current = ia32_trace_control (inst, dest, vaddr_inst, NULL,
		NULL);
	daddr_correct = br->endbr[endbr_num]->start;

	if (daddr_current == daddr_correct)
		return;

	fprintf (stderr, "_fix_inst: instruction at 0x%08x\n"
		"\tdestaddr current = 0x%08x\n"
		"\tdestaddr correct = 0x%08x\n"
		"\tbblock unused    = 0x%08x\n",
		vaddr_inst, daddr_current, daddr_correct, br->last_unused);

	/* get the position and size of the displacement, then adjust it
	 * in-place
	 */
	displ_relofs = ia32_has_displacement (inst, &displ_size);
	assert (displ_relofs != 0);

	fprintf (stderr, "\t%d bit displacement at: 0x%08x + %d\n",
		displ_size, vaddr_inst, displ_relofs);

	displ_new = daddr_correct;
	displ_new -= vaddr_inst + inst->length;
	fprintf (stderr, "\told displacement: 0x%08x\n"
		"\tnew displacement: 0x%08x\n",
		inst->opc.displ_value, displ_new);

	assert (morph_displ_boundcheck (displ_new, displ_size) == 0);
	ia32_encode_value (dest + displ_relofs, displ_size, displ_new);

	return;
}


int
morph_displ_boundcheck (int displ_val, unsigned int displ_size)
{
	int	bytes;
	int	valid_up[] = { 0, 0x7f, 0x7fff, 0, 0x7fffffff };
	int	valid_down[] = { 0, -0x80, -0x8000, 0, -0x80000000 };


	bytes = ia32_bit_to_byte (displ_size);

	if (displ_val > valid_up[bytes])
		return (1);

	if (displ_val < valid_down[bytes])
		return (1);

	return (0);
}


void
morph_func_fix (morph *mr)
{
}


void
morph_func_sort (morph *mr)
{
	qsort (mr->flist, mr->flist_count, sizeof (mr->flist[0]),
		(int (*)(const void *,const void*)) morph_func_sort_2);
}


static int
morph_func_sort_2 (void *e1, void *e2)
{
	ia32_function *	f1 = *((ia32_function **) e1);
	ia32_function *	f2 = *((ia32_function **) e2);


	if (f1->start == f2->start)
		return (0);

	if (f1->start < f2->start)
		return (-1);

	return (1);
}


void
morph_br_sort (ia32_bblock **brlist, unsigned int br_len)
{
	qsort (brlist, br_len, sizeof (brlist[0]),
		(int (*)(const void *, const void *)) morph_br_sort_2);
}


static int
morph_br_sort_2 (void *e1, void *e2)
{
	ia32_bblock *	b1 = *((ia32_bblock **) e1);
	ia32_bblock *	b2 = *((ia32_bblock **) e2);


	if (b1->start == b2->start)
		return (0);

	if (b1->start < b2->start)
		return (-1);

	return (1);
}

