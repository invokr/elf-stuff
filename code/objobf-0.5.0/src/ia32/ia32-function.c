/* ia32-function.c - ia32 function abstraction layer
 *
 * by scut
 */

#include <asm/unistd.h>

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <common.h>
#include <ia32-debug.h>
#include <ia32-function.h>


/*** static prototypes
 */
static void
ia32_func_copy (ia32_function *target, ia32_function *source, char *name);

static ia32_function **
ia32_func_treeplain_fixreloc (ia32_function *func, elf_reloc_list *rel,
	ia32_function **flist, unsigned int flist_count,
	unsigned int *nfcount);

static ia32_bblock **
ia32_func_br_sp_list_2 (ia32_bblock **btl, unsigned int btl_len,
	ia32_function *func, unsigned int *brl_len,
	ia32_bblock *source, ia32_bblock *dest);

static ia32_bblock *
ia32_func_br_sp_list_3 (ia32_bblock **brl, unsigned int brl_len,
	unsigned int idx, int *sparr);

static void
ia32_func_br_sp_2 (ia32_bblock **brl, unsigned int brl_length,
	unsigned int brl_cur, int *patharray);

static int
ia32_func_breakup_2 (ia32_function *func, ia32_bblock *root,
	ia32_bblock *this, elf_reloc_list *rel_code, elf_reloc_list *rel_rodata,
	ia32_bblock **all, unsigned int all_count);

static void
ia32_graphviz_func_out_2 (FILE *fp, ia32_function **flist,
	unsigned int flist_count, int *flist_consider,
	elf_reloc_list *reloc_text);

static char *
ia32_graphviz_func_out_extern (FILE *fp, ia32_function *func,
	ia32_xref *xr, elf_reloc_list *reloc_text);

static void
ia32_graphviz_func_out_intern (FILE *fp, ia32_function *func, ia32_xref *xr,
	ia32_function **flist, unsigned int flist_count,
	int *flist_consider);

static int
ia32_func_switchtable_is (ia32_instruction *inst);

#ifdef	DUPE_DEBUG
void dupe_alloc (unsigned int max_addr);
void dupe_free (void);
void dupe_check (unsigned int addr);

/* global enable flag. can be used to selectivly drop certain sections
 */
int		dupe_check_enabled = 0;
unsigned int *	addr_arr = NULL;
unsigned int	addr_max = 0;
unsigned int	addr_ac = 1;	/* sequential access counter */
#endif

int	ia32_graphviz_align_undefined = 0;


extern char *	ia32_regs_wide[];

/*** implementation
 */

ia32_xref *
ia32_xref_new (void)
{
	return (xcalloc (1, sizeof (ia32_xref)));
}


ia32_function *
ia32_func_new (void)
{
	return (xcalloc (1, sizeof (ia32_function)));
}


ia32_xref *
ia32_func_xref_add (ia32_function *func, int totype,
	unsigned int at, unsigned int addend, unsigned int to,
	ia32_function *called, Elf32_Rel *rel, int inter_section)
{
	unsigned int	n;
	ia32_xref *	xref;


	ia32_debug (IA32_DEBUG, "ia32_func_xref_add: from 0x%08x to 0x%08x, "
		"type %d\n", at + addend, to, totype);
	/*if (to > 0x08000000)
		ia32_confirm ();*/

	for (n = 0 ; n < func->func_xref_count ; ++n) {
		if ((func->func_xref[n]->from + func->func_xref[n]->addend) ==
			(at + addend))
		{
			ia32_debug (IA32_WARNING,
				"ia32_func_xref_add: double xref at 0x%08x\n",
				to);
		}
	}

	xref = ia32_xref_new ();
	if (rel != NULL) {
		memcpy (&xref->orig, rel, sizeof (Elf32_Rel));
		xref->original_relocation = 1;
	}

	xref->from = at;
	xref->addend = addend;
	xref->to = to;
	xref->to_type = totype;
	xref->to_data = called;
	xref->inter_section = inter_section;

	func->func_xref_count += 1;
	func->func_xref = xrealloc (func->func_xref, func->func_xref_count *
		sizeof (ia32_xref *));
	func->func_xref[func->func_xref_count - 1] = xref;

	return (xref);
}


ia32_xref *
ia32_func_xref_findfrom (ia32_function *func, unsigned int vaddr_from)
{
	unsigned int	xrn;


	for (xrn = 0 ; xrn < func->func_xref_count ; ++xrn) {
		if (func->func_xref[xrn]->from == vaddr_from)
			return (func->func_xref[xrn]);
	}

	return (NULL);
}


unsigned int
ia32_func_xref_count (ia32_function **flist, unsigned int flist_count,
	int xref_type)
{
	unsigned int	fln,
			xrn,
			xref_count = 0;


	for (fln = 0 ; fln < flist_count ; ++fln) {
		for (xrn = 0 ; xrn < flist[fln]->func_xref_count ; ++xrn) {
			if (flist[fln]->func_xref[xrn]->to_type == xref_type)
				xref_count += 1;
		}
	}

	return (xref_count);
}


ia32_bblock *
ia32_func_find_bblock_byrelofs (ia32_function *func, unsigned int relofs)
{
	unsigned int	n;
	unsigned int	brall_count;
	ia32_bblock **	brall;
	ia32_bblock *	br;


	brall = ia32_br_get_all (func->br_root, &brall_count);

	for (n = 0 ; n < brall_count ; ++n) {
		if ((brall[n]->start - func->start) > relofs)
			continue;
		if ((brall[n]->end - func->start) <= relofs)
			continue;

		br = brall[n];
		free (brall);

		return (br);
	}

	free (brall);

	return (NULL);
}


void
ia32_func_list_walk (ia32_function **flist, unsigned int flist_count,
	void (* walk)(ia32_function *))
{
	unsigned int	n;


	for (n = 0 ; n < flist_count ; ++n)
		walk (flist[n]);

	return;
}


/* br_xref_fromfunc
 *
 * sort in all other relocations happening within function `func' into the
 * corresponding bblockes for easier/faster access on bblock level.
 *
 * return in any case
 */

void
ia32_func_oxref_fromfunc (ia32_function *func)
{
	unsigned int	n,
			dst;
	ia32_bblock *	brc;
	ia32_xref **	xrarr;
	ia32_xref *	xrcur;


	if (func->is_copy)
		return;

	/* sort in all other cross references into their corresponding bblockes
	 */
	for (n = 0 ; n < func->other_xref_count ; ++n) {
		assert (func->other_xref[n] != NULL);
		brc = ia32_func_find_bblock_byrelofs (func,
			func->other_xref[n]->from);

		if (brc == NULL) {
			ia32_debug (IA32_WARNING, "WARNING: "
				"(ia32_func_oxref_fromfunc) dangling "
				"relocation in %s:0x%05x, no bblock found\n",
				func->name, func->other_xref[n]->from);
			ia32_debug (IA32_WARNING, "  func: 0x%08x-0x%08x, "
				"no bblock found at 0x%08x\n",
				func->start, func->end,
				func->other_xref[n]->from + func->start);

			/*ia32_debug (IA32_DEBUG, "dumping bblock level\n");
			ia32_br_dump (func->name, func->br_root);
			ia32_debug (IA32_DEBUG, "end of dump\n");*/

			/* leave func->other_xref[n] to non-NULL, so it
			 * at least appears in compressed array below
			 */
			continue;
		}

		assert (brc != NULL);
		brc->other_xref_count += 1;
		brc->other_xref = xrealloc (brc->other_xref,
			brc->other_xref_count * sizeof (ia32_xref *));
		xrarr = brc->other_xref;

		xrcur = func->other_xref[n];
		xrcur->from = (func->start + xrcur->from) - brc->start;
		xrarr[brc->other_xref_count - 1] = xrcur;
		func->other_xref[n] = NULL;
	}

	/* compress now modified func->other_xref array
	 */
	for (dst = 0, n = 0 ; n < func->other_xref_count ; ++n) {
		if (func->other_xref[n] == NULL)
			continue;

		func->other_xref[dst] = func->other_xref[n];
		dst += 1;
	}

	func->other_xref_count = dst;

	/* FIXME: remove this pseudo-assertion once we've found this nasty bug.
	 */
	for (n = 0 ; n < func->other_xref_count ; ++n) {
		assert (func->other_xref[n] != NULL);
	}

	func->other_xref = xrealloc (func->other_xref, func->other_xref_count *
		sizeof (ia32_xref *));

	return;
}


unsigned char *
ia32_func_v2real (ia32_function *func, unsigned int vaddr)
{
	/* kludge: some libraries (e.g. dietlibc) have functions written in
	 *         assembly, that do not have a proper size description and
	 * have their end set to the start address (i.e. zero sized). to work
	 * around this problem, we explicitly check here, and skip all sanity
	 * checking.
	 */
	if (func->start == func->end)
		return (&func->mem[vaddr - func->start]);

	assert (vaddr >= func->start && vaddr < func->end);

	return (&func->mem[vaddr - func->start]);
}


unsigned int
ia32_func_r2virt (ia32_function *func, unsigned int real)
{
	unsigned char *	rptr = (unsigned char *) real;

	/* kludge: see ia32_func_v2real for description
	 */
	if (func->start == func->end)
		return (rptr - func->mem);

	assert (rptr >= func->mem &&
		rptr < (func->mem + (func->end - func->start)));

	return (rptr - func->mem);
}


ia32_function *
ia32_func_findcopy (ia32_function *func,
	ia32_function **flist, unsigned int flist_count)
{
	unsigned int	n;


	ia32_debug (IA32_DEBUG, "DEBUG: (ia32_func_findcopy) checking dupe "
		"between (0x%x-0x%x): %s\n",
		func->start, func->end, func->name);

	for (n = 0 ; n < flist_count ; ++n) {
		if (flist[n]->passed == 0 || flist[n] == func)
			continue;

		if (flist[n]->section_idx != func->section_idx)
			continue;

		if (flist[n]->start == func->start)
			return (flist[n]);

		/* there are situations when two functions are nested, so that
		 * they share the same trailing code. this happens for manually
		 * optimized functions, such as __syscall_error and
		 * __syscall_error_1 within the GNU C library. since they are
		 * exactly the same functions when they have the same starting
		 * address, in case they are nested, it must be a different
		 * address. as we sort the function list before any parsing
		 * operation, we can ensure we have already processed the outer
		 * function.
		 *
		 * the same odd case but reversed: overlapping but not enclosed
		 * functions.
		 *
		 * example: siglongjmp and longjmp within glibc, which both
		 *     have a damaged symbol table entry, something like this:
		 *
		 *    siglongjmp  [0x644b - 0x6491]
		 *    longjmp           [0x6467 - 0x64ad]
		 *
		 * what we do here is that we do not mark the function, but
		 * clear the array of accesses for the overlapping range.
		 * crude solution to an even more crude problem.
		 */
		if ((flist[n]->start > func->start && flist[n]->start < func->end) ||
			(flist[n]->end > func->start && flist[n]->end < func->end) ||
			(flist[n]->start < func->start && flist[n]->end >= func->end))
#if 0
		if ((flist[n]->start < func->start && flist[n]->end >= func->end) ||
			(flist[n]->start < func->start &&
			flist[n]->end <= func->end))
#endif
		{
			func->is_nested = 1;
			ia32_debug (IA32_WARNING, "WARNING: %s is nested\n",
				func->name);

			return (flist[n]);
		}
	}

	return (NULL);
}


/* FIXME: do a deep copy instead of shallowing things
 */
static void
ia32_func_copy (ia32_function *target, ia32_function *source, char *name)
{
	/* since we do not care about memory leaks anyway, just do a shallow
	 * copy and then replace the name
	 */
	memcpy (target, source, sizeof (ia32_function));
	target->name = name;
	target->is_copy = 1;

	return;
}


void
ia32_func_treeplain (ia32_function ***flist, unsigned int *flist_count,
	elf_reloc_list *rel_code, elf_reloc_list *rel_rodata,
	unsigned int code_idx)
{
	unsigned int	n;
	ia32_function *	func;

	ia32_function **	fnl;
	ia32_function *		fcopy;	/* symbolic copy of function */
	unsigned int		fnl_count;


	elf_function_list_sort (*flist, *flist_count);

	/* collect all bblockes of the function
	 */
reparse:
	while ((func = ia32_func_get_unpassed (*flist, *flist_count,
		code_idx)) != NULL)
	{
		ia32_debug (IA32_INFO, "INFO: (ia32_func_treeplain) "
			"breaking up: %s (0x%x-0x%x)\n", func->name,
			func->start, func->end);

		/* try to locate a symbolic copy. for example, in glibc, the
		 * __srandom function is aliased as srand, too. so, only
		 * decode one, and make the other function an alias. note that
		 * we cannot just drop one, because a relocation might refer
		 * to it using its symbol table entry
		 */
		fcopy = ia32_func_findcopy (func, *flist, *flist_count);
		if (fcopy != NULL && func->is_nested == 0) {
			ia32_func_copy (func, fcopy, func->name);
			func->passed = 1;
			ia32_debug (IA32_INFO, "INFO: (ia32_func_treeplain) "
				"\"%s\" is an alias of \"%s\"\n",
				func->name, fcopy->name);

			continue;
		} else if (fcopy != NULL && func->is_nested == 1) {
			ia32_debug (IA32_WARNING, "WARNING: "
				"(ia32_func_treeplain) %s is nested within "
				"%s, address checks disabled\n",
				func->name, fcopy->name);
		}

		func->br_root = ia32_func_breakup (func, rel_code, rel_rodata);
		ia32_debug (IA32_DEBUG, "\t=> %-10u xrefs\n",
			func->func_xref_count);
		func->passed = 1;
	}

	/* fix cross references
	 */
	for (n = 0 ; n < *flist_count ; ++n) {
		/* FIXME:SEC */
		if ((*flist)[n]->section_idx != code_idx)
			continue;

		if ((*flist)[n]->is_copy)
			continue;

		fnl = ia32_func_treeplain_fixreloc ((*flist)[n], rel_code,
			*flist, *flist_count, &fnl_count);

		if (fnl_count == 0)
			continue;

		*flist = xrealloc (*flist, (*flist_count + fnl_count) *
			sizeof (ia32_function *));
		memcpy (&((*flist)[*flist_count]), fnl,
			fnl_count * sizeof (ia32_function *));
		*flist_count += fnl_count;
		free (fnl);

		elf_function_list_sort (*flist, *flist_count);
		ia32_debug (IA32_INFO, "WARNING: (ia32_func_treeplain) "
			"reparsing functions\n");

		goto reparse;
	}

	return;
}


static ia32_function **
ia32_func_treeplain_fixreloc (ia32_function *func, elf_reloc_list *rel,
	ia32_function **flist, unsigned int flist_count,
	unsigned int *nfcount)
{
	unsigned int	xc,
			dst,
			rn;
	ia32_xref *	xref;
	elf_reloc *	reloc;
	unsigned int	rfunc_offset;	/* relative to function offset */

	ia32_function *		fnew;
	ia32_function **	new_flist = NULL;
	unsigned int		new_flist_count = 0,
				fwn;
	int			need_compress = 0;


	assert (func->is_copy == 0);

	for (xc = 0 ; xc < func->func_xref_count ; ++xc) {
		ia32_function *	coverfunc;


		xref = func->func_xref[xc];

		/* in case its refering an external function we cannot provide
		 * the ia32_function pointer, so set it to NULL, humm...
		 */
		if (xref->to_type == IA32_XREF_FUNCEXTERN) {
			ia32_debug (IA32_INFO, "extern function reference from "
				"0x%08x (%s)\n", xref->from, func->name);

			xref->to_data = NULL;

			continue;
		} else if (xref->to_type == IA32_XREF_FUNCTION) {
			/* FIXME:SEC */
			xref->to_data = ia32_func_list_find_bystart (flist,
				flist_count, xref->to);
		} else {
			assert (0);
		}

		if (xref->to_data != NULL)
			continue;

		/* heuristics: when the reference is to within the function it
		 *             is contained in, then we have some complicated
		 * redirection construct, most likely a complicated
		 * switchtable. see _IO_vfprintf code within glibc for an
		 * example:
		 *     0x0001bbc8 b827cd0100     mov     eax, 0x1cd27
		 *     0x0001bbcd e9a71b0000     jmp     0x1d779
		 *     ...
		 *     0x0001d779 ffe0           jmp     eax
		 *
		 * at the time we see the mov, we cannot be sure it is a
		 * function pointer or a in-function address. this is because
		 * the function could be processed in tracing mode, without
		 * known function boundaries. so step back at that time, and
		 * process such references now, after the boundaries are known.
		 *
		 * so, first test whether the reference is to within the own
		 * function. if it is, there are two cross references, added
		 * from ia32_func_breakup_2, one function xref, and one other
		 * xref. we need to remove the function cross reference, but
		 * conserve the other cross reference, but marking it as code
		 * related crossreference.
		 */
		if (ia32_trace_range (func->start, func->end, xref->to)) {
			ia32_xref *	oxf;
			ia32_xref *	carry_tmp;	/* temp. holder */

			ia32_debug (IA32_INFO, "INFO: internal function "
				"reference from %s to %s (0x%x)\n",
				func->name, func->name, xref->to);

			/* remove function crossreference. do the free later,
			 * as 'xref' still references to it.
			 */
			carry_tmp = func->func_xref[xc];
			func->func_xref[xc] = NULL;
			need_compress = 1;

			/* find the related other crossreference, and mark it
			 * as code related. note that other crossreference do
			 * not have addends, function xrefs do. so sum both.
			 */
			oxf = ia32_func_oxref_findfrom (func,
				xref->from + xref->addend);
			assert (oxf != NULL);
			oxf->other_subtype = IA32_XREF_O_FUNCTIONINTERN;

			free (carry_tmp);

			continue;
		}

		/* when the function is within another section, skip over the
		 * hidden function detection.
		 */
		if (xref->inter_section)
			continue;

		/* heuristics: some static functions used only locally within
		 *             an ELF object (eg. getopterror within getopt.c
		 * of dietlibc) have no symbol table entry at all. our idea to
		 * catch those functions also is to trace the calltree for
		 * calls to areas not covered by any function in the list.
		 * this is exactly the case we now check for.
		 */
		coverfunc = ia32_func_list_is_covered (xref->to,
			flist, flist_count);
		if (coverfunc != NULL) {
			ia32_debug (IA32_FATAL, "FATAL: "
				"(ia32_func_treeplain_fixreloc) function "
				"reference from %s:0x%x (0x%08x-0x%08x) "
				"to 0x%08x is covered/misaligned by another "
				"function: %s (0x%08x-0x%08x)\n",
				func->name, xref->from,
				func->start, func->end, xref->to,
				coverfunc->name, coverfunc->start,
				coverfunc->end);

			/*continue;*/
			exit (EXIT_FAILURE);
			/* FIXME: this should not happen, exit (EXIT_FAILURE);
			 */
		}

		ia32_debug (IA32_WARNING, "WARNING: "
			"(ia32_func_treeplain_fixreloc) hidden function "
			"detected due to %s:0x%x, entry point: 0x%08x\n",
			func->name, xref->from, xref->to);

		/* avoid duplicate functions within the new ones
		 */
		for (fwn = 0 ; fwn < new_flist_count ; ++fwn)
			if (new_flist[fwn]->start == xref->to)
				break;

		if (fwn < new_flist_count)
			continue;

		/* lets setup a new function definition for the hidden function
		 * FIXME: the fnew->mem stuff is rather ugly ;), as we assume
		 *        the function memory is all continuous
		 */
		fnew = ia32_func_new ();
		xref->to_data = fnew;	/* patch cross reference properly */
		fnew->name = "";
		fnew->start = fnew->end = xref->to;
		fnew->mem = func->mem - func->start + fnew->start;
		/* TODO: remove this once bugs are squashed */
		assert (fnew->mem >= (unsigned char *) 0x08000000 &&
			fnew->mem <= (unsigned char *) 0x50000000);

		fnew->section_idx = func->section_idx;

		new_flist_count += 1;
		new_flist = xrealloc (new_flist,
			new_flist_count * sizeof (ia32_function *));
		new_flist[new_flist_count - 1] = fnew;

		ia32_debug (IA32_DEBUG, "  ==> scheduled for the tracer\n");
	}

	/* compress func_xref array by removing any NULL entries
	 */
	if (need_compress) {
		for (dst = 0, xc = 0 ; xc < func->func_xref_count ; ++xc) {
			if (func->func_xref[xc] == NULL)
				continue;

			func->func_xref[dst] = func->func_xref[xc];
			dst += 1;
		}

		func->func_xref_count = dst;
		func->func_xref = xrealloc (func->func_xref,
			func->func_xref_count * sizeof (func->func_xref[0]));

		assert (func->func_xref_count == 0 || func->func_xref != NULL);
	}

#if 0
	/* OLD, obsolete version. remove soon when other proved correct.
	 * the new version is order-preserving and simpler and easier to
	 * understand
	 */
	if (need_compress) {
		for (xc = 0 ; xc < func->func_xref_count ; ++xc) {
			if (func->func_xref[xc] != NULL)
				continue;

			/* as its unsorted, take it the easy way
			 */
			func->func_xref[xc] =
				func->func_xref[func->func_xref_count - 1];
			func->func_xref_count -= 1;
			--xc;
		}

		func->func_xref = realloc (func->func_xref,
			func->func_xref_count * sizeof (func->func_xref[0]));

		assert (func->func_xref_count == 0 || func->func_xref != NULL);
	}
#endif

	/* now add the non-directly-control flow function cross references.
	 * for example code like this:
	 *      push   function
	 *      call   otherfunc
	 * then a reloc will be emitted by the linker that will insert the
	 * address of function at the correct place. since we do overlays of
	 * basic blocks, we have to insert the address in runtime and hence
	 * need this info.
	 */
	for (xc = 0 ; xc < rel->reloc_count ; ++xc) {
		reloc = rel->reloc[xc];

		if (reloc->offset_rel < func->start ||
			reloc->offset_rel >= func->end)
			continue;

		/* the crossreferences always refer relative to the function
		 * start
		 */
		rfunc_offset = reloc->offset_rel - func->start;

		/* check whether we already have this xref in the function
		 * references
		 */
		for (rn = 0 ; rn < func->func_xref_count ; ++rn) {
			if ((func->func_xref[rn]->from +
				func->func_xref[rn]->addend) == rfunc_offset)
			{
				break;
			}
		}

		if (rn < func->func_xref_count)
			continue;

		/* now we've found a relocation that is happening within the
		 * function body. we add it, since it is currently missing (it
		 * was not mentioned by any control flow instruction from
		 * within the functions code)
		 */
		ia32_debug (IA32_DEBUG, "DEBUG: _oxref_add "
			"(\"%s\", 0x%08x, 0x%08x)\n", func->name,
			rfunc_offset, (unsigned int) reloc);
		ia32_func_oxref_add (func, rfunc_offset, reloc);
	}

	*nfcount = new_flist_count;

	return (new_flist);
}


ia32_function *
ia32_func_list_is_covered (unsigned int vaddr, ia32_function **flist,
	unsigned int flist_count)
{
	unsigned int	n;


	for (n = 0 ; n < flist_count ; ++n) {
		if (flist[n]->is_copy)
			continue;

		if (vaddr >= flist[n]->start && vaddr < flist[n]->end)
			return (flist[n]);
	}

	return (NULL);
}


/* duplicate code, doh!
 */
ia32_xref *
ia32_func_oxref_findfrom (ia32_function *func, unsigned int vaddr_from)
{
	unsigned int	xrn;


	for (xrn = 0 ; xrn < func->other_xref_count ; ++xrn) {
		if (func->other_xref[xrn]->from == vaddr_from)
			return (func->other_xref[xrn]);
	}

	return (NULL);
}


void
ia32_func_oxref_add (ia32_function *func, unsigned int relofs, elf_reloc *rel)
{
	ia32_xref *	xref = ia32_xref_new ();
	unsigned int	wn;


	/* check for duplicates. this is necessary because _oxref_add may be
	 * called multiple times on the same relocation entry at multiple runs
	 * of ia32_func_treeplain_fixreloc.
	 */
	for (wn = 0 ; wn < func->other_xref_count ; ++wn) {
		if (func->other_xref[wn]->from == relofs) {
			ia32_debug (IA32_DEBUG, "DEBUG: equal (%d): in %s: "
				"0x%08x\n", wn, func->name, relofs);

			return;
		}
	}

	memcpy (&xref->orig, &rel->orig, sizeof (Elf32_Rel));

	/* no addend for other cross references
	 */
	xref->from = relofs;
	xref->addend = 0;
	xref->to_type = IA32_XREF_OTHER;
	xref->to_data = (void *) rel;
	assert (rel != NULL);
	xref->rel_addend = rel->addend;

	/* we once had the addend directly read out of memory. nowadays, we
	 * copy it from a once-read rel structure, as the original code may be
	 * properly relocated already. old behaviour was:
	 *
	 * xref->rel_addend = *((unsigned int *) &func->mem[relofs]);
	 */

	func->other_xref_count += 1;
	func->other_xref = xrealloc (func->other_xref, func->other_xref_count *
		sizeof (ia32_xref *));
	func->other_xref[func->other_xref_count - 1] = xref;

	return;
}


ia32_function *
ia32_func_get_unpassed (ia32_function **flist, unsigned int flist_count,
	unsigned int sidx)
{
	unsigned int	n;


	for (n = 0 ; n < flist_count ; ++n)
		if ((sidx == 0 || flist[n]->section_idx == sidx) &&
			flist[n]->passed == 0)
		{
			return (flist[n]);
		}

	return (NULL);
}


ia32_bblock *
ia32_func_br_end (ia32_function *func)
{
	int		n;
	ia32_bblock *	br_end;
	ia32_bblock **	brl;


	brl = ia32_br_get_all (func->br_root, (unsigned int *) &n);

	for (n = n - 1 ; n >= 0 ; --n) {
		if (brl[n]->endtype == BR_END_RET ||
			brl[n]->endtype == BR_END_CTRL_SYSCALL_END)
		{
			break;
		}
	}

	assert (n >= 0);
	br_end = brl[n];
	free (brl);

	return (br_end);
}


ia32_bblock **
ia32_func_br_mustexec (ia32_function *func, unsigned int *br_count)
{
	unsigned int	n,
			bn;
	ia32_bblock *	br_return;

	ia32_bblock **	br_all;
	unsigned int	br_all_count;

	ia32_bblock **	brl_sp;
	unsigned int	brl_sp_count;

	ia32_bblock **	brl_must = NULL;
	unsigned int	brl_must_count = 0;


	/* 1. bblockes that must be executed on every functions run have to lie
	 * on the shortest path
	 */
	br_return = ia32_func_br_end (func);
	brl_sp = ia32_func_br_sp_list (func, &brl_sp_count,
		func->br_root, br_return);
	assert (brl_sp_count > 0);

	/* the startnode must lie in the list for sure
	 */
	brl_must_count += 1;
	brl_must = xrealloc (brl_must, brl_must_count * sizeof (ia32_bblock));
	brl_must[brl_must_count - 1] = func->br_root;

	/* 2. for the nodes that lie on the shortest path - except the start
	 * and end node, there must be no path around them, else they do not
	 * belong to the must-exec nodes
	 */
	br_all = ia32_br_get_all (func->br_root, &br_all_count);

	for (n = 0 ; n < brl_sp_count ; ++n) {
		ia32_bblock *	br_temp;
		ia32_bblock **	sp_temp;


		/* ignore start and end, they must be executed anytime
		 */
		if (brl_sp[n] == func->br_root || brl_sp[n] == br_return)
			continue;

		/* temporarily remove bblock from the "all bblockes" list,
		 * then check if there is a path now, with the bblock removed
		 */
		for (bn = 0 ; bn < br_all_count ; ++bn)
			if (brl_sp[n] == br_all[bn])
				break;
		assert (bn < br_all_count);

		br_temp = br_all[bn];
/*		assert ((br_all_count - bn - 1) > 0);*/

		br_all_count -= 1;
		memmove (&br_all[bn], &br_all[bn + 1], (br_all_count - n) *
			sizeof (ia32_bblock *));

		/* check whether there is a path
		 */
		sp_temp = ia32_func_br_sp_list_2 (br_all, br_all_count, func,
			NULL, func->br_root, br_return);

		if (sp_temp != NULL)
			free (sp_temp);

		/* no path => the bblock must be travelled in any possible case
		 */
		if (sp_temp == NULL) {
			brl_must_count += 1;
			brl_must = xrealloc (brl_must,
				brl_must_count * sizeof (ia32_bblock));
			brl_must[brl_must_count - 1] = br_temp;
		}

		/* fixup the bblock array by inserting the removed bblock again
		 */
		memmove (&br_all[bn + 1], &br_all[bn], (br_all_count - n) *
			sizeof (ia32_bblock *));
		br_all[bn] = br_temp;
		br_all_count += 1;
	}

	free (brl_sp);
	free (br_all);

	/* the endnode also lies always in the list, in case it is not
	 * identical with the start node
	 */
	if (br_return != func->br_root) {
		brl_must_count += 1;
		brl_must = xrealloc (brl_must, brl_must_count *
			sizeof (ia32_bblock));
		brl_must[brl_must_count - 1] = br_return;
	}

	*br_count = brl_must_count;

	return (brl_must);
}


ia32_bblock **
ia32_func_br_sp_list (ia32_function *func, unsigned int *brl_len,
	ia32_bblock *source, ia32_bblock *dest)
{
	ia32_bblock **	btl;
	unsigned int	btl_len;
	ia32_bblock **	br_ret;

	btl = ia32_br_get_all (func->br_root, &btl_len);
	br_ret = ia32_func_br_sp_list_2 (btl, btl_len, func, brl_len,
		source, dest);

	free (btl);

	return (br_ret);
}


static ia32_bblock **
ia32_func_br_sp_list_2 (ia32_bblock **btl, unsigned int btl_len,
	ia32_function *func, unsigned int *brl_len,
	ia32_bblock *source, ia32_bblock *dest)
{
	unsigned int	source_idx,
			dest_idx;
	int *		sp_arr;

	ia32_bblock **	sp_bra = NULL;
	unsigned int	sp_idx;
	unsigned int	brl_len_dummy;


	if (btl_len == 0)
		return (NULL);

	if (brl_len == NULL)
		brl_len = &brl_len_dummy;

	source_idx = ia32_brl_find (btl, btl_len, source);
	dest_idx = ia32_brl_find (btl, btl_len, dest);
	assert (source_idx != -1 && dest_idx != -1);

	sp_arr = xcalloc (btl_len, sizeof (int));
	ia32_func_br_sp (btl, btl_len, source_idx, sp_arr);

	/* ensure there is a path from source to dest, else bail out
	 */
	if (sp_arr[dest_idx] == -1)
		goto bail;

	sp_bra = xcalloc (btl_len, sizeof (ia32_bblock *));
	sp_idx = btl_len - 1;
	sp_bra[sp_idx] = dest;

	while (sp_bra[sp_idx] != source) {
		sp_idx -= 1;

		sp_bra[sp_idx] = ia32_func_br_sp_list_3 (btl, btl_len,
			dest_idx, sp_arr);

		dest_idx = ia32_brl_find (btl, btl_len, sp_bra[sp_idx]);
		assert (dest_idx != -1);
	}

	*brl_len = btl_len - sp_idx;
	memmove (&sp_bra[0], &sp_bra[sp_idx], *brl_len *
		sizeof (ia32_bblock *));
	sp_bra = xrealloc (sp_bra, *brl_len * sizeof (ia32_bblock *));

bail:
	free (sp_arr);

	return (sp_bra);
}


static ia32_bblock *
ia32_func_br_sp_list_3 (ia32_bblock **brl, unsigned int brl_len,
	unsigned int idx, int *sparr)
{
	unsigned int	n,
			bn;


	for (n = 0 ; n < brl_len ; ++n) {
		if (n == idx)
			continue;

		if ((sparr[n] + 1) != sparr[idx])
	      		continue;

		/* now we have a possible node with a correct stepcount, check
		 * whether our node is a subnode of it
		 */
		for (bn = 0 ; bn < brl[n]->endbr_count ; ++bn)
			if (brl[n]->endbr[bn] == brl[idx])
				return (brl[n]);
	}

	assert (n < brl_len);

	return (NULL);
}


void
ia32_func_br_sp (ia32_bblock **brl, unsigned int brl_length,
	unsigned int brl_source, int *patharray)
{
	unsigned int	n;


	/* use a recursing bellman-ford algorithm with constant edge weight of
	 * one. recursive due to adjascent vertex restriction in original
	 * bellman-ford.
	 *
	 * 1. initialization, -1 denotes infinity
	 */
	for (n = 0 ; n < brl_length ; ++n)
		patharray[n] = -1;
	patharray[brl_source] = 0;

	ia32_func_br_sp_2 (brl, brl_length, brl_source, patharray);
}


static void
ia32_func_br_sp_2 (ia32_bblock **brl, unsigned int brl_length,
	unsigned int brl_cur, int *patharray)
{
	unsigned int	n,
			bidx;
	ia32_bblock *	br = brl[brl_cur];


	for (n = 0 ; n < br->endbr_count ; ++n) {
		bidx = ia32_brl_find (brl, brl_length, br->endbr[n]);
		if (bidx == -1 || bidx == brl_cur)
			continue;

		/* 2. relax for each subnode, then recurse
		 */
		if (patharray[bidx] == -1 ||
			patharray[bidx] > (patharray[brl_cur] + 1))
		{
			ia32_debug (IA32_DEBUG, "relax: 0x%08x from "
				"%2d to %2d\n", brl[bidx]->start,
				patharray[bidx], patharray[brl_cur] + 1);

			patharray[bidx] = patharray[brl_cur] + 1;

			ia32_func_br_sp_2 (brl, brl_length,
				bidx, patharray);
		}
	}
}


static int
ia32_func_switchtable_is (ia32_instruction *inst)
{
	if (OD_TEST (inst->opc.used, OP_CONTROL) == 0 ||
		OD_TEST (inst->opc.used, OP_JUMP) == 0)
	{
		return (0);
	}

	if (OD_TEST (inst->opc.used, OP_TARGET) == 0)
		return (0);

	/* it may be somewhat dangerous, but we treat function pointers as
	 * special cases of one-element switch tables :-)
	 */
	if (inst->opc.target_type == OP_TYPE_REG)
		return (1);

	if (inst->opc.target_type != OP_TYPE_MEM)
		return (0);

	/* we either need a table start through a register or through a
	 * displacement. if both are lost, we are lost.
	 */
	if (inst->opc.base == 0 && OD_TEST (inst->opc.used, OP_DISPLACE) == 0)
		return (0);

	if (OD_TEST (inst->opc.used, OP_SIB))
		return (1);

	return (0);
}


ia32_bblock *
ia32_func_breakup (ia32_function *func, elf_reloc_list *rel_code,
	elf_reloc_list *rel_rodata)
{
	ia32_bblock *		root;
	ia32_bblock *		cur = ia32_br_new ();

	/* since the calls to ia32_br_get_all_2 are very expensive (uncached
	 * they take up >95% of program execution time), we cache the lookups
	 * here
	 */
	ia32_bblock **		all = NULL;
	unsigned int		all_count;
	int			cache_isdirty = 1;

	/* functions with zero size length are almost always the result of
	 * manual mangling with function definitions (when writing functions
	 * in assembly). hence, when we stumble over such a function, enable
	 * the tracer mode, in which we try to identify the function
	 * boundaries much like IDA does (by tracing the control flow)
	 *
	 * XXX: note that complex compiler constructs, such as switchtables,
	 *      require the assistance of function-length information still.
	 * it is technically possible to decode such constructs, too, but its
	 * not worth the effort here. to add such decoding, uncomment the
	 * line below and debug what breaks:
	 *
	 * func->end = func->start;
	 */
	if (func->start == func->end) {
		ia32_debug (IA32_WARNING, "WARNING: (ia32_func_breakup) "
			"broken function bounds (zero-sized), using tracer\n");

		func->traced_bounds = 1;
	} else
		func->traced_bounds = 0;

	cur->start = func->start;
	root = cur;

	/* work until all bblockes are passed
	 */
	do {
		if (cache_isdirty) {
			if (all != NULL)
				free (all);

			all = ia32_br_get_all (root, &all_count);
		}

		cur = ia32_br_get_unpassed (all, all_count);
		if (cur == NULL)
			break;

		if (func->end != func->start && cur->start == func->end &&
			func->is_symdamaged == 0 && func->traced_bounds == 0)
		{
			ia32_debug (IA32_WARNING, "WARNING: "
				"(ia32_func_breakup) function \"%s\" ends "
				"abnormaly\n", func->name);

			func->is_abnormal_end = 1;
		}
#ifdef	DUPE_DEBUG
		else if (func->is_nested == 0) {
			dupe_check (cur->start);
		}
#endif
		cache_isdirty = ia32_func_breakup_2 (func, root, cur,
			rel_code, rel_rodata, all, all_count);

		if (func->traced_bounds == 0 && cur->end > func->end) {
			ia32_debug (IA32_WARNING, "WARNING: invalid function "
				"symbol table entry for \"%s\" (tb = %d), "
				"fixing (end: 0x%x to 0x%x)\n",
				func->name, func->traced_bounds,
				func->end, cur->end);
			/*ia32_confirm ();*/

			func->end = cur->end;
			func->is_symdamaged = func->traced_bounds = 1;
		}
	} while (1);

	if (all != NULL) {
		free (all);
		all = NULL;
	}


	if (func->traced_bounds) {
		ia32_bblock *		br;
		ia32_bblock **		br_all;
		unsigned int		br_all_count,
					fend;

		br_all = ia32_br_get_all (root, &br_all_count);
		for (fend = 0 ; br_all_count > 0 ; --br_all_count) {
			br = br_all[br_all_count - 1];
			if (br->end > fend)
				fend = br->end;
		}
		free (br_all);

		func->end = fend;
		ia32_debug (IA32_INFO, "  traced function boundaries: "
			"0x%x-0x%x\n", func->start, func->end);
	}

	return (root);
}


/* this is the heart of the control flow analyzation engine
 */

static int
ia32_func_breakup_2 (ia32_function *func, ia32_bblock *root,
	ia32_bblock *this, elf_reloc_list *rel_code, elf_reloc_list *rel_rodata,
	ia32_bblock **all, unsigned int all_count)
{
	int			tb;	/* tracing bounds */
	ia32_instruction *	inst,	/* helper pointer for inst_s */
				inst_s;	/* instruction structure */
		/* temporary working bblockes */
	ia32_bblock *		work1;	/* temporary work bblock */
	ia32_bblock *		work2;	/* temporary work bblock */
	unsigned int		vaddr;	/* current virtual address */
	unsigned int		destaddr = 0x0,	/* control flow destination */
				rdaddr;	/* relocation destaddr */
	unsigned char *		cur;	/* memory position of vaddr */
	unsigned int		ilen;	/* instruction length */

	/* flags for a single control flow change */
	int			intra;	/* is within current function? */
	int			cond;	/* is condition-based? */
	int			resume;	/* will the call/jmp will resume? */
	unsigned int		swmask;	/* switchmask */
	int			duesplit;
	int			c_volatile,
				switch_fail;
	int			br_splitted,
				rval = 0;	/* return value, helpervalue */
	char			inst_str[64];	/* string representation */



	tb = func->traced_bounds;
	vaddr = this->end = this->start;
	this->passed = 1;
	ilen = 0;

	while (tb || vaddr < func->end) {
	/*	ia32_br_dump (func->name, root); */
		/* relocate and decode current instruction
		 */
		cur = &func->mem[vaddr - func->start];
		inst = ia32_decode_instruction (cur, &inst_s);

		if (inst == NULL) {
			ia32_debug (IA32_WARNING,
				"WARNING: (ia32_func_breakup_2) failed to "
				"decode instruction at 0x%08x, in function "
				"\"%s\"\n",
				vaddr, func->name == NULL ? "__unknown" :
				func->name);
			this->endtype = BR_END_INVALID;

			return (rval);
		}

		/* optionally dump instruction being analyzed (when verbosity
		 * is greater-equal to DEBUG).
		 */
		ia32_sprint (inst, inst_str, sizeof (inst_str));
		ia32_debug (IA32_DEBUG, "\t\t(0x%08x) 0x%08x: %s\n",
			(unsigned int) cur, vaddr, inst_str);

		if (vaddr >= 0x17fef && vaddr <= 0x180a5)
			printf ("XXXSCUT\n");

		ilen = inst->length;

		this->end = vaddr;

		/* we have hit a control instruction, lets get its target, if
		 * possible.
		 */
		if (OD_TEST (inst->opc.used, OP_CONTROL))
			destaddr = ia32_trace_control (inst, cur, vaddr,
				&resume, &c_volatile);

		/* heuristics: there are function pointers passed as data that
		 *   are invisible in the symbol table (local static
		 *   functions). to catch those we rely on at least a generic
		 *   "relative-to-.text" symbol table entry. a good example
		 *   for such code can be found in dietlibc/libstdio/vfprintf.c
		 *   where "__fwrite" is passed to __vfprintf within a struct.
		 */
		if (strcmp (inst->opc.opcode->name, "mov") == 0 &&
			OD_TEST (inst->opc.used, OP_SOURCE | OP_TARGET |
				OP_IMMEDIATE) &&
			inst->opc.source_type == OP_TYPE_IMM &&
			inst->opc.source_width == IA32_WIDTH_WORD &&
			inst->opc.imm_size == IA32_WIDTH_WORD &&
			inst->opc.target_width == IA32_WIDTH_WORD)
		{
			elf_reloc *	rel_el;

			rel_el = elf_reloc_list_lookup (rel_code,
				vaddr + ia32_has_immediate (inst, NULL));

			/* this is the most important criterion in the
			 * heuristic (since any function is relocateable there
			 * have to be relocation entries for their offsets).
			 */
			if (rel_el == NULL)
				goto no_shadowed_fptr;

			assert (rel_el->sym != NULL);

			/* how to handle SHN_COMMON externs ?
			 * easy: we do not allow any common symbol, so
			 * we just bail out
			 */
			if (rel_el->sym->sent.st_shndx == SHN_COMMON) {
				ia32_debug (IA32_FATAL, "  0x%08x: relocation "
				"to \"common\" symbol %s\n", vaddr,
				rel_el->sym->name);

				assert (0);

				/* if you don't want to bail, go here */
				goto no_shadowed_fptr;
			}

			assert (rel_el->sym->sec != NULL);
			assert (rel_el->sym->sec->name != NULL);

			/* FIXME:SEC */
			if (strcmp (rel_el->sym->sec->name, ".text") != 0)
				goto no_shadowed_fptr;

			if (ELF32_R_TYPE (rel_el->orig.r_info) != R_386_32)
				goto no_shadowed_fptr;

			/* add new function cross reference (which will result
			 * in a new function being traced). the addend is the
			 * destination address
			 */
			ia32_func_xref_add (func, IA32_XREF_FUNCTION,
				vaddr - func->start,
				ia32_has_immediate (inst, NULL),
				rel_el->addend, NULL, &rel_el->orig, 0);

			ia32_func_oxref_add (func, vaddr - func->start +
				ia32_has_immediate (inst, NULL), rel_el);
		}
no_shadowed_fptr:

		if (tb == 0 && (vaddr + ilen) > func->end) {
			ia32_debug (IA32_WARNING, "WARNING: instruction (%d) "
				"in \"%s\" at 0x%x overlaps function end "
				"0x%x, tracing bounds\n",
				ilen, func->name, vaddr, func->end);

			/*ia32_confirm ();*/
			tb = func->traced_bounds = 1;

		/* even more complicated case: the basic block runs against
		 * the function end without a control flow instruction. that
		 * is, it executes beyond the function end. mostly as a result
		 * of fscked up symbol table entries.
		 * XXX: howto handle this?
		 */
		} else if (tb == 0 && (vaddr + ilen) == func->end &&
			OD_TEST (inst->opc.used, OP_CONTROL) == 0)
		{
			ia32_debug (IA32_WARNING, "WARNING: last basic block "
				"in \"%s\" at 0x%x runs into the function end "
				"0x%x\n", func->name, this->start, func->end);
			ia32_debug (IA32_WARNING, "         tracing bounds, "
				"but take care for possible code duplication\n");

			tb = func->traced_bounds = 1;
			/*ia32_confirm ();*/
		}

		if (OD_TEST (inst->opc.used, OP_CONTROL) == 0) {
			vaddr += ilen;

			work1 = ia32_br_find (root, vaddr, all, all_count,
				&br_splitted);

			if (work1 != NULL) {
				this->end = vaddr;
				this->endtype = BR_END_PASS;
				this->endbr = xcalloc (1, sizeof (ia32_bblock *));
				this->endbr[0] = work1;
				this->endbr_count = 1;

				return (br_splitted ? 1 : 0);
			}

			continue;
		}

		/* from now on, everything is a control flow instruction.
		 * the last instruction length is stored to be able to morph
		 * the last bblock instruction (jcc, call, ret, ..) without
		 * having to re-disassemble it
		 */
		this->last_ilen = ilen;

		/* try to detect whether the control flow leaves our function.
		 * for trace-bounds mode, we have to make a guess.
		 */
		intra = 0;
		if (tb && ia32_verbose (IA32_DEBUG))
			ia32_print (inst);

		if (destaddr != 0xffffffff && tb) {
			/* in case the control is within the instruction, its
			 * either a PIC or relocated entry and we decode it
			 * through the "within function" switchcase below.
			 */
			if (destaddr >= vaddr && destaddr <= vaddr + ilen)
				intra = 1;

			/* when its a "return" instruction, make it
			 * inter-function else only intra function instructions
			 * (cond, uncond jumps) are left, and we make it intra
			 * function
			 */
			if (ia32_trace_return_is (inst, cur))
				intra = 0;
			else
				intra = 1;

			if (destaddr < func->start)
				intra = 0;
		} else if (destaddr != 0xffffffff) {
			intra = ia32_trace_range (func->start, func->end,
				destaddr);

			/* special case (e.g. in glibc, "pause" function with
			 * its invalid symbol table entry): the call is right
			 * at the end of a non-traced bound function. happens
			 * only with invalid symbol table entries.
			 */
			if (intra == 0 && destaddr >= func->start &&
				destaddr <= (vaddr + ilen))
			{
				intra = 1;

				ia32_debug (IA32_WARNING, "WARNING: 0x%x in "
					"\"%s\": overhanging instruction\n",
					vaddr, func->name);
			}
		}

		cond = (OD_TEST (inst->opc.used, OP_COND)) ? 1 : 0;
#define	SW_INTRA	1
#define	SW_INTER	0
#define	SW_COND		2
#define	SW_UNCOND	0
#define	SW_RESUME	4
#define	SW_PASS		0
		swmask = (intra ? SW_INTRA : 0) | (cond ? SW_COND : 0) |
			(resume ? SW_RESUME : 0);

		this->end = vaddr + ilen;

		/* control flow instructions that cannot be predicted can be
		 * of two kinds:
		 *
		 *  - switch tables, which do not resume control and are
		 *    decoded by us
		 *  - function pointer calls, which do resume the control flow
		 */
		switch_fail = 0;

		if (c_volatile && resume == 0) {
			/* volatile jumps (switchtables or manual assembly)
			 */
			ia32_switchtable *	stab;
			int			selem;
			/* unsigned int		addr_sw;	*//* walker */


			this->endtype = BR_END_UNPREDICT;
			if (ia32_func_switchtable_is (inst) == 0) {
				ia32_debug (IA32_WARNING, "WARNING: "
					"(ia32_func_breakup_2) weird control "
					"flow at 0x%08x\n", vaddr);

				return (rval);
			}


			/* now we have to decode the switch table. the current
			 * bblock has to be terminated already, which we
			 * ensured above.
			 */
			ia32_debug (IA32_INFO, "  0x%08x: possible "
				"switch table\n", vaddr);

			stab = ia32_func_switchtable_decode (func, root, this,
				vaddr, inst);

			/* TODO: add && ia32_func_list_find_bystart
			 *         (..., vaddr + inst->length)
			 * XXX: if we failed to break up the switch table, try
			 *      as function pointer
			 */
			if (stab == NULL && inst->opc.target_type == OP_TYPE_REG) {
				switch_fail = 1;

				goto try_func_ptr;
			}

			/* TODO: is it necessary to process relocations for
			 *       stab->vaddr_loc here?
			 * FIXME: instead of always using rel_rodata, check
			 * where the relocation stems from and use the proper
			 * relocation table instead
			 */
			assert (stab != NULL);
			stab->mem_start = /*FIXME:RELOC rel_rodata->reloc_modify->data +*/
				(unsigned int *) stab->vaddr_start;

			/* build the bblock end
			 */
			this->endtype = BR_END_SWITCH;
			this->endbr = xcalloc (stab->entries,
				sizeof (ia32_bblock *));

			stab->reloc = rel_rodata;
			if (rel_rodata != NULL) {
				assert ((unsigned char *) stab->mem_start >=
					rel_rodata->reloc_modify->data);
				assert ((unsigned char *) stab->mem_start <
					(rel_rodata->reloc_modify->data +
					rel_rodata->reloc_modify->data_len));

				stab->vaddr_start = (unsigned int) stab->mem_start;
				stab->vaddr_start -=
					(unsigned int) rel_rodata->reloc_modify->data;
			} else
				stab->vaddr_start = 0x0;

			/*addr_sw = stab->vaddr_start;*/
			for (selem = 0 ; selem < stab->entries ; ++selem) {
				unsigned int	daddr,
						bbn;
#if 0
				elf_reloc *	rel_el;

				/* find the corresponding relocation entry
				 * for the switch table entry. then check for
				 * correct reloca type (R_386_32), and add the
				 * case to our internal struct
				 */
				rel_el = elf_reloc_list_lookup (rel_rodata,
					addr_sw);
				addr_sw += 4;

				/* FIXME: ugly heuristics. if we fail to obtain
				 *        a relocation entry, then our size
				 * guess of the table was wrong. lets refine.
				 */
				if (rel_el == NULL) {
					stab->entries = selem - 1;
					ia32_debug (IA32_INFO, "  refined to "
						"%u cases\n", stab->entries);
					continue;
				}
				assert (rel_el != NULL);

				assert (ELF32_R_TYPE (rel_el->orig.r_info) ==
					R_386_32);
				daddr = rel_el->sym->sent.st_value +
					rel_el->addend;
#endif
				daddr = stab->mem_start[selem];

				/* convert from memory to object file address,
				 * as we need to get the basic block
				 * addresses.
				 */
				daddr = daddr - (((unsigned int) func->mem) -
					func->start);

				ia32_debug (IA32_INFO, "    case %d ==> "
					"target: 0x%08x\n", selem, daddr);

				/* note that we rely on basic compiler sanity
				 * so that the switch will not reach into our
				 * current bblock.
				 * when we create a new bblock, mark return
				 * value
				 *
				 * first, try to find a basic block with the
				 * same destaddr within the already processed
				 * switch cases, then fall back on the
				 * function-level basic block search (_br_find)
				 */
				work1 = NULL;
				for (bbn = 0 ; bbn < selem ; ++bbn) {
					if (this->endbr[bbn]->start != daddr)
						continue;

					work1 = this->endbr[bbn];
					break;
				}

				br_splitted = 0;
				if (work1 == NULL)
					work1 = ia32_br_find (root, daddr,
						all, all_count, &br_splitted);

				if (br_splitted || work1 == NULL)
					rval = 1;

				if (work1 == NULL) {
					work1 = ia32_br_new ();
					work1->start = daddr;
				}
				this->endbr[selem] = work1;
			}

			this->endbr_count = stab->entries;
			this->switchtab = stab;

			return (rval);
		}

try_func_ptr:
		if (switch_fail || (c_volatile && resume)) {
			ia32_linux_interrupt *	intdef;

			/* volatile calls (function pointer calls or syscalls)
			 */
			assert (OD_TEST (inst->opc.used, OP_TARGET));

			intdef = ia32_linux_interrupt_decode (func, root,
				this, vaddr, inst);

			/* its a system call that does not resume, so setup an
			 * extra endtype of _END_CTRL_SYSCALL_END. does not return
			 * just means that it may jump elsewhere (like
			 * sigreturn), not that the program is terminated.
			 */
			if (intdef != NULL && intdef->resume == 0) {
				ia32_debug (IA32_WARNING, "WARNING: "
					"(ia32_func_breakup_2) non-returning "
					"system call 0x%x\n", intdef->syscall);

				this->interrupt = intdef;
				this->endtype = BR_END_CTRL_SYSCALL_END;

				return (rval);
			}
#if 1
			/* FIXME: linux centric code
			 */
			if (strcmp (inst->opc.opcode->name, "int") == 0 &&
				inst->opc.target_type == OP_TYPE_IMM &&
				inst->opc.imm_value == IA32_LINUX_SYSCALLINT)
			{
				ia32_debug (IA32_DEBUG, "DEBUG: 0x%x: "
					"generic linux system call\n", vaddr);

				work1 = ia32_br_find (root, vaddr + ilen,
					all, all_count, &br_splitted);

				if (br_splitted)
					rval = 1;

				this->endtype = BR_END_CTRL_SYSCALL;

				this->endbr = xcalloc (1,
					sizeof (ia32_bblock *));
				this->endbr[0] = work1;
				if (this->endbr[0] == NULL) {
					rval = 1;
					this->endbr[0] = ia32_br_new ();
					this->endbr[0]->start = vaddr + ilen;
				}
				this->endbr_count = 1;

				return (rval);
			}
#endif
			/* immediate target is another interrupt call
			 * normally. just go ahead
			 */
			if (inst->opc.target_type == OP_TYPE_IMM) {
				vaddr += ilen;

				work1 = ia32_br_find (root, vaddr,
					all, all_count, &br_splitted);
				if (work1 != NULL) {
					this->end = vaddr;
					this->endtype = BR_END_PASS;
					this->endbr = xcalloc (1,
						sizeof (ia32_bblock *));
					this->endbr[0] = work1;
					this->endbr_count = 1;

					return (br_splitted ? 1 : 0);
				}

				continue;
			}

			/* memory pointer call. (function pointer but stored
			 * in memory). hell, ia32 addressing modes are a mess.
			 * not every function pointer call is spilled through
			 * a register load and register call, but some are
			 * direct-memory calls. this is one, so decode it.
			 * example of such code: second basic block of
			 * __uselocale within glibc.
			 */
			if (inst->opc.target_type == OP_TYPE_MEMABS) {
				/* FIXME: keep this as warning because i am
				 * not yet sure how well this works
				 */
				ia32_debug (IA32_DEBUG, "DEBUG: (%s) 0x%x: "
					"memory indirect call found\n",
					func->name, vaddr);

				ia32_debug (IA32_DEBUG, "   0x%08x: volatile "
					"memory indirect \"%s\" instruction\n",
					vaddr, inst->opc.opcode->name);

				/* we are only interested in memory displaced
				 * calls
				 */
				if (strcmp (inst->opc.opcode->name,
					"call") != 0 ||
					ia32_has_displacement (inst, NULL) == 0)
				{
					assert (0);
				}

				work1 = ia32_br_find (root, vaddr + ilen,
					all, all_count, &br_splitted);

				if (br_splitted)
					rval = 1;

				this->endtype = BR_END_CALL_MEM;
				this->memabs_pos =
					ia32_has_displacement (inst, NULL);

				this->endbr = xcalloc (1,
					sizeof (ia32_bblock *));
				this->endbr[0] = work1;
				if (this->endbr[0] == NULL) {
					rval = 1;
					this->endbr[0] = ia32_br_new ();
					this->endbr[0]->start = vaddr + ilen;
				}
				this->endbr_count = 1;

				return (rval);
			}

			if (inst->opc.target_type == OP_TYPE_MEMREG) {
				ia32_debug (IA32_DEBUG, "DEBUG: 0x%08x: "
					"_MEMREG volatile call\n", vaddr);

				/* _MEMREG should implicit target_reg.
				 * displ_value is optional though.
				 */
				this->memreg_displ = 0;

#if 0
				/* this displacement should never be covered
				 * by a relocation entry.
				 */
				if (ia32_has_displacement (inst, NULL)) {
					elf_reloc *	rel_el;

					rel_el = elf_reloc_list_lookup
						(rel_code, vaddr +
						ia32_has_displacement
						(inst, NULL));

					if (rel_el != NULL) {
						ia32_debug (IA32_FATAL,
							"FATAL: 0x%08x: "
							"_MEMREG call covered "
							"by relocation\n",
							vaddr);

						assert (0);
						exit (EXIT_FAILURE);
					}

					this->memreg_displ = ia32_extend_signed
						(inst->opc.displ_value,
						inst->opc.displ_size);
				}
#endif
				this->memreg_displ = ia32_has_displacement (inst, NULL);
				this->memreg_callreg = inst->opc.target_reg;

				ia32_debug (IA32_DEBUG, "    [reg %d + 0x%08x]\n",
					this->memreg_callreg, this->memreg_displ);

				this->end = vaddr + ilen;
				work1 = ia32_br_find (root, vaddr + ilen,
					all, all_count, &br_splitted);

				if (br_splitted)
					rval = 1;

				this->endtype = BR_END_CALL_MEMREG;

				this->endbr = xcalloc (1,
					sizeof (ia32_bblock *));
				this->endbr[0] = work1;
				if (this->endbr[0] == NULL) {
					rval = 1;
					this->endbr[0] = ia32_br_new ();
					this->endbr[0]->start = vaddr + ilen;
				}
				this->endbr_count = 1;

				return (rval);
			}

			/* SIB addressed calls. the most complicated, but we
			 * just move the complexity to the loaders ;)
			 */
			if (inst->opc.target_type == OP_TYPE_MEM) {
				ia32_debug (IA32_DEBUG, "DEBUG: 0x%08x: SIB "
					"addressing call/jump\n", vaddr);

				assert (strcmp (inst->opc.opcode->name, "call") == 0);

				this->end = vaddr + ilen;
				work1 = ia32_br_find (root, vaddr + ilen,
					all, all_count, &br_splitted);

				if (br_splitted)
					rval = 1;

				this->endtype = BR_END_CALL_MEMSIB;

				this->endbr = xcalloc (1,
					sizeof (ia32_bblock *));
				this->endbr[0] = work1;
				if (this->endbr[0] == NULL) {
					rval = 1;
					this->endbr[0] = ia32_br_new ();
					this->endbr[0]->start = vaddr + ilen;
				}
				this->endbr_count = 1;

				this->memsib_scale = inst->opc.scale;
				this->memsib_index = inst->opc.index;
				this->memsib_indexreg = inst->opc.index_reg;
				this->memsib_base = inst->opc.base;
				this->memsib_basereg = inst->opc.base_reg;
				this->memsib_displpos =
					ia32_has_displacement (inst, NULL);

				return (rval);
			}

			/* the only target type thats left should be a simple
			 * register based jump/call. if its not, bail.
			 */
			if (inst->opc.target_type != OP_TYPE_REG) {
				ia32_debug (IA32_FATAL, "FATAL: 0x%08x: "
					"volatile, unhandled (sib?) call "
					"found, target type %d\n", vaddr,
					inst->opc.target_type);

				assert (0);
				exit (EXIT_FAILURE);
			}

			ia32_debug (IA32_DEBUG, "    0x%08x: volatile %s, "
				"register %s\n", vaddr,
				switch_fail ? "jump" : "call",
				ia32_regs_wide[inst->opc.target_reg]);

			this->end = vaddr + ilen;
			this->call_reg = inst->opc.target_reg;
			work1 = ia32_br_find (root, vaddr + ilen,
				all, all_count, &br_splitted);

			if (br_splitted)
				rval = 1;

			if (switch_fail) {
				this->endtype = BR_END_FUNCPTR_JUMP;
				this->endbr_count = 0;

				return (rval);
			}

			this->endtype = BR_END_FUNCPTR_CALL;
			this->endbr = xcalloc (1, sizeof (ia32_bblock *));

			this->endbr[0] = work1;
			if (this->endbr[0] == NULL) {
				rval = 1;
				this->endbr[0] = ia32_br_new ();
				this->endbr[0]->start = vaddr + ilen;
			}
			this->endbr_count = 1;

			return (rval);
		}

		switch (swmask) {
		/* inter function references
		 */
		/* bblock terminate, "ret" return or a "hlt" instruction, but
		 * we treat them much the same way.
		 */
		case (SW_INTER | SW_UNCOND | SW_PASS):
			this->endtype = BR_END_RET;

			return (rval);

		/* bblock ignore, conditional jump inter-function
		 */
		case (SW_INTER | SW_COND | SW_PASS):
			/* the most common case for this to happen is to share
			 * the same trailing function code (including ret) for
			 * a number of functions (e.g. strcoll in glibc). the
			 * problem with this type of jump is that the code it
			 * jumps to may lead to undiscovered functions which
			 * we have to analyze later. therefore, add a function
			 * reference and the special _END_IF_INTER type.
			 */
			assert (ia32_has_displacement (inst, NULL));
			ia32_func_xref_add (func, IA32_XREF_FUNCTION,
				vaddr - func->start,
				ia32_has_displacement (inst, NULL),
				destaddr, NULL, NULL, 0);

			work1 = ia32_br_find (root, vaddr + ilen,
				all, all_count, &br_splitted);

			if (br_splitted)
				rval = 1;

			this->endtype = BR_END_IF_INTER;
			this->cond = inst->opc.cond;
			this->endbr_count = 1;
			this->endbr = xcalloc (1, sizeof (ia32_bblock *));
			this->endbr[0] = work1;

			if (this->endbr[0] == NULL) {
				rval = 1;
				this->endbr[0] = ia32_br_new ();
				this->endbr[0]->start = vaddr + ilen;
			}

			return (rval);
			break;

		/* bblock call, external function reference
		 * add the special passing bblock type "call".
		 */
		case (SW_INTER | SW_UNCOND | SW_RESUME):
		case (SW_INTER | SW_COND | SW_RESUME):
			/* FIXME: calc correct addend (not just 1)
			 */
			ia32_func_xref_add (func, IA32_XREF_FUNCTION,
				vaddr - func->start, 1,
				destaddr, NULL, NULL, 0);

			this->end = vaddr + ilen;
			work1 = ia32_br_find (root, vaddr + ilen,
				all, all_count, &br_splitted);

			if (br_splitted)
				rval = 1;

			this->endtype = BR_END_CALL;
			this->endbr = xcalloc (1, sizeof (ia32_bblock *));

			this->endbr[0] = work1;
			if (this->endbr[0] == NULL) {
				rval = 1;
				this->endbr[0] = ia32_br_new ();
				this->endbr[0]->start = vaddr + ilen;
			}
			this->endbr_count = 1;

			return (rval);

		/* intra function references
		 */
		/* bblock if, conditional jump
		 */
		case (SW_INTRA | SW_COND | SW_PASS):
			if (destaddr == 0xffffffff)
				break;

			/* when the jcc points to within its own instruction,
			 * we can be sure there will be a relocation offset
			 * inserted at that place. this is rarely used, the
			 * only place i have seen it yet was the handling of
			 * system calls in glibc, where an inter-function jump
			 * to __syscall_error is used.
			 */
			if (ia32_trace_range (vaddr, vaddr + ilen, destaddr)) {
				unsigned int	odaddr = destaddr;


				destaddr = elf_reloc_list_lookup_func (rel_code,
					destaddr);

				ia32_debug (IA32_INFO, "    0x%08x: calljump "
					"to 0x%08x\n", vaddr, destaddr);

				assert (destaddr != 0xffffffff);

				ia32_func_xref_add (func, IA32_XREF_FUNCTION,
					vaddr - func->start, odaddr - vaddr,
					destaddr, NULL, NULL, 0);

				work1 = ia32_br_find (root, vaddr + ilen,
					all, all_count, &br_splitted);

				if (br_splitted)
					rval = 1;

				this->endtype = BR_END_IF_INTER;
				this->cond = inst->opc.cond;
				this->endbr_count = 1;
				this->endbr = xcalloc (1, sizeof (ia32_bblock *));
				this->endbr[0] = work1;

				if (this->endbr[0] == NULL) {
					rval = 1;
					this->endbr[0] = ia32_br_new ();
					this->endbr[0]->start = vaddr + ilen;
				}

				return (rval);
			}

			/* XXX: finding on the vaddr address cannot clash,
			 * since we either find no bblock or an already passed
			 * bblock. finding on the destination address can split
			 * our current bblock (`this'). hence, the first thing
			 * we have to ensure is whether we got a bblock and if
			 * resulted through a split
			 */
			duesplit = ia32_trace_range (this->start, this->end,
				destaddr);
			work1 = ia32_br_find (root, vaddr + ilen,
				all, all_count, &br_splitted);
			if (br_splitted)
				rval = 1;
			work2 = ia32_br_find (root, destaddr, all, all_count,
				&br_splitted);
			if (br_splitted)
				rval = 1;

			if (duesplit) {
				assert (work2 != NULL);
				this = work2;
			}

			/* XXX: set this after ia32_br_find, else clash
			 */
			this->endtype = BR_END_IF;
			this->cond = inst->opc.cond;
			this->endbr_count = 2;
			this->endbr = xcalloc (2, sizeof (ia32_bblock *));
			this->endbr[0] = work1;
			this->endbr[1] = work2;

			if (this->endbr[0] == NULL) {
				rval = 1;
				this->endbr[0] = ia32_br_new ();
				this->endbr[0]->start = vaddr + ilen;
			}

			if (this->endbr[1] == NULL) {
				rval = 1;
				this->endbr[1] = ia32_br_new ();
				this->endbr[1]->start = destaddr;
			}

			return (rval);

		/* bblock transfer, unconditional jump
		 */
		case (SW_INTRA | SW_UNCOND | SW_PASS):
			if (destaddr == 0xffffffff)
				break;

			/* check whether there are relocation information for
			 * the location
			 */
			rdaddr = elf_reloc_list_lookup_func (rel_code,
				vaddr + ia32_has_displacement (inst, NULL));
			ia32_debug (IA32_DEBUG, "    0x%08x: unconditional "
				"jump, reloc lookup: 0x%08x\n", vaddr, rdaddr);

			if (rdaddr != 0xffffffff) {
				unsigned int	rel_displ;

				rel_displ = ia32_has_displacement (inst, NULL);

				ia32_debug (IA32_DEBUG, "      through reloc "
					"at 0x%08x to 0x%08x\n",
					vaddr + rel_displ, rdaddr);

				ia32_func_xref_add (func, IA32_XREF_FUNCTION,
					vaddr - func->start, rel_displ,
					rdaddr, NULL, NULL, 0);

				this->endtype = BR_END_TRANSFER_INTER;
				this->endbr_count = 0;

				return (rval);
			}

			duesplit = ia32_trace_range (this->start, this->end,
				destaddr);
			work1 = ia32_br_find (root, destaddr, all, all_count,
				&br_splitted);
			if (br_splitted)
				rval = 1;

			if (duesplit) {
				assert (work1 != NULL);
				this = work1;
			}

			this->endtype = BR_END_TRANSFER;
			this->endbr = xcalloc (1, sizeof (ia32_bblock *));

			this->endbr[0] = work1;
			if (this->endbr[0] == NULL) {
				rval = 1;
				this->endbr[0] = ia32_br_new ();
				this->endbr[0]->start = destaddr;
			}
			this->endbr_count = 1;

			return (rval);

		/* bblock ignore or failure, relocation or non-conform code
		 * mostly normal calls that get fixed by relocation entries
		 */
		case (SW_INTRA | SW_UNCOND | SW_RESUME):
		case (SW_INTRA | SW_COND | SW_RESUME):
			/* ignore unknown targets
			 */
			if (destaddr == 0xffffffff)
				break;

		        /* for directly-after-instruction calls the call is
			 * used to obtain the current position (in PIC code
			 * before any relocation could take place).  this
			 * might be problematic for some applications, so mark
			 * that odd case within the function object but ignore
			 * otherwise.
			 */
			if (destaddr == vaddr + ilen) {
				ia32_debug (IA32_WARNING, "WARNING: function "
					"\"%s\" is position curious at 0x%x. "
					"marking as such.\n", func->name,
					vaddr);

				func->is_pos_curious = 1;

				break;
			}

			ia32_debug (IA32_INFO, "  0x%08x: call\n", vaddr);

			/* to-be-filled-in relocation positions in ELF object
			 * files have target one after the call instruction
			 * so, look it up in the relocation table.
			 * FIXME: use a more generic "destaddr within
			 *        instruction" approach, ia32_trace_range (..)
			 */
			if (destaddr == vaddr + 1) {
				elf_reloc * rel_item;

				destaddr = elf_reloc_list_lookup_func (rel_code,
					vaddr + 1);

				rel_item = elf_reloc_list_lookup (rel_code,
					vaddr + 1);

				/* still invalid :-/
				 */
				if (destaddr == 0xffffffff) {
					ia32_debug (IA32_DEBUG, "DEBUG: "
						"(ia32_func_breakup_2) failed "
						"to obtain relocation for "
						"0x%08x\n", vaddr);

					elf_reloc_list_debug (rel_code, vaddr + 1);

					ia32_func_xref_add (func,
						IA32_XREF_FUNCEXTERN,
						vaddr - func->start, 1,
						destaddr, NULL, rel_item == NULL ?
							NULL : &rel_item->orig, 0);

					/* XXX ugly hack: step over the call,
					 * create a "ignore instruction"
					 * endtype.
					 * FIXME: find a better way
					 */
					ia32_debug (IA32_DEBUG, "DEBUG: "
						"adding skip branch end type, "
						"danger ahead...\n");

					work1 = ia32_br_find (root, vaddr + ilen,
						all, all_count, &br_splitted);
					if (br_splitted)
						rval = 1;

					this->endtype = BR_END_CALL_EXTERN;
					this->endbr = xcalloc (1,
						sizeof (ia32_bblock *));

					this->endbr[0] = work1;
					if (this->endbr[0] == NULL) {
						rval = 1;
						this->endbr[0] = ia32_br_new ();
						this->endbr[0]->start = vaddr + ilen;
					}
					this->endbr_count = 1;
					/*assert (0); */
					return (rval);
				}

				ia32_debug (IA32_INFO, "    through reloc at "
					"0x%08x to 0x%08x\n", vaddr, destaddr);
				ia32_func_xref_add (func, IA32_XREF_FUNCTION,
					vaddr - func->start, 1, destaddr, NULL,
					rel_item == NULL ?
						NULL : &rel_item->orig, 0);

				work1 = ia32_br_find (root, vaddr + ilen,
					all, all_count, &br_splitted);
				if (br_splitted)
					rval = 1;

				this->endtype = BR_END_CALL;
				this->endbr = xcalloc (1, sizeof (ia32_bblock *));

				this->endbr[0] = work1;
				if (this->endbr[0] == NULL) {
					rval = 1;
					this->endbr[0] = ia32_br_new ();
					this->endbr[0]->start = vaddr + ilen;
				}
				this->endbr_count = 1;

				ia32_debug (IA32_INFO, "    ==> call at 0x%08x "
					"to 0x%08x\n", vaddr, destaddr);

				return (rval);
			}

			/* one legit destaddr is the start of this function,
			 * in case its direct recursive. check this case
			 */
			if (func->start == destaddr) {
				/* do not specify an ia32_function structure
				 * for now, will fill that in later
				 */
				ia32_func_xref_add (func, IA32_XREF_FUNCTION,
					vaddr - func->start, 1, destaddr, NULL,
					NULL, 0);

				break;
			}

			/* in case of inter-section calls (example: _init
			 * calling into .text section), add just the function
			 * address as reference and let it fillin the correct
			 * function object later, when all sections have been
			 * processed.
			 */
			if (ia32_has_displacement (inst, NULL)) {
				/* adress the relocation is done */
				unsigned int	rel_addr;
				elf_reloc *	rel;

				rel_addr = vaddr +
					ia32_has_displacement (inst, NULL);

				rel = elf_reloc_list_lookup (rel_code, rel_addr);
				if (rel != NULL) {
					if (rel->type != ELF_RELOC_SECTION)
						goto complex_func_hierarchy;

					destaddr = rel->addend -
						ia32_has_displacement (inst, NULL) +
						inst->length;

					ia32_debug (IA32_WARNING, "WARNING: 0x%08x: "
						"inter section call from \"%s\" "
						"(%s:0x%x (+%d) -> %s:0x%x)\n",
						vaddr, func->name,
						rel_code->reloc_modify->name, vaddr,
						ia32_has_displacement (inst, NULL),
						rel->sym != NULL ? rel->sym->sec->name :
						"?", destaddr);

				} else {
					/* no relocation entry found, that
					 * means destaddr is already valid
					 */
					ia32_debug (IA32_INFO, "INFO: 0x%x: "
						"displaced non-relocation call\n",
						vaddr);
					ia32_confirm ();
				}

				/* FIXME:SEC: we just pack in the offset of
				 * the function, but do not specify to what
				 * section it refers, doh! :-/
				 */
				ia32_func_xref_add (func, IA32_XREF_FUNCTION,
					vaddr - func->start,
					ia32_has_displacement (inst, NULL),
					destaddr, NULL,
					rel == NULL ? NULL : &rel->orig, 1);

				work1 = ia32_br_find (root, vaddr + ilen,
					all, all_count, &br_splitted);

				if (br_splitted)
					rval = 1;

				this->endtype = BR_END_CALL;
				this->endbr = xcalloc (1, sizeof (ia32_bblock *));

				this->endbr[0] = work1;
				if (this->endbr[0] == NULL) {
					rval = 1;
					this->endbr[0] = ia32_br_new ();
					this->endbr[0]->start = vaddr + ilen;
				}
				this->endbr_count = 1;

				return (rval);
			}

complex_func_hierarchy:
			/* everything else is an error or complex function
			 * unrolling we cannot cope with
			 */
			ia32_debug (IA32_FATAL, "FATAL: (ia32_func_breakup_2) "
				"complex function hierarchy\n");
			ia32_debug (IA32_FATAL, "  func-entry: 0x%08x, "
				"vaddr: 0x%08x, destaddr: 0x%08x",
				func->start, vaddr, destaddr);

			assert (0);
			this->endtype = BR_END_INVALID;

			return (rval);

		default:
			break;
		}
#undef	SW_INTRA
#undef	SW_INTER
#undef	SW_COND
#undef	SW_UNCOND
#undef	SW_RESUME
#undef	SW_PASS
		vaddr += ilen;

		/* examine next instruction, is there already a bblock for it?
		 */
		work1 = ia32_br_find (root, vaddr, all, all_count,
			&br_splitted);
		if (br_splitted)
			rval = 1;

		if (work1 != NULL) {
			this->end = vaddr;
			this->endtype = BR_END_PASS;
			this->endbr = xcalloc (1, sizeof (ia32_bblock *));
			this->endbr[0] = work1;
			this->endbr_count = 1;

			return (rval);
		}
	}

	return (rval);
}


ia32_linux_interrupt *
ia32_linux_interrupt_decode (ia32_function *func, ia32_bblock *root,
	ia32_bblock *this, unsigned int vaddr, ia32_instruction *inst)
{
	ia32_linux_interrupt *	intdef;
	ia32_instruction *	cur;
	ia32_instruction *	ilist;
	int			ilist_count,
				in;	/* ilist walker */
	int			syscall_number = -1;


	if (strcmp (inst->opc.opcode->name, "int") != 0 ||
		inst->opc.target_type != OP_TYPE_IMM ||
		inst->opc.imm_value != IA32_LINUX_SYSCALLINT)
		return (NULL);

	/* decode the instructions leading to the system call. then try to
	 * figure out its system call number.
	 */
	ilist = ia32_func_inst_traceup (4, &ilist_count, func, root,
		this, vaddr);
	assert (ilist != NULL && ilist_count > 0);

	for (in = ilist_count - 1 ; in >= 0 ; --in) {
		cur = &ilist[in];
		if (ia32_verbose (IA32_DEBUG))
			ia32_print (cur);

		if (strcmp (cur->opc.opcode->name, "mov") != 0)
			continue;

		assert (OD_TEST (cur->opc.used, OP_SOURCE | OP_TARGET));

		if (cur->opc.target_type != OP_TYPE_REG ||
			cur->opc.source_type != OP_TYPE_IMM)
			continue;

		if (cur->opc.target_reg != IA32_REG_EAX)
			continue;

		syscall_number = cur->opc.imm_value;
		break;
	}

	if (syscall_number < 0 || syscall_number > IA32_LINUX_MAXSYSCALL) {
		ia32_debug (IA32_FATAL, "FATAL: (ia32_linux_interrupt_decode) "
			"failed to obtain system call number\n");

		return (NULL);
	}

	intdef = xcalloc (1, sizeof (ia32_linux_interrupt));
	intdef->syscall = syscall_number;

	switch (syscall_number) {
	case (__NR_exit):
	case (__NR_sigreturn):
	case (__NR_rt_sigreturn):
		intdef->resume = 0;
		break;
	default:
		intdef->resume = 1;
		break;
	}

	return (intdef);
}

/* we need to decode possible switch tables to do a complete basic block
 * analysis. for the actual native run we do not need one though.
 */

ia32_switchtable *
ia32_func_switchtable_decode (ia32_function *func, ia32_bblock *root,
	ia32_bblock *this, unsigned int vaddr, ia32_instruction *inst)
{
	ia32_instruction *	cur;
	ia32_instruction *	ilist;
	ia32_instruction	inst_s;
	int			ilist_count;

	/* we trace back the use of registers to index and displace into the
	 * switch table. to do this, we keep register indexes.
	 *   stab_idx_reg = register used to relativly index into the table
	 *   disp_reg = table base register
	 *   comb_reg = combined register
	 *
	 * only stab_idx_reg is mandatory, the others are used to fill
	 *   table_start = absolute address of switch table
	 *
	 * our algorithm is to trace back until we have both the table_start
	 * and the stab_idx_reg. then we can emulate the switch table
	 * behaviour and fill in the bblockes.
	 *
	 *   stab_size is optional, and filled in when we see a check for
	 * an upper bound of stab_idx_reg.
	 */
	int			stab_idx_reg = -1,
				stab_idx_scale = -1,
				disp_reg = -1,
				comb_reg = -1;
	unsigned int		table_start = 0xffffffff,
				table_loc_vaddr = 0xffffffff;
	int			in;	/* instruction walker */
	int			stab_size = -1;
	ia32_switchtable *	stab;
	unsigned int		t_rel,
				t_val = 0;


	ilist = ia32_func_inst_traceup (16, &ilist_count, func, root,
		this, vaddr);
	assert (ilist != NULL && ilist_count > 0);

	cur = inst;
	if (ia32_verbose (IA32_DEBUG))
		ia32_print (cur);

	if (cur->opc.target_type == OP_TYPE_REG) {
		comb_reg = cur->opc.target_reg;
	} else if (cur->opc.target_type == OP_TYPE_MEM) {
		unsigned int	displ_rel;


		if (cur->opc.base)
			disp_reg = cur->opc.base_reg;

		/* FIXME: check whether the index reg is already 4*'ed */
		if (cur->opc.index) {
			stab_idx_reg = cur->opc.index_reg;
			stab_idx_scale = cur->opc.scale;
		}

		displ_rel = ia32_has_displacement (cur, NULL);
		if (displ_rel != 0) {
			table_start = inst->opc.displ_value;
			table_loc_vaddr = vaddr + displ_rel;
		}
	}

	for (in = ilist_count - 1 ; in >= 0 ; --in) {
		cur = &ilist[in];
		if (ia32_verbose (IA32_DEBUG))
			ia32_print (cur);

		if (strcmp (cur->opc.opcode->name, "mov") == 0) {
			int *		regp;

			assert (OD_TEST (cur->opc.used, OP_SOURCE | OP_TARGET));

			if (cur->opc.target_type != OP_TYPE_REG)
				continue;

			if (cur->opc.target_reg == disp_reg)
				regp = &disp_reg;
			else if (cur->opc.target_reg == comb_reg)
				regp = &comb_reg;
			else
				continue;


			if (cur->opc.source_type == OP_TYPE_REG) {
				*regp = cur->opc.source_reg;
				continue;
			}

			t_rel = ia32_has_immediate (cur, NULL);
			if (t_rel) {
				t_val = cur->opc.imm_value;
			} else {
				t_rel = ia32_has_displacement (cur, NULL);
				if (t_rel)
					t_val = cur->opc.displ_value;

				/* SIB addressing on combined register almost
				 * always means jumptable access
				 */
				if (cur->opc.source_type == OP_TYPE_MEM &&
					cur->opc.target_reg == comb_reg &&
					cur->opc.index)
				{
					comb_reg = -1;
					stab_idx_reg = cur->opc.index_reg;
					/* FIXME: what to do about
					 * scales != 2 ?
					 */
					stab_idx_scale = cur->opc.scale;
					table_start = cur->opc.displ_value;
				}
			}

			if (t_rel && (cur->opc.source_type == OP_TYPE_IMM ||
				cur->opc.source_type == OP_TYPE_MEMREG))
			{
#ifdef	MAYBE_REWRITE_THIS_HEURISTICS
				ia32_debug (IA32_INFO, "INFO: abort "
					"switchtable search with t_val = "
					"0x%08x\n", t_val);

				return (NULL);
#endif
#if 1
				table_start = t_val;
				table_loc_vaddr = vaddr + t_rel;

				if (cur->opc.source_type == OP_TYPE_MEMREG &&
					regp == &comb_reg)
				{
					comb_reg = -1;
					stab_idx_reg = cur->opc.source_reg;
				}

				goto ccond;
#endif
			}

		} else if (strcmp (cur->opc.opcode->name, "cmp") == 0) {
			/* heuristics to guess the size of the switch table
			 */
			t_rel = ia32_has_immediate (cur, NULL);
			if (t_rel && cur->opc.imm_value > 0 &&
				cur->opc.imm_value < 4096)
			{
				stab_size = cur->opc.imm_value;
			}
		}
#if 1
ccond:
#endif
		if (stab_size != -1 && stab_idx_reg != -1 &&
			table_start != 0xffffffff)
		{
			break;
		}
	}

	/* XXX: ugly heuristics. if we have everything but the table start,
	 *      because one register is kept for the entire function and
	 * there are multiple pathes to the switch block, we just trace the
	 * function from top to bottom and use the first register load to
	 * the disp_reg. ugly, but should work in 90% of the cases.
	 * using a real safe method would require code- and dataflow analysis.
	 * XXX: maybe a dominator tree of the basic blocks is enough, or even
	 *      just _one_ path, since it would suffice to let the register
	 * load
	 */
	if (in < 0 && stab_size != -1 && stab_idx_reg != -1 &&
		disp_reg != -1 && table_start == 0xffffffff)
	{
		for (vaddr = func->start ; table_start == 0xffffffff &&
			vaddr < func->end ; vaddr += cur->length)
		{
			cur = ia32_decode_instruction
				(&func->mem[vaddr - func->start], &inst_s);
			assert (cur != NULL);

			if (strcmp (cur->opc.opcode->name, "mov") != 0)
				continue;

			assert (OD_TEST (cur->opc.used, OP_SOURCE | OP_TARGET));
			if (cur->opc.target_type != OP_TYPE_REG)
				continue;

			if (cur->opc.target_reg != disp_reg)
				continue;

			if (cur->opc.source_type != OP_TYPE_IMM)
				continue;

			t_rel = ia32_has_immediate (cur, NULL);
			if (t_rel) {
				t_val = cur->opc.imm_value;
			} else {
				t_rel = ia32_has_displacement (cur, NULL);
				if (t_rel)
					t_val = cur->opc.displ_value;
			}

			if (t_rel) {
				table_start = t_val;
				table_loc_vaddr = vaddr + t_rel;
			}
		}
	} else if (in < 0) {
		ia32_debug (IA32_WARNING, "WARNING: "
			"(ia32_func_switchtable_decode) failed to extract "
			"switchtable information\n");

		return (NULL);
	}

	ia32_debug (IA32_INFO, "switch table, start: 0x%08x, elements 0-%d, "
		"index reg %d (scale %d)\n",
		table_start, stab_size, stab_idx_reg, stab_idx_scale);

	free (ilist);

	stab = xcalloc (1, sizeof (ia32_switchtable));
	stab->entries = stab_size + 1;
	stab->vaddr_start = table_start;
	stab->vaddr_loc = table_loc_vaddr;	/* used for relocation */
	stab->idx_reg = stab_idx_reg;
	stab->idx_scale = stab_idx_scale;

	return (stab);
}


ia32_instruction *
ia32_func_inst_traceup (int backcount, int *inst_count, ia32_function *func,
	ia32_bblock *root, ia32_bblock *cur, unsigned int end_vaddr)
{
	ia32_instruction *	inst,
				inst_s;
	ia32_instruction *	ilist = NULL;
	unsigned char *		mem;
	unsigned int		icount,
				vaddr,
				skipcount = 0;
	ia32_bblock **		brefs;
	int			brefs_count;
	ia32_instruction *	sub_ilist;
	int			sub_ilist_count;


	*inst_count = 0;

	icount = ia32_func_inst_count (func, cur->start, end_vaddr);
	if (icount > backcount) {
		skipcount = icount - backcount;
		icount = backcount;
	}

	/* create the list in correct order
	 */
	for (vaddr = cur->start ; vaddr < end_vaddr ; vaddr += inst->length) {
		mem = &func->mem[vaddr - func->start];
		inst = ia32_decode_instruction (mem, &inst_s);
		assert (inst != NULL);

		/* skip instructions that are beyond the number we should
		 * collect.
		 */
		if (skipcount > 0) {
			skipcount -= 1;
			continue;
		}

		/* else add the decoded instruction to our list
		 */
		*inst_count += 1;
		ilist = xrealloc (ilist, *inst_count * sizeof (ilist[0]));
		memcpy (&ilist[*inst_count - 1], &inst_s, sizeof (inst_s));
	}

	/* in case we collected enough instructions, return the list, else
	 * trace the bblockes back up when possible. for more than one backref
	 * we cannot tell which lead to here, so return less than the requested
	 * number of instructions
	 */
	if (*inst_count == backcount)
		return (ilist);

	brefs = ia32_func_bblock_backrefs (&brefs_count, root, cur);
	if (brefs_count != 1) {
		if (brefs != NULL)
			free (brefs);

		return (ilist);
	}

	/* recurse to collect the instructions of the last bblock
	 */
	assert (backcount > *inst_count);
	sub_ilist = ia32_func_inst_traceup (backcount - *inst_count,
		&sub_ilist_count, func, root, brefs[0], brefs[0]->end);

	assert (sub_ilist != NULL && sub_ilist_count > 0);
	/* merge the sublist to the front of the main list
	 */
	ilist = xrealloc (ilist,
		(*inst_count + sub_ilist_count) * sizeof (ilist[0]));
	memmove (&ilist[sub_ilist_count], &ilist[0],
		*inst_count * sizeof (ilist[0]));
	memcpy (&ilist[0], sub_ilist, sub_ilist_count * sizeof (ilist[0]));
	free (sub_ilist);

	*inst_count += sub_ilist_count;

	return (ilist);
}


unsigned int
ia32_func_inst_count (ia32_function *func, unsigned int vstart,
	unsigned int vend)
{
	ia32_instruction *	inst,
				inst_s;
	unsigned char *		mem;
	unsigned int		icount,
				cur_vaddr;


	/* exclude traced functions from range checking
	 */
	if (func->start != func->end && func->traced_bounds == 0) {
		assert (vstart >= func->start && vend <= func->end);
	}

	cur_vaddr = vstart;

	for (icount = 0 ; cur_vaddr < vend ; ++icount) {
		mem = &func->mem[cur_vaddr - func->start];
		inst = ia32_decode_instruction (mem, &inst_s);

		assert (inst != NULL);
		cur_vaddr += inst->length;
	}

	return (icount);
}


ia32_bblock **
ia32_func_bblock_backrefs (int *br_count, ia32_bblock *root, ia32_bblock *cur)
{
	ia32_bblock **	btl;	/* list of all bblockes */
	unsigned int	btl_len,/* length of this list */
			n,	/* main walker */
			ebn,	/* end bblock walker */
			aln;	/* add list walker */
	ia32_bblock **	list = NULL;
	ia32_bblock *	add;
	int		dupe;


	btl = ia32_br_get_all (root, &btl_len);
	*br_count = 0;

	/* the basic idea is this: walk all bblockes already processed and
	 * collect all bblockes that have forward references to the current
	 * bblock. avoid dupes, but leave the resulting list unsorted.
	 */
	for (n = 0 ; n < btl_len ; ++n) {
		if (btl[n] == cur)
			continue;

		add = NULL;
		for (ebn = 0 ; ebn < btl[n]->endbr_count ; ++ebn) {
			if (btl[n]->endbr[ebn] == cur) {
				add = btl[n];
				break;
			}
		}

		if (add == NULL)
			continue;

		dupe = 0;
		for (aln = 0 ; aln < *br_count ; ++aln)
			if (list[aln] == add)
				dupe = 1;

		/* when its already in the backref list, skip
		 */
		if (dupe)
			continue;

		*br_count += 1;
		list = xrealloc (list, *br_count * sizeof (ia32_bblock *));
		list[*br_count - 1] = add;
	}

	free (btl);

	return (list);
}


ia32_function *
ia32_func_list_find_bymem (ia32_function **flist, unsigned int flist_count,
	unsigned char *memstart)
{
	unsigned int	n;


	for (n = 0 ; n < flist_count ; ++n) {
		if (flist[n]->mem == memstart && flist[n]->is_copy == 0)
			return (flist[n]);
	}

	return (NULL);
}


ia32_function *
ia32_func_list_find_bystart (ia32_function **flist, unsigned int flist_count,
	unsigned int start)
{
	unsigned int	n;


	for (n = 0 ; n < flist_count ; ++n) {
		if (flist[n]->start == start && flist[n]->is_copy == 0)
			return (flist[n]);
	}

	return (NULL);
}


ia32_function *
ia32_func_list_find_byname (ia32_function **flist, unsigned int flist_count,
	char *fname)
{
	unsigned int	n;


	for (n = 0 ; n < flist_count ; ++n) {
		if (flist[n]->name == NULL)
			continue;

		if (strcmp (fname, flist[n]->name) == 0)
			return (flist[n]);
	}

	return (NULL);
}


int
ia32_func_list_find_index (ia32_function **flist, unsigned int flist_count,
	ia32_function *func)
{
	unsigned int	n;


	for (n = 0 ; n < flist_count ; ++n)
		if (flist[n] == func)
			return (n);

	return (-1);
}


void
ia32_func_list_dump (ia32_function **flist, unsigned int flist_count)
{
	unsigned int	n;


	for (n = 0 ; n < flist_count ; ++n) {
		printf ("%-32s | 0x%08x - 0x%08x | @ 0x%08x\n",
			flist[n]->name, flist[n]->start, flist[n]->end,
			(unsigned int) flist[n]->mem);
	}
}


void
ia32_graphviz_func_out (FILE *fp, ia32_function **flist,
	unsigned int flist_count, elf_reloc_list *reloc_text)
{
	ia32_graphviz_func_out_2 (fp, flist, flist_count, NULL, reloc_text);
}


static void
ia32_graphviz_func_out_2 (FILE *fp, ia32_function **flist,
	unsigned int flist_count, int *flist_consider,
	elf_reloc_list *reloc_text)
{
	char **		ext_list = NULL;
	unsigned int	ext_list_count = 0;
	char *		ext_current;
	unsigned int	ext_wlk;

	unsigned int	n,
			i;


	fprintf (fp, "digraph functiondeps {\n\n");
	fprintf (fp, "\tnode [\n");
	fprintf (fp, "\t\tstyle = filled\n");
	fprintf (fp, "\t\tshape = \"record\"\n");
	fprintf (fp, "\t\tfillcolor = \"lightskyblue\"\n");
	fprintf (fp, "\t];\n\n");

	for (n = 0 ; n < flist_count ; ++n) {
		if (flist_consider != NULL && flist_consider[n] == 0)
			continue;

		fprintf (fp, "\t\"%s\" [\n", flist[n]->name);
		fprintf (fp, "\t\tlabel = \"{ <fi> | %s | <fo> }\"\n",
			flist[n]->name);
		fprintf (fp, "\t];\n");
	}

	for (n = 0 ; n < flist_count ; ++n) {
		if (flist_consider != NULL && flist_consider[n] == 0)
			continue;

		for (i = 0 ; i < flist[n]->func_xref_count ; ++i) {
			ext_current = NULL;

			switch (flist[n]->func_xref[i]->to_type) {
			case (IA32_XREF_FUNCEXTERN):
				ext_current = ia32_graphviz_func_out_extern
					(fp, flist[n],
					flist[n]->func_xref[i],
					reloc_text);
				break;
			case (IA32_XREF_FUNCTION):
				ia32_graphviz_func_out_intern (fp,
					flist[n], flist[n]->func_xref[i],
					flist, flist_count, flist_consider);
				break;
			default:
				break;
			}

			if (ext_current == NULL)
				continue;

			for (ext_wlk = 0 ; ext_wlk < ext_list_count ; ++ext_wlk) {
				if (strcmp (ext_list[ext_wlk], ext_current) == 0)
					break;
			}

			if (ext_wlk < ext_list_count)
				continue;

			ext_list_count += 1;
			ext_list = xrealloc (ext_list,
				ext_list_count * sizeof (char *));
			ext_list[ext_list_count - 1] = ext_current;
		}
	}

	/* output all external references found while dumping normal references
	 */
	if (ext_list_count > 0 && ia32_graphviz_align_undefined)
		fprintf (fp, "\tsubgraph cluster_undefined {\n"
			"\t\tlabel = \"undefined\";\n\n");

	for (ext_wlk = 0 ; ext_wlk < ext_list_count ; ++ext_wlk) {
		fprintf (fp, "\t\t\"%s\" [\n", ext_list[ext_wlk]);
		fprintf (fp, "\t\t\tlabel = \"{ <fi> | %s | <fo> }\"\n",
			ext_list[ext_wlk]);
		fprintf (fp, "\t\t\tfillcolor = \"red\"\n");
		fprintf (fp, "\t\t];\n");
	}

	if (ext_list_count > 0 && ia32_graphviz_align_undefined)
		fprintf (fp, "\t}\n");

	free (ext_list);

	fprintf (fp, "}\n");

	return;
}


static char *
ia32_graphviz_func_out_extern (FILE *fp, ia32_function *func,
	ia32_xref *xr, elf_reloc_list *reloc_text)
{
	unsigned int	from_addr;
	elf_reloc *	rel;
	char *		ext_name;


	if (reloc_text == NULL)
		return (NULL);

	/* look up relocation entry for reference source address, then try
	 * to pull the symbol table entry
	 */
	from_addr = xr->from + xr->addend + func->start;
	rel = elf_reloc_list_lookup (reloc_text, from_addr);
	if (rel == NULL)
		return (NULL);

	ext_name = "???";
	if (rel->sym->name != NULL)
		ext_name = rel->sym->name;

	ia32_debug (IA32_DEBUG, "0x%08x: %s -> %s\n", from_addr,
		func->name, ext_name);
	fprintf (fp, "\t\"%s\":fo -> \"%s\":fi;\n",
		func->name, ext_name);

	return (ext_name);
}


static void
ia32_graphviz_func_out_intern (FILE *fp, ia32_function *func, ia32_xref *xr,
	ia32_function **flist, unsigned int flist_count,
	int *flist_consider)
{
	char *		dname;	/* destination reference */
	ia32_function *	dest_func;


	if (func == NULL)
		return;

	if (flist_consider != NULL &&
		flist_consider[ia32_func_list_find_index (flist,
			flist_count, func)] == 0)
	{
		return;
	}

	dest_func = xr->to_data;
	assert (dest_func != NULL);
	dname = dest_func->name;

	if (dname != NULL) {
		ia32_debug (IA32_DEBUG, "          : %s -> %s\n",
			func->name, dname);
		fprintf (fp, "\t\"%s\":fo -> \"%s\":fi;\n",
			func->name, dname);
	}

	return;
}


void
ia32_graphviz_func_out_calltree (FILE *fp, ia32_function **flist,
	unsigned int flist_count, ia32_function *interest)
{
	int			int_idx;
	int *			int_arr;

	ia32_function *		func;
	unsigned int		n_m,
				n,
				i;


	assert (interest != NULL);
	int_idx = ia32_func_list_find_index (flist, flist_count, interest);
	assert (int_idx != -1);

	int_arr = xcalloc (flist_count, sizeof (int));
	int_arr[int_idx] = 1;

	/* do a little by brute force,
	 * FIXME: use a more elegant way ;)
	 */
#if 0
	for (n_m = 0 ; n_m < (flist_count * flist_count) ; ++n_m) {
#endif
	for (n_m = 0 ; n_m < (32 * flist_count) ; ++n_m) {
		n = n_m % flist_count;

		if (int_arr[n] != 0)
			continue;

		for (i = 0 ; i < flist[n]->func_xref_count ; ++i) {
			unsigned int	sub_idx;

			if (flist[n]->func_xref[i]->to_type !=
				IA32_XREF_FUNCTION)
				continue;

			func = (ia32_function *) flist[n]->func_xref[i]->to_data;
			if (func == NULL)
				continue;

			sub_idx = ia32_func_list_find_index (flist,
				flist_count, func);
			if (int_arr[sub_idx] == 1)
				int_arr[n] = 1;
		}
	}

	ia32_graphviz_func_out_2 (fp, flist, flist_count, int_arr, NULL);

	free (int_arr);
}


#ifdef	DUPE_DEBUG
void
dupe_alloc (unsigned int max_addr)
{
	addr_arr = xcalloc (max_addr, sizeof (unsigned int));
	addr_max = max_addr;
}

void
dupe_free (void)
{
	if (addr_arr != NULL)
		free (addr_arr);

	addr_max = 0;
}


void
dupe_check (unsigned int addr)
{
	/* not to use dupe check for runtime
	 */
	if (dupe_check_enabled == 0 || addr_max == 0)
		return;

	assert (addr < addr_max);
	if (addr_arr[addr] != 0) {
		ia32_debug (IA32_FATAL, "FATAL: (dupe_check) address access "
			"(%d) dupe at 0x%08x, dumping\n", addr_ac, addr);
		ia32_debug (IA32_FATAL, "\t%1d %1d %1d %1d %1d %1d %1d %1d\n",
			addr_arr[addr + 0], addr_arr[addr + 1],
			addr_arr[addr + 2], addr_arr[addr + 3],
			addr_arr[addr + 4], addr_arr[addr + 5],
			addr_arr[addr + 6], addr_arr[addr + 7]);

		assert (0);
	} else
		ia32_debug (IA32_DEBUG, "§ %d access: 0x%08x\n", addr_ac, addr);

	addr_arr[addr] = addr_ac;
	addr_ac += 1;
}
#endif


