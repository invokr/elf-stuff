/* func_handling.c - additional function processing for be2 engine
 *
 * by scut
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <elf.h>

#include <elf_base.h>
#include <elf_reloc.h>
#include <elf_section.h>
#include <ia32-function.h>
#include <ia32-decode.h>
#include <ia32-trace.h>
#include <ia32-dataflow.h>
#include <ia32-codeflow.h>

#include <func_handling.h>
#include <utility.h>
#include <common.h>


/*** static prototypes */

static void
func_bblock_remove_interfunc (ia32_bblock *cur, ia32_xref *xref);


/*** implementation */

unsigned int
func_bblock_deref_interfunc (ia32_function **flist, unsigned int flist_count)
{
	unsigned int		fn,
				changed = 0;
	ia32_bblock **		all = NULL;	/* all basic blocks of a function */
	unsigned int		all_count,
				all_walk;
	ia32_bblock *		cur;
	ia32_function *		target;
	ia32_xref **		xrarr;


	for (fn = 0 ; fn < flist_count ; ++fn) {

		/* do not operate on shallow-copied objects
		 */
		if (flist[fn]->is_copy) {
			ia32_function *	dupe_func;

			dupe_func = ia32_func_list_find_bystart (flist,
				flist_count, flist[fn]->start);
			assert (dupe_func != NULL);
			fnote ("function '%s' is a dupe of '%s'\n",
				flist[fn]->name, dupe_func->name);

			continue;
		}

		all = ia32_br_get_all (flist[fn]->br_root, &all_count);
		for (all_walk = 0 ; all_walk < all_count ; ++all_walk) {
			ia32_xref *	xref;

			cur = all[all_walk];

			/* check whether this basic block ends with a static
			 * inter-function reference. if not, skip it.
			 */
			if (cur->endtype != BR_END_CALL &&
				cur->endtype != BR_END_TRANSFER_INTER &&
				cur->endtype != BR_END_IF_INTER &&
				cur->endtype != BR_END_CALL_EXTERN)
			{
				continue;
			}

			xref = ia32_func_xref_findfrom (flist[fn],
				cur->end - cur->last_ilen - flist[fn]->start);

			assert (xref != NULL && (xref->to_type == IA32_XREF_FUNCTION ||
				xref->to_type == IA32_XREF_FUNCEXTERN));
			target = (ia32_function *) xref->to_data;
			assert (target != NULL || xref->to_type == IA32_XREF_FUNCEXTERN);

			fnote ("bblock'ing static inter-function reference "
				"from: %s -> %s\n", flist[fn]->name,
				target == NULL ? "(__extern__) ?" : target->name);

			/* sanity check: removal of this cross reference from
			 * the basic block itself.
			 */
			func_bblock_remove_interfunc (cur, xref);

			/* sort in all function references into their bblock
			 * other_xref.
			 */
			xref->from += flist[fn]->start - cur->start;
			/*xref->from -= cur->start;*/

			cur->other_xref_count += 1;
			cur->other_xref = xrealloc (cur->other_xref,
				cur->other_xref_count * sizeof (ia32_xref *));
			xrarr = (ia32_xref **) cur->other_xref;
			xrarr[cur->other_xref_count - 1] = xref;

			if (xref->to_type == IA32_XREF_FUNCEXTERN)
				continue;

			/* add the target function root block to the endbr
			 * array. note that this works for all three kinds of
			 * inter-function ends:
			 *  - _END_CALL/_END_TRANSFER_INTER
			 *    has no endbr, so this is the only one
			 *  - _END_IF_INTER
			 *    has one endbr (the false branch), so we add one
			 *    behind, the true basic block.
			 */
			cur->endbr_count += 1;
			cur->endbr = xrealloc (cur->endbr, cur->endbr_count *
				sizeof (ia32_bblock *));
			cur->endbr[cur->endbr_count - 1] = target->br_root;

			if (cur->endbr_external == NULL) {
				cur->endbr_external = xcalloc (cur->endbr_count,
					sizeof (unsigned int));
			} else {
				cur->endbr_external =
					xrealloc (cur->endbr_external,
					cur->endbr_count * sizeof (unsigned int));
			}
			cur->endbr_external[cur->endbr_count - 1] = 1;

			/* increase changed counter
			 */
			changed += 1;
		}

		if (all != NULL)
			free (all);
	}

	return (changed);
}


static void
func_bblock_remove_interfunc (ia32_bblock *cur, ia32_xref *xref)
{
	ia32_xref **	xrarr;
	ia32_xref *	xrw;	/* cross reference walker */
	unsigned int	xn;
	elf_reloc *	rel;


	xrarr = (ia32_xref **) cur->other_xref;
	for (xn = 0 ; xn < cur->other_xref_count ; ++xn) {
		xrw = xrarr[xn];
		assert (xrw != NULL);

		if (xrw->from != xref->from)
			continue;

		rel = (elf_reloc *) xrw->to_data;

		/* TODO: if this ever happens, implement removal of this cross
		 * reference from the basic block. should not happen, as we
		 * would have made an error in the analysis before (which we
		 * hopefully didn't ;).
		 */
		assert (0);
	}
}


void
fix_ustart (elf_base *obj)
{
	unsigned int	n;
	elf_section *	symtab_str;
	elf_section *	symtab;
	char *		fname;
	Elf32_Sym	sent;


	symtab = elf_section_list_find_type (obj->seclist, SHT_SYMTAB, NULL);
	assert (symtab != NULL);
	symtab_str = elf_section_list_find_index (obj->seclist,
		symtab->Shdr.sh_link);
	assert (symtab_str != NULL);


	for (n = 0 ; n < symtab->Shdr.sh_size ; n += sizeof (sent)) {
		memcpy (&sent, &symtab->data[n], sizeof (sent));
		if (ELF32_ST_TYPE (sent.st_info) == STT_FUNC)
			continue;

		fname = elf_string (symtab_str, sent.st_name);
		if (strcmp (fname, "_start") != 0)
			continue;

		fnote ("fixing _start to STT_FUNC");
		sent.st_info = STT_FUNC;
		memcpy (&symtab->data[n], &sent, sizeof (sent));

		break;
	}

	return;
}


/*** HEURISTICS */

void
find_position_curious_functions (ia32_function **flist, unsigned int flist_count)
{
	unsigned int	fn;


	printf ("listing position curious functions\n");

	for (fn = 0 ; fn < flist_count ; ++fn) {
		if (flist[fn]->is_pos_curious == 0)
			continue;

		printf ("0x%08x | %s\n", flist[fn]->start, flist[fn]->name);
	}
	printf ("\n");
}


void
find_abnormal_end_functions (ia32_function **flist, unsigned int flist_count)
{
	unsigned int	fn;


	printf ("listing functions which end abnormally\n");

	for (fn = 0 ; fn < flist_count ; ++fn) {
		if (flist[fn]->is_abnormal_end == 0)
			continue;

		printf ("0x%08x | %s\n", flist[fn]->start, flist[fn]->name);
	}
	printf ("\n");
}


/*** TESTING AND OUTPUT functions */

void
func_output (const char *outputfile, ia32_function **flist, unsigned int flist_count,
	char *fname, int loop_detect)
{
	FILE *		fp;
	ia32_function *	func;


	fp = fopen (outputfile == NULL ? "output.vcg" : outputfile, "w");
	if (fp == NULL) {
		perror ("fopen");
		exit (EXIT_FAILURE);
	}

	func = ia32_func_list_find_byname (flist, flist_count, fname);
	if (func == NULL) {
		fprintf (stderr, "no function named \"%s\" to output, sorry.\n",
			fname);

		exit (EXIT_FAILURE);
	}

	if (loop_detect) {
		ia32_domtree_build (func->br_root);
		ia32_loop_find (func->br_root, loop_detect == 2 ?
			IA32_LOOP_DRAGON : IA32_LOOP_NEST);
	}

	/*ia32_graphviz_br_output (fp, func->br_root, func);*/
	ia32_vcg_br_output (fp, func->br_root, func);
	fclose (fp);

	/*system ("dot -Tps -o output.ps output.dot");*/
	system ("rm -f output.ps ; xvcg -color -psoutput output.ps output.vcg");
	system ("gv output.ps");
/*	system ("rm output.ps output.dot"); */
}


void
func_livereg (const char *outputfile, ia32_function **flist, unsigned int flist_count,
	char *livereg_func, int loop_detect)
{
	FILE *		fp;
	ia32_function *	func =
		ia32_func_list_find_byname (flist, flist_count, livereg_func);

	if (func == NULL) {
		fprintf (stderr, "no function named \"%s\" to do d/f "
			"analysis on.\n", livereg_func);

		exit (EXIT_FAILURE);
	}

	ia32_df_bbtree_live (func, func->br_root);
	if (loop_detect) {
		ia32_domtree_build (func->br_root);
		ia32_loop_find (func->br_root, loop_detect == 2 ?
			IA32_LOOP_DRAGON : IA32_LOOP_NEST);
	}

	func->livereg_available = 1;

	fp = fopen (outputfile == NULL ? "output.vcg" : outputfile, "w");
	if (fp == NULL) {
		perror ("fopen");
		exit (EXIT_FAILURE);
	}

	/*ia32_graphviz_br_output (fp, func->br_root, func);*/
	ia32_vcg_br_output (fp, func->br_root, func);
	fclose (fp);

	/*system ("dot -Tps -o output.ps output.dot");*/
	system ("rm -f output.ps ; xvcg -color -psoutput output.ps output.vcg");
	system ("gv output.ps");
}


void
func_domtree (const char *outputfile, ia32_function **flist,
	unsigned int flist_count, char *domtree_func)
{
	FILE *		fp;
	ia32_function *	func =
		ia32_func_list_find_byname (flist, flist_count, domtree_func);

	if (func == NULL) {
		fprintf (stderr, "no function named \"%s\" to do dominator "
			"tree analysis on.\n", domtree_func);

		exit (EXIT_FAILURE);
	}

	ia32_domtree_build (func->br_root);

	fp = fopen (outputfile == NULL ? "output.vcg" : outputfile, "w");
	if (fp == NULL) {
		perror ("fopen");
		exit (EXIT_FAILURE);
	}

	ia32_vcg_domtree_output (fp, func->br_root);
	fclose (fp);

	system ("rm -f output.ps ; xvcg -color -psoutput output.ps output.vcg");
	system ("gv output.ps");
}


/* restore_section_data
 *
 * restore the backup'ed sections of `base'.
 *
 * return in any case
 */

void
restore_section_data (elf_base *base)
{
	elf_section *	cur;
	unsigned int	sn;

	for (sn = 0 ; sn < base->seclist->elem_count ; ++sn) {
		cur = base->seclist->list[sn];
		memcpy (cur->data, cur->data_backup, cur->data_len);
	}
}


void
backup_section_data (elf_base *base)
{
	elf_section *	cur;
	unsigned int	sn;

	for (sn = 0 ; sn < base->seclist->elem_count ; ++sn) {
		cur = base->seclist->list[sn];
		cur->data_backup = xcalloc (1, cur->data_len);
		memcpy (cur->data_backup, cur->data, cur->data_len);
	}
}


elf_reloc_list *
get_rodata_relocation (elf_base *base, elf_rel_list *rel_list)
{
	elf_section *		sh_walk = NULL;
	elf_reloc_list *	reloc_sec;

	do {
		sh_walk = elf_section_list_find_type (base->seclist,
			SHT_REL, sh_walk);

		if (sh_walk == NULL)
			break;

		reloc_sec = elf_reloc_list_create (base,
			elf_rel_list_find_byrelsection (rel_list, sh_walk),
			NULL, 0);

		if (strcmp (reloc_sec->reloc_modify->name, ".rodata") != 0) {
			elf_reloc_list_destroy (reloc_sec);
			continue;
		}

		elf_reloc_list_hashgen (reloc_sec, 0);

		return (reloc_sec);
	} while (1);

	return (NULL);
}


void
relocate_sections (elf_base *base, elf_rel_list *rel_list)
{
	elf_section *		sh_walk = NULL;
	elf_reloc_list *	reloc_sec;

	do {
		sh_walk = elf_section_list_find_type (base->seclist,
			SHT_REL, sh_walk);

		if (sh_walk == NULL)
			break;

		reloc_sec = elf_reloc_list_create (base,
			elf_rel_list_find_byrelsection (rel_list, sh_walk),
			NULL, 0);

#if 0
		/* do not modify code sections yet
		 */
		if (reloc_sec->reloc_modify->Shdr.sh_flags & SHF_EXECINSTR)
			continue;
#endif

		/* some speed optimization
		 */
		elf_reloc_list_hashgen (reloc_sec, 0);
		relocate_data (base, reloc_sec);

		/* FIXME: memleak */
	} while (1);

	return;
}


code_pair *
code_pair_extract (elf_base *base, elf_section_list *seclist,
	elf_rel_list *rel_list)
{
	code_pair	current;
	code_pair *	cp;		/* temporary object */
	code_pair *	root = NULL;
	code_pair *	listel = NULL;
	elf_section *	sh_walk = NULL;


	do {
		sh_walk = elf_section_list_find_type (base->seclist,
			SHT_PROGBITS, sh_walk);

		if (sh_walk == NULL)
			break;

		if ((sh_walk->Shdr.sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) !=
			(SHF_ALLOC | SHF_EXECINSTR))
			continue;

		memset (&current, 0x00, sizeof (current));

		current.next = NULL;
		current.code_section = sh_walk;
		current.reloc = elf_rel_list_find_bymodsection (rel_list, sh_walk);
		assert (current.reloc != NULL);

		cp = xcalloc (1, sizeof (code_pair));
		memcpy (cp, &current, sizeof (code_pair));

		if (listel == NULL) {
			root = listel = cp;
		} else {
			listel->next = cp;
			listel = cp;
		}
	} while (1);

	return (root);
}


void
relocate_data (elf_base *eb, elf_reloc_list *rl)
{
	unsigned int	rn;		/* relocation entry index walker */
	elf_reloc *	rel;		/* one relocation entry at a time */

	unsigned int	value,		/* absolute base value for reloc */
			symval,		/* the encoded symbol value */
			addend;		/* value found in-place in memory */
	unsigned int *	place;		/* where to commit the relocation */


	for (rn = 0 ; rn < rl->reloc_count ; ++rn) {
		rel = rl->reloc[rn];

		assert (rel->sym != NULL);
		if (rel->sym->sec == NULL) {
			fprintf (stderr, "FATAL: relocation refers NULL "
				"section. most likely this is the result\n"
				"       of dangling *common references, see "
				"manual how to fix this.\n");

			exit (EXIT_FAILURE);
			assert (rel->sym->sec != NULL);
		}

		/* rl->reloc_modify is the only section we modify.
		 * rel->sym->sec is the section we use to compute the address
		 *   we store in the reloc_modify section.
		 */
		place = (unsigned int *)
			&rl->reloc_modify->data[rel->orig.r_offset];

		addend = *place;

		value = (unsigned int) rel->sym->sec->data;
		symval = rel->sym->sent.st_value;

#if 0
		fnote (" [A: 0x%08x, S: 0x%08x, SEC: %08x]\n",
			addend, symval, value);
#endif

		switch (ELF32_R_TYPE (rel->orig.r_info)) {
		/* R_386_32 = S + A */
		case (R_386_32):
			value += symval + addend;
			break;
		default:
			assert (0);
			break;
		}

#if 0
		fnote ("DATA RELOCATION => 0x%08x (%s) into 0x%08x ###\n",
			value, rel->sym->name == NULL ? "?" : rel->sym->name,
			(unsigned int) place);
#endif

		*place = value;
	}
}

