/* objobf.c - x86/Linux ELF object obfuscator utility
 *
 * by scut
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <elf_base.h>
#include <elf_reloc.h>
#include <elf_section.h>
#include <ia32-function.h>
#include <ia32-decode.h>
#include <ia32-encode.h>
#include <ia32-trace.h>
#include <ia32-dataflow.h>
#include <ia32-codeflow.h>

#include <common.h>
#include <codegen.h>
#include <objwriter.h>
#include <func_handling.h>
#include <utility.h>

#include <version.h>

	/* minimum number of instructions required to do sane instruction
	 * count profiling. below, hardwired all-equal probabilities are used.
	 */
#define	OBJOBF_MIN_INST_PROFILE	256

/*** EXTERNS */
extern int	quiet;
extern ia32_df_abi_hook_type ia32_df_abi_hook;


/*** STATIC PROTOTYPES */


/* do_reguse_profiling
 *
 * do a register use profile of all functions in `flist', which is
 * `flist_count' items long. print the profile to stdout.
 *
 * return in any case
 */

static void
do_reguse_profiling (ia32_function **flist, unsigned int flist_count);


/* do_instuse_profiling
 *
 * do an instruction usage profile of all functions in `flist', which is
 * `flist_count' items long. print the profile to stdout. if `machine' is
 * non-zero, a machine parseable format is used.
 *
 * return in any case
 */

static void
do_instuse_profiling (ia32_function **flist, unsigned int flist_count,
	int machine);


/* split_bblocks
 *
 * globally split random basic blocks of all functions within `flist', which
 * is `flist_count' items long. randomly, `split_factor' * global_block_count
 * blocks are selected and split at a random point by either a static jump or
 * an opaque construct. the later involves code duplication.
 *
 * return in any case
 */

static void
split_bblocks (ia32_function **flist, unsigned int flist_count,
	double split_factor);


/* split_bblock_single
 *
 * split a single basic block `bb' at a random point. adjust all the basic
 * block related structures.
 *
 * return in any case
 */

static void
split_bblock_single (ia32_bblock *bb);


/* bblock_duplicate
 *
 * create a deep copy of the basic block `bb' and all its data structures.
 *
 * return new basic block on success
 * return NULL on failure
 */

static ia32_bblock *
bblock_duplicate (ia32_bblock *bb);


/* bblock_split
 *
 * split the basic block `bb' at the `point'th instruction into a new block
 * lieing after `bb'. `bb' is converted to a PASS type.
 *
 * return in any case
 */

static void
bblock_split (ia32_bblock *bb, unsigned int point);


/* insert_junk_instructions
 *
 * do a live register analysis for all basic blocks of all functions in
 * `flist', which is `flist_count' items long. then insert junk instructions
 * at a factor of `junk_function', meaning the overall instruction count of
 * the object is multiplied by this factor.
 *
 * return in any case
 */

static void
insert_junk_instructions (ia32_function **flist, unsigned int flist_count,
	double junk_factor);


/* insert_junk_instruction_bb_once
 *
 * like _bb, but inserts only one random instruction at a random point within
 * `bb'. registers will be picked according to `prof', if non-NULL, the
 * instruction choosen with `iprof', if non-NULL.
 *
 * return zero in case no instruction was inserted
 * return one on success
 */

static int
insert_junk_instructions_bb_once (ia32_bblock *bb,
	reguse_profile *prof, instuse_profile *iprof);


/* swapinst_bblocks
 *
 * swap instructions in basic blocks with rate `swap_factor'. all basic blocks
 * in all functions in `flist', which is `flist_count' items long are
 * processed.
 *
 * return in any case
 */

static void
swapinst_bblocks (ia32_function **flist, unsigned int flist_count,
	double swap_factor);


/* bblock_swap_commit
 *
 * commit a random swap of instruction in basic block `bb'. the total number
 * of swaps possible has to be given with `swap_possible'.
 *
 * return in any case
 */

static void
bblock_swap_commit (ia32_bblock *bb, unsigned int swap_possible);


/* bblock_swap_count
 *
 * count the number of possible swaps within basic block `bb'.
 *
 * return count in any case
 */

static unsigned int
bblock_swap_count (ia32_bblock *bb);


/* bblock_is_instruction_swapable
 *
 * check two instructions at `pt1' and `pt2' in the basic block `bb' on
 * swapability without dataflow damage.
 *
 * return zero if they are not swapable
 * return non-zero in case they are
 */

static int
bblock_is_instruction_swapable (ia32_bblock *bb,
	unsigned int pt1, unsigned int pt2);


/* bblock_is_instruction_independant
 *
 * checks indep(df1,df2,df3) condition defined as:
 *	df1.use \cap df2.def = \emptyset
 *  and df1.use \cap df3.def = \emptyset
 *
 * return zero in case the condition failes
 * return one on success
 */

static int
bblock_is_instruction_independant (ia32_df_set *df1, ia32_df_set *df2,
	ia32_df_set *df3);


/*** GLOBAL DATA */

char *	output_filename = "output.o";
char *	livereg_func = NULL;
char *	domtree_func = NULL;
char *	visual_func = NULL;
char *	visual_obf_func = NULL;
extern int	ia32_verbosity;

char *	random_file = "/dev/urandom";

obfuscation_param	obf;


/*** IMPLEMENTATION */

static void
usage (char *progname)
{
	fprintf (stderr, "usage: %s [options] <input.o>\n\n", progname);

	fprintf (stderr, "options - general\n"
		"\t-o file  output object filename (default: \"output.o\")\n"
		"\t-v num   verbosity, 0 (low) to 3 (max), default: low\n"
		"\t-r file  use data from file to produce random numbers\n"
		"\n"
		"options - graphing\n"
		"\t-l func  dump a register usage analysis (dataflow: live reg)\n"
		"\t-c func  dump a control flow graph\n"
		"\t-d func  dump a dominator tree graph\n"
	/*	"\t-C func  dump a control flow graph, after obfuscation\n" */
		"\t-n       detect natural loops (nest-prefer)\n"
		"\t-N       detect natural loops (group-prefer, dragon book)\n"
		"\t-u       create and print a register usage profile\n"
		"\t-i       create and print an instruction usage profile\n"
		"\t-I       just like -i, but machine parseable\n"
		"\n"
		"options - obfuscation\n"
		"\t-A       ALL-mode: activate a good amount of obfuscation\n"
		"\t-e       entangle function objects (simple, cfg unmerged)\n"
		"\t-j S     scale code by inserting junk, factor S, S >= 1.0\n"
		"\t   -m    mark all junk instructions by prepending NOP\n"
		"\t-s F     split basic blocks at factor F, 0.0 <= F <= 1.0\n"
		"\t   -O P  for every split block, with a probability of P,\n"
		"\t         duplicate the new block and make the path opaque,\n"
		"\t         0.0 <= P <= 1.0 (default: 0.5). only active with -s\n"
		"\t-w F     do instruction swaps at factor F, 0.0 <= F <= 1.0\n"
		"\n");

	exit (EXIT_FAILURE);
}


int
main (int argc, char *argv[])
{
	char		c;
	char *		progname = argv[0];
	char *		elfname;

	elf_base *		base;
	elf_rel_list *		rel_list;
	elf_reloc_list *	rel_rodata;
	code_pair *		exec_sections;
	code_pair *		exec_sec;	/* walker */
	unsigned int		lidx;
	unsigned int		reloc_code_list_count = 0;
	elf_reloc_list **	reloc_code_list = NULL;

	ia32_function **	flist = NULL;
	unsigned int		flist_count = 0;
	int			loop_detect = 0;
	int			do_reguse = 0,
				do_instuse = 0;


	printf ("objobf - x86/linux ELF object obfuscator, version "VERSION".\n");
	printf ("Copyright (C) 2002-2003 -- TEAM TESO\n\n");

	printf ("-+- PRELIMINARY BETA SOFTWARE, DO NOT USE IN PRODUCTION -+-\n\n");
	if (argc < 2)
		usage (progname);

	quiet = 1;
	memset (&obf, 0x00, sizeof (obf));

	while ((c = getopt (argc, argv, "o:Aej:ms:O:w:l:c:d:C:nNuiIv:r:")) != EOF) {
		switch (c) {
		case ('o'):
			output_filename = optarg;
			break;
		case ('A'):
			obf.entangle_basic = 1;
			obf.junk_instructions = 1;
			obf.junk_rate = 6.0;
			obf.split_blocks = 1;
			obf.split_opaque_cond_copy_set = 1;
			obf.split_opaque_cond_copy = 0.75;
			break;
		case ('e'):
			obf.entangle_basic = 1;
			break;
		case ('j'):
			obf.junk_instructions = 1;
			if (sscanf (optarg, "%lf", &obf.junk_rate) != 1)
				usage (progname);
			if (obf.junk_rate < 1.0)
				usage (progname);
			break;
		case ('m'):
			obf.junk_debug = 1;
			break;
		case ('s'):
			obf.split_blocks = 1;
			if (sscanf (optarg, "%lf", &obf.split_factor) != 1)
				usage (progname);
			if (obf.split_factor < 0.0 || obf.split_factor > 1.0)
				usage (progname);

			if (obf.split_opaque_cond_copy_set == 0)
				obf.split_opaque_cond_copy = 0.5;
			break;
		case ('O'):
			if (sscanf (optarg, "%lf", &obf.split_opaque_cond_copy) != 1)
				usage (progname);
			if (obf.split_opaque_cond_copy < 0.0 ||
				obf.split_opaque_cond_copy > 1.0)
			{
				usage (progname);
			}
			obf.split_opaque_cond_copy_set = 1;
			break;
		case ('w'):
			if (sscanf (optarg, "%lf", &obf.instruction_swap_rate) != 1)
				usage (progname);
			if (obf.instruction_swap_rate < 0.0 ||
				obf.instruction_swap_rate > 1.0)
			{
				usage (progname);
			}
			obf.instruction_swap = 1;
			break;
		case ('l'):
			livereg_func = optarg;
			break;
		case ('c'):
			visual_func = optarg;
			break;
		case ('d'):
			domtree_func = optarg;
			break;
		case ('C'):
			visual_obf_func = optarg;
			break;
		case ('n'):
			loop_detect = 1;
			break;
		case ('N'):
			loop_detect = 2;
			break;
		case ('u'):
			do_reguse = 1;
			break;
		case ('i'):
			do_instuse = 1;
			break;
		case ('I'):
			do_instuse = 2;
			break;
		case ('v'):
			if (sscanf (optarg, "%u", &ia32_verbosity) != 1)
				usage (progname);
			if (ia32_verbosity > 0)
				quiet = 0;
			break;
		case ('r'):
			random_file = optarg;
			break;
		default:
			usage (progname);
		}
	}

	if ((optind + 1) > argc)
		usage (progname);

	elfname = argv[optind];
	if (elfname[0] == '-')
		usage (progname);
	++optind;
	if (optind != argc)
		usage (progname);

	be_randinit_file (random_file);
	ia32_df_abi_hook = ia32_df_abi_sysvlinux;

	base = elf_base_load (elfname);
	if (base == NULL) {
		fprintf (stderr, "elf_base_load failed\n");

		exit (EXIT_FAILURE);
	}

	elf_section_secalloc (base->seclist);

	/* do the relocations
	 */
	rel_list = elf_rel_list_create (base);
	exec_sections = code_pair_extract (base, base->seclist, rel_list);
	for (exec_sec = exec_sections ; exec_sec != NULL ;
		exec_sec = exec_sec->next)
	{
		ia32_function **	flist_sec;
		unsigned int		flist_sec_count;

		printf ("codepair: %s / %s with %s\n",
			exec_sec->code_section->name,
			exec_sec->reloc->reloc_section->name,
			exec_sec->reloc->reloc_symbol->name);

		flist_sec = elf_function_list_create (base->elf, base->seclist,
			exec_sec->code_section, &flist_sec_count);

		if (flist_sec == NULL) {
			fprintf (stderr, "elf_function_list_create failed on "
				"%s\n", exec_sec->code_section->name);

			exit (EXIT_FAILURE);
		}

		/* append new functions to global list.
		 */
		flist = xrealloc (flist, (flist_count + flist_sec_count) *
			sizeof (ia32_function *));
		memcpy (&flist[flist_count], flist_sec, flist_sec_count *
			sizeof (ia32_function *));

		printf ("adding %d items to %d items long list\n", flist_sec_count,
			flist_count);
		flist_count += flist_sec_count;
		free (flist_sec);
	}
	elf_function_list_sort (flist, flist_count);

	/* build relocation lists
	 */
	for (exec_sec = exec_sections ; exec_sec != NULL ;
		exec_sec = exec_sec->next)
	{
		lidx = reloc_code_list_count;
		reloc_code_list_count += 1;
		reloc_code_list = xrealloc (reloc_code_list,
			reloc_code_list_count * sizeof (elf_reloc_list *));

		reloc_code_list[lidx] = elf_reloc_list_create (base,
			exec_sec->reloc, flist, flist_count);
		elf_reloc_list_hashgen (reloc_code_list[lidx], 0);
	}

	backup_section_data (base);
	relocate_sections (base, rel_list);
	rel_rodata = get_rodata_relocation (base, rel_list);

	ia32_func_list_dump (flist, flist_count);

	/* do the real intra-function analysis
	 */
	lidx = 0;
	for (exec_sec = exec_sections ; exec_sec != NULL ;
		exec_sec = exec_sec->next, ++lidx)
	{
		ia32_func_treeplain (&flist, &flist_count,
			reloc_code_list[lidx], rel_rodata,
			exec_sec->code_section->sh_idx);
	}

	if (visual_func != NULL) {
		func_output ("output.vcg", flist, flist_count, visual_func,
			loop_detect);

		exit (EXIT_SUCCESS);
	}

	ia32_func_list_walk (flist, flist_count, ia32_func_oxref_fromfunc);

	if (livereg_func != NULL) {
		func_livereg ("output.vcg", flist, flist_count, livereg_func,
			loop_detect);

		exit (EXIT_SUCCESS);
	}

	printf ("\n### FUNCTION LIST BEGIN ###\n");
	ia32_func_list_dump (flist, flist_count);
	printf ("### FUNCTION LIST END ###\n\n");

	func_bblock_deref_interfunc (flist, flist_count);
	restore_section_data (base);

	if (domtree_func != NULL) {
		func_domtree ("output.vcg", flist, flist_count, domtree_func);

		exit (EXIT_SUCCESS);
	}

	obj_calculate_bblock_mem (flist, flist_count);
	obj_flist_memlift (flist, flist_count);

	if (do_reguse)
		do_reguse_profiling (flist, flist_count);

	if (do_instuse) {
		do_instuse_profiling (flist, flist_count,
			do_instuse == 1 ? 0 : 1);
	}

	if (do_reguse || do_instuse)
		exit (EXIT_SUCCESS);

	printf ("obfuscating... (this can take a while)\n\n");

	/* TODO: insert user-supplyable order string parsing in here
	 */
	if (obf.instruction_swap)
		swapinst_bblocks (flist, flist_count,
			obf.instruction_swap_rate);

	if (obf.split_blocks)
		split_bblocks (flist, flist_count, obf.split_factor);

	if (obf.junk_instructions)
		insert_junk_instructions (flist, flist_count, obf.junk_rate);

	obj_write (output_filename, base, flist, flist_count, &obf);

	printf ("wrote object file \"%s\".\n", output_filename);

#if 0
	/* not yet working */
	if (visual_obf_func != NULL) {
		func_output ("output.vcg", flist, flist_count, visual_obf_func);

		exit (EXIT_SUCCESS);
	}
#endif

	be_randend ();

	exit (EXIT_SUCCESS);
}


static void
do_reguse_profiling (ia32_function **flist, unsigned int flist_count)
{
	unsigned int		fn;
	reguse_profile *	prof;


	for (fn = 0 ; fn < flist_count ; ++fn)
		ia32_df_bbtree_live (flist[fn], flist[fn]->br_root);

	prof = codegen_reguse_profile_create (flist, flist_count);
	codegen_reguse_profile_print (prof);
	free (prof);
}


static void
do_instuse_profiling (ia32_function **flist, unsigned int flist_count,
	int machine)
{
	instuse_profile *	iprof;

	iprof = codegen_instuse_profile_create (flist, flist_count);
	codegen_instuse_profile_print (iprof, machine);
	free (iprof);
}


static void
split_bblocks (ia32_function **flist, unsigned int flist_count,
	double split_factor)
{
	unsigned int	fn,
			bn,
			blocks_to_split;
	ia32_bblock **	all;
	unsigned int 	all_count;


	for (fn = 0 ; fn < flist_count ; ++fn)
		ia32_df_bbtree_live (flist[fn], flist[fn]->br_root);

	all = obj_bblist_build (flist, flist_count, &all_count);

	/* split the desired number of blocks by picking random blocks out of
	 * the global list
	 */
	for (blocks_to_split = all_count * split_factor ; blocks_to_split > 0 ;
		--blocks_to_split)
	{
		bn = be_random (all_count);
#if 0
		printf ("%d. splitting: 0x%x - 0x%x\n", blocks_to_split,
			all[bn]->start, all[bn]->end);
#endif
		split_bblock_single (all[bn]);
	}

	free (all);
}


static void
split_bblock_single (ia32_bblock *bb)
{
	unsigned int		spt;	/* split point, count before inst */
	ia32_df_bblock *	dfb;


	assert (bb->mem_allocated);
	dfb = (ia32_df_bblock *) bb->user->dfb;
	assert (dfb != NULL);

	/* select a random split point, if there is anything to choose
	 */
	spt = 0;
	if (dfb->df_count > 0)
		spt = be_random (dfb->df_count);

	bblock_split (bb, spt);

	/* make a conditional split out of the block
	 */
	if (be_random_coin (obf.split_opaque_cond_copy)) {
		unsigned int	bb_size;

		bb->endbr = xrealloc (bb->endbr, 2 * sizeof (ia32_bblock *));
		bb->endbr_count = 2;
		bb->endbr[1] = bblock_duplicate (bb->endbr[0]);

		bb_size = bb->end - bb->start;

		assert (bb->mem_allocated);
		bb->mem = xrealloc (bb->mem, bb_size + 2);
		bb->end += 2;

		bb->endtype = BR_END_IF;
		bb->mem[bb_size + 0] = IA32_OPCODE_JCC | be_random (0x10);
		bb->mem[bb_size + 1] = 0xfe;
		assert (bb->last_ilen == 0);
		bb->last_ilen = 2;

		ia32_df_bblock_append_instruction (bb->user->dfb,
			&bb->mem[bb_size]);
	}
}


/* swapinst_bblocks
 *
 * swap instructions in basic blocks with rate `swap_factor'. all basic blocks
 * in all functions in `flist', which is `flist_count' items long are
 * processed.
 *
 * return in any case
 */

static void
swapinst_bblocks (ia32_function **flist, unsigned int flist_count,
	double swap_factor)
{
	unsigned int	fn,
			bn,
			sn;	/* swap walker */
	ia32_bblock **	all;
	unsigned int 	all_count,
			swap_count,
			do_swaps;


	for (fn = 0 ; fn < flist_count ; ++fn)
		ia32_df_bbtree_live (flist[fn], flist[fn]->br_root);

	all = obj_bblist_build (flist, flist_count, &all_count);

	for (bn = 0 ; bn < all_count ; ++bn) {
		swap_count = bblock_swap_count (all[bn]);
		do_swaps = swap_factor * swap_count;

		/* do a fixed number of random swap, even risking reverting a
		 * swap.
		 */
		for (sn = 0 ; sn < do_swaps ; ++sn)
			bblock_swap_commit (all[bn], swap_count);
	}

	free (all);
}


static void
bblock_swap_commit (ia32_bblock *bb, unsigned int swap_possible)
{
	unsigned int	icount,
			pt1,
			pt2,
			sidx,
			i1_len,
			i2_len,
			blk_size,
			swap_count;
	int		blk_offset;
	unsigned char *	mi1;
	unsigned char *	mi2;
	unsigned char *	blk;
	unsigned char	i1_data[IA32_INSTRUCTION_MAXLEN],
			i2_data[IA32_INSTRUCTION_MAXLEN];
	int *		dont_touch;


	/* we want to do the n'th possible swap
	 */
	assert (swap_possible >= 1);
	sidx = be_random (swap_possible);
	icount = ia32_br_instruction_count (bb);

	if (bb->endtype != BR_END_PASS)
		icount -= 1;

	swap_count = 0;
	pt2 = 0;
	for (pt1 = 0 ; pt1 < icount ; ++pt1) {
		for (pt2 = pt1 ; pt2 < icount ; ++pt2) {
			if (pt1 == pt2)
				continue;

			if (bblock_is_instruction_swapable (bb, pt1, pt2) == 0)
				continue;

			if (sidx == swap_count)
				goto swap_reached;
			swap_count += 1;
		}
	}

swap_reached:
	/* no swap possible (swapped enough already?)
	 */
	if (sidx != swap_count || pt1 >= pt2)
		return;

	printf ("swap: %d with %d\n", pt1, pt2);

	mi1 = ia32_instruction_advance (bb->mem, pt1);
	i1_len = ia32_instruction_length (mi1);
	memcpy (i1_data, mi1, i1_len);
	mi2 = ia32_instruction_advance (bb->mem, pt2);
	i2_len = ia32_instruction_length (mi2);
	memcpy (i2_data, mi2, i2_len);

	/* "the space between"
	 */
	blk_size = mi2 - mi1 - i1_len;
	blk_offset = i2_len - i1_len;
	blk = mi1 + i1_len;
	if (blk_size > 0)
		memmove (blk + blk_offset, blk, blk_size);

	memcpy (mi1, i2_data, i2_len);
	memcpy (mi2 + blk_offset, i1_data, i1_len);

	if (bb->user != NULL && bb->user->dfb != NULL) {
		ia32_df_bblock *	dfb;
		ia32_df_set		set_temp;

		dfb = (ia32_df_bblock *) bb->user->dfb;
		set_temp = dfb->df[pt1];
		dfb->df[pt1] = dfb->df[pt2];
		dfb->df[pt2] = set_temp;
	}

	/* if relocations cover the swapped instructions, account for them
	 */
	if (bb->other_xref_count > 0) {
		dont_touch = xcalloc (bb->other_xref_count, sizeof (int));

		obj_bblock_move_reloc (bb, mi1 - bb->mem, i1_len,
			mi2 - mi1 + blk_offset, dont_touch);
		obj_bblock_move_reloc (bb, mi2 - bb->mem, i2_len,
			-(mi2 - mi1), dont_touch);

		free (dont_touch);
	}
}


static unsigned int
bblock_swap_count (ia32_bblock *bb)
{
	unsigned int	swap_count = 0,
			icount,
			pt1,
			pt2;


	icount = ia32_br_instruction_count (bb);
	if (icount <= 1)
		return (0);

	if (bb->endtype != BR_END_PASS)
		icount -= 1;

	for (pt1 = 0 ; pt1 < icount ; ++pt1) {
		for (pt2 = pt1 ; pt2 < icount ; ++pt2) {
			if (pt1 == pt2)
				continue;

			if (bblock_is_instruction_swapable (bb, pt1, pt2) == 0)
				continue;

			swap_count += 1;
			printf ("0x%x-0x%x, %d.: pt1 = %d, pt2 = %d, "
					"swapable = %s\n",
				bb->start, bb->end, swap_count, pt1, pt2,
				bblock_is_instruction_swapable (bb, pt1, pt2) ?
					"YES" : "NO");
		}
	}

	return (swap_count);
}


static int
bblock_is_instruction_swapable (ia32_bblock *bb,
	unsigned int pt1, unsigned int pt2)
{
	unsigned int	ptn,
			pt_temp;
	ia32_df_bblock *	dfb;


	dfb = (ia32_df_bblock *) bb->user->dfb;
	assert (dfb != NULL);
	assert (pt1 < dfb->df_count && pt2 < dfb->df_count);

	if (pt1 > pt2) {
		pt_temp = pt1;
		pt1 = pt2;
		pt2 = pt_temp;
	} else if (pt1 == pt2)
		return (1);

	/* for every instruction C between A....B, where A...C..B, check that:
	 *    A.use \cap C.def = \emptyset
	 *    A.use \cap B.def = \emptyset
	 *    C.use \cap A.def = \emptyset
	 *    C.use \cap B.def = \emptyset
	 *    B.use \cap A.def = \emptyset
	 *    B.use \cap C.def = \emptyset
	 */
	for (ptn = pt1 ; ptn < pt2 ; ++ptn) {
		if (bblock_is_instruction_independant
			(&dfb->df[pt1], &dfb->df[pt2], &dfb->df[ptn]) == 0
			|| bblock_is_instruction_independant
			(&dfb->df[ptn], &dfb->df[pt1], &dfb->df[pt2]) == 0
			|| bblock_is_instruction_independant
			(&dfb->df[pt2], &dfb->df[pt1], &dfb->df[ptn]) == 0)
		{
			return (0);
		}
	}

	return (1);
}


static int
bblock_is_instruction_independant (ia32_df_set *df1, ia32_df_set *df2,
	ia32_df_set *df3)
{
	if ((df1->use & df2->def) == 0 &&
		(df1->use & df3->def) == 0)
		return (1);

	return (0);
}


static ia32_bblock *
bblock_duplicate (ia32_bblock *bb)
{
	ia32_bblock *		new;
	unsigned int		bb_size,
				en;	/* endbr index walker */


	new = ia32_br_new ();
	memcpy (new, bb, sizeof (ia32_bblock));
	bb_size = bb->end - bb->start;

	new->mem = xcalloc (1, bb_size);
	if (new->mem != NULL && bb->mem != NULL)
		memcpy (new->mem, bb->mem, bb_size);

	if (bb->endbr_count > 0) {
		new->endbr = xcalloc (bb->endbr_count, sizeof (ia32_bblock *));
		memcpy (new->endbr, bb->endbr,
			bb->endbr_count * sizeof (ia32_bblock *));

		/* replace self references to really duplicate the block
		 * instead of just creating another instance
		 */
		for (en = 0 ; en < new->endbr_count ; ++en) {
			if (new->endbr[en] == bb)
				new->endbr[en] = new;
		}
	}

	if (bb->endbr_external != NULL) {
		new->endbr_external = xcalloc (bb->endbr_count,
			sizeof (unsigned int));
		memcpy (new->endbr_external, bb->endbr_external,
			bb->endbr_count * sizeof (unsigned int));
	}

	new->other_xref = (void *) obj_bblock_copy_reloc (bb);

	new->user = xcalloc (1, sizeof (ia32_bb_user));
	new->user->dfb = ia32_df_bblock_copy (bb->user->dfb);
	new->user->instr_insert = codegen_instr_array_copy
		(bb->user->instr_insert);

	return (new);
}


static void
bblock_split (ia32_bblock *bb, unsigned int point)
{
	ia32_bblock *		new;
	unsigned char *		mem_split;
	unsigned int		bb_size,
				bb_new_size;
	ia32_df_bblock *	dfb;


	assert (bb->mem_allocated);
	dfb = (ia32_df_bblock *) bb->user->dfb;
	assert (dfb != NULL);
	assert (point <= dfb->df_count);

	mem_split = bb->mem;
	if (bb->mem != NULL)
		mem_split = ia32_instruction_advance (bb->mem, point);

	bb_size = bb->end - bb->start;
	bb_new_size = bb_size - (mem_split - bb->mem);

	/* similar to ia32_br_split in ia32-trace.c, but we cannot use this,
	 * as it is designed for use in the analyzation phase and cannot cope
	 * with dataflow splitting
	 *
	 * 1. copy instruction space memory
	 */
	new = ia32_br_new ();
	memcpy (new, bb, sizeof (ia32_bblock));
	new->mem = xcalloc (1, bb_new_size);
	if (new->mem != NULL && mem_split != NULL)
		memcpy (new->mem, mem_split, bb_new_size);

	/* 2. adjust sizes
	 */
	new->start += (mem_split - bb->mem);
	bb->end -= bb_new_size;

	/* 3. make first block a pass block to the new one
	 */
	bb->endtype = BR_END_PASS;
	bb->endbr_count = 1;
	bb->endbr = xcalloc (1, sizeof (ia32_bblock *));
	bb->endbr[0] = new;
	bb->last_ilen = bb->last_unused = 0;
	bb->endbr_external = NULL;

	/* 4. split relocation information, dataflow information and duplicate
	 * codeflow information using duplicate pointers, as modification is
	 * unlikely. TODO: do a deep copy of codeflow structures
	 */
	obj_bblock_split_reloc (bb, new);

	new->user = xcalloc (1, sizeof (ia32_bb_user));
	new->user->dfb = ia32_df_bblock_split (bb->user->dfb, point);
	new->user->instr_insert = codegen_instr_array_split
		(bb->user->instr_insert, point);

	bb->mem = xrealloc (bb->mem, bb->end - bb->start);
}


static void
insert_junk_instructions (ia32_function **flist, unsigned int flist_count,
	double junk_factor)
{
	unsigned int	fn,
			bbn;
	reguse_profile *	prof;
	instuse_profile *	iprof;

	unsigned int	inst_now,
			inst_original;
	ia32_bblock **	all;
	unsigned int 	all_count;


	for (fn = 0 ; fn < flist_count ; ++fn)
		ia32_df_bbtree_live (flist[fn], flist[fn]->br_root);

	prof = codegen_reguse_profile_create (flist, flist_count);
	iprof = codegen_instuse_profile_create (flist, flist_count);

	if (iprof->lines < OBJOBF_MIN_INST_PROFILE) {
		printf ("INFO: too few instructions in object file "
			"(%d, %d required) to\n"
			"      generate instructions according to profile, "
			"falling back\n"
			"      to hardwired operation.\n",
			iprof->lines, OBJOBF_MIN_INST_PROFILE);

		free (iprof);
		iprof = NULL;
	}


	inst_original = inst_now = prof->lines;
	all = obj_bblist_build (flist, flist_count, &all_count);
	assert (all_count > 0);

	while (inst_now < (junk_factor * inst_original)) {
		ia32_bblock *bb_cur;
		bbn = be_random (all_count);

		bb_cur = all[bbn];
		insert_junk_instructions_bb_once
			(bb_cur,
			prof,
			iprof);
		inst_now += 1;
	}

	free (all);
	free (prof);
}


static int
insert_junk_instructions_bb_once (ia32_bblock *bb,
	reguse_profile *prof, instuse_profile *iprof)
{
	int		sclob;	/* source operand clobbering */
	unsigned int	ic,
			in;
	instr_array *	ia;
	ia32_df_bblock *	dfb;
	ia32_instruction *	inst;
	unsigned int	opcode,
			test_inst_len;
	unsigned char	test_inst[16];
	ia32_instruction *	t_inst,
				t_inst_s;
	unsigned char		t_inst_str[128];

	ia32_df_set *	df,
			df_s;


	assert (bb->user != NULL && bb->user->dfb != NULL);
	dfb = (ia32_df_bblock *) bb->user->dfb;
	ic = ia32_br_instruction_count (bb);

	ia = bb->user->instr_insert;
	if (ia == NULL) {
		ia = xcalloc (1, sizeof (instr_array));
		ia->in_count = ic;

		ia->in_points = xcalloc (ic, sizeof (ia32_instruction *));
		ia->in_points_opcode = xcalloc (ic, sizeof (unsigned int *));
		ia->in_points_icount = xcalloc (ic, sizeof (unsigned int));
	}

	/* do not insert anything into dangling zero-size blocks
	 */
	if (ic == 0)
		return (0);
	
	in = be_random (ic);

	ia->in_points_opcode[in] = xrealloc (ia->in_points_opcode[in],
		(ia->in_points_icount[in] + 1) * sizeof (unsigned int));

	assert (in < dfb->df_count);
	opcode = codegen_generate_operation (dfb->df[in].in,
		&sclob, iprof);
	ia->in_points_opcode[in][ia->in_points_icount[in]] = opcode;

	ia->in_points[in] = xrealloc (ia->in_points[in],
		(ia->in_points_icount[in] + 1) *
		sizeof (ia32_instruction));
	inst = codegen_generate_instruction (opcode, dfb->df[in].in,
		&ia->in_points[in][ia->in_points_icount[in]],
		sclob, prof);
	if (inst == NULL) {
		/*printf ("DEBUG: failed to generate an instruction "
			"at 0x%x:%d\n", bb->start, in);*/
		return (0);
	}

	test_inst_len = ia32_encode_instruction (opcode,
		&ia->in_points[in][ia->in_points_icount[in]], test_inst);

	/* should not happen
	 */
	if (test_inst_len == 0) {
		printf ("DEBUG: failed to test-encode instruction at "
			"0x%x:%d\n", bb->start, in);

		return (0);
	}

	/* double check decode again for register clobbering
	 */
	t_inst = ia32_decode_instruction (test_inst, &t_inst_s);
	assert (t_inst != NULL);
	df = ia32_df_set_from_instruction (t_inst, &df_s);
	if (df->def & dfb->df[in].in) {
		printf ("FATAL: instruction clobbers registers\n");

		return (0);
	}

	/* no instruction could be generated -> just try at the next
	 * instruction
	 */
	if (inst == NULL) {
		printf ("DEBUG: failed to generate instruction at "
			"0x%x:%d\n", bb->start, in);
		return (0);
	}

	ia32_sprint (t_inst, t_inst_str, sizeof (t_inst_str));
	fnote ("JUNK-INSERT: 0x%x-0x%x, point %d: %s\n",
		bb->start, bb->end, in, t_inst_str);

	ia->in_points_icount[in] += 1;
	bb->user->instr_insert = ia;

	return (1);
}


