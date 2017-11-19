/* ia32-trace.c - ia32 control flow tracer
 *
 * by scut
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <common.h>
#include <ia32-decode.h>
#include <ia32-debug.h>
#include <ia32-trace.h>
#include <ia32-function.h>
#include <ia32-dataflow.h>
#include <ia32-codeflow.h>


/*** static prototypes
 */

static int
ia32_br_dump_compar (const void *el1, const void *el2);

static ia32_bblock **
ia32_br_get_all_2 (ia32_bblock **arr, ia32_bblock *root, unsigned int *count);

/* ia32_graphviz_br_output_2 - helper function
 */
static void
ia32_graphviz_br_output_2 (FILE *fp, ia32_function *func, ia32_bblock *br);


/*** implementation
 */

/*** bblock routines
 */

ia32_bblock *
ia32_br_new (void)
{
	ia32_bblock *	new = calloc (1, sizeof (ia32_bblock));

	new->passed = 0;
	new->start = new->end = 0;
	new->user = xcalloc (1, sizeof (ia32_bb_user));
	new->user->dfb = new->user->instr_insert = NULL;

	new->last_ilen = new->last_unused = 0;

	new->endtype = BR_END_INVALID;
	new->endbr_count = 0;
	new->endbr = NULL;

	return (new);
}


void
ia32_br_dump (char *name, ia32_bblock *root)
{
	ia32_bblock **	all;
	unsigned int	all_count,
			n;

	all = ia32_br_get_all (root, &all_count);
	qsort (all, all_count, sizeof (all[0]), ia32_br_dump_compar);

	if (name != NULL)
		ia32_debug (IA32_DEBUG, "%s\n", name);

	for (n = 0 ; n < all_count ; ++n) {
		ia32_debug (IA32_DEBUG, " %s [0x%08x .. %8d .. 0x%08x]\n",
			all[n]->passed ? "   " : "###",
			all[n]->start, all[n]->end - all[n]->start,
			all[n]->end);
	}

	return;
}


static int
ia32_br_dump_compar (const void *el1, const void *el2)
{
	ia32_bblock *	br1 = ((ia32_bblock **) el1)[0];
	ia32_bblock *	br2 = ((ia32_bblock **) el2)[0];

	/* assert ((br1->end <= br2->start) || (br1->start >= br2->end)); */
	if (br1->start < br2->start)
		return (-1);
	if (br1->start > br2->start)
		return (1);

	/* assert (br1->start != br2->start); */
	return (0);
}


ia32_bblock *
ia32_br_get_unpassed (ia32_bblock **all, unsigned int all_count)
{
	ia32_bblock *	unpassed = NULL;
	unsigned int	n;


	for (n = 0 ; unpassed == NULL && n < all_count ; ++n)
		if (all[n]->passed == 0)
			unpassed = all[n];

	return (unpassed);
}


ia32_bblock *
ia32_br_split (ia32_bblock *br, unsigned int vaddr)
{
	ia32_bblock *	br_cont = ia32_br_new ();


	/* shallow copy all standard data, then adjust for the split
	 */
	memcpy (br_cont, br, sizeof (ia32_bblock));

	br->end = vaddr;
	br_cont->start = vaddr;

	br->endtype = BR_END_PASS;
	br->endbr_count = 1;
	br->endbr = malloc (sizeof (ia32_bblock *));
	br->endbr[0] = br_cont;
	/* printf ("old last_ilen = %d, squashed to zero\n", br->last_ilen); */
	br->last_ilen = 0;

	assert (br_cont->user == NULL || (br_cont->user->dfb == NULL &&
		br_cont->user->instr_insert == NULL));
	br_cont->user = xcalloc (1, sizeof (ia32_bb_user));

	return (br_cont);
}


ia32_bblock **
ia32_br_get_all (ia32_bblock *root, unsigned int *count)
{
	*count = 0;

	return (ia32_br_get_all_2 (NULL, root, count));
}


static ia32_bblock **
ia32_br_get_all_2 (ia32_bblock **arr, ia32_bblock *root, unsigned int *count)
{
	unsigned int	n;


	/* check if cur is already inside the array
	 */
	for (n = 0 ; n < *count ; ++n)
		if (arr[n] == root)
			return (arr);

	/* else add this bblock and recurse
	 */
	*count += 1;
	arr = xrealloc (arr, *count * sizeof (ia32_bblock *));
	arr[*count - 1] = root;

	for (n = 0 ; n < root->endbr_count ; ++n) {
		/* do not process external references
		 */
		if (root->endbr_external != NULL && root->endbr_external[n] != 0)
			continue;

		arr = ia32_br_get_all_2 (arr, root->endbr[n], count);
	}

	return (arr);
}


int
ia32_br_predecessor_is (ia32_bblock *from, ia32_bblock *to)
{
	unsigned int	bew;	/* branch end walker */

	for (bew = 0 ; bew < from->endbr_count ; ++bew) {
		if (from->endbr[bew] == to)
			return (1);
	}

	return (0);
}


ia32_bblock *
ia32_br_find (ia32_bblock *root, unsigned int vaddr,
	ia32_bblock **br_all, unsigned int br_count, int *br_split)
{
	ia32_bblock *	br_hit = NULL;
	unsigned int	n;


	if (br_all == NULL)
		br_all = ia32_br_get_all (root, &br_count);

	*br_split = 0;

	for (n = 0 ; br_hit == NULL && n < br_count ; ++n) {
		if (br_all[n]->start == vaddr) {
			br_hit = br_all[n];
		} else if (br_all[n]->passed &&
			ia32_trace_range (br_all[n]->start, br_all[n]->end,
				vaddr))
		{
			br_hit = ia32_br_split (br_all[n], vaddr);
			/* invalidate the bblock cache by announcing the split
			 */
			*br_split = 1;
		}
	}

	return (br_hit);
}


int
ia32_brl_find (ia32_bblock **list, unsigned int list_len, ia32_bblock *br)
{
	unsigned int	n;


	for (n = 0 ; n < list_len ; ++n)
		if (list[n] == br)
			return (n);

	return (-1);
}


int
ia32_trace_range (unsigned int start, unsigned int end, unsigned int ref)
{
	if (ref < start || ref >= end)
/*	if (ref < start || ref > end) */
		return (0);

	return (1);
}


int
ia32_trace_return_is (ia32_instruction *inst, unsigned char *inst_src)
{
	if (OD_TEST (inst->opc.used, OP_CONTROL) == 0)
		return (0);

	switch (inst_src[0]) {
	case (0xc2):
	case (0xc3):
	case (0xca):
	case (0xcb):
		return (1);
		break;
	default:
		return (0);
		break;
	}
}


unsigned int
ia32_trace_control (ia32_instruction *inst, unsigned char *inst_src,
	unsigned int cur, int *resume, int *ctrl_volatile)
{
	int		resume_dummy,
			vol_dummy;
	unsigned int	std_displ;


	if (resume == NULL)
		resume = &resume_dummy;
	if (ctrl_volatile == NULL)
		ctrl_volatile = &vol_dummy;

	*resume = 0;
	*ctrl_volatile = 0;

	std_displ = inst->length + inst->opc.displ_value + cur;

	if (OD_TEST (inst->opc.used, OP_CONTROL) == 0)
		return (0xffffffff);

	switch (inst_src[0]) {
		/* return */
	case (0xc2):
	case (0xc3):
	case (0xca):
	case (0xcb):
	case (0xf4):
		break;

		/* interrupts, usually syscalls. lets ignore them
		 */
	case (0xcd):
		*resume = 1;
		*ctrl_volatile = 1;
		break;

		/* call with modr/rm, this cannot be predicted statically, so
		 * lets ignore it
		 */
	case (0xff):
		if ((inst_src[1] & 0x38) == 0x10) {
			*resume = 1;
			*ctrl_volatile = 1;
		} else if ((inst_src[1] & 0x38) == 0x20 ||
			(inst_src[1] & 0x38) == 0x28)
		{
			*resume = 0;
			*ctrl_volatile = 1;
		} else {
			ia32_debug (IA32_FATAL, "FATAL: "
				"(ia32_trace_control) invalid 0xff "
				"control opcode\n");

			exit (EXIT_FAILURE);
		}
		return (0);
		break;

		/* call with displacement */
	case (0xe8):
		*resume = 1;
		return (std_displ);
		break;
		/* jcc with displacement */
	case (0x70):
	case (0x71):
	case (0x72):
	case (0x73):
	case (0x74):
	case (0x75):
	case (0x76):
	case (0x77):
	case (0x78):
	case (0x79):
	case (0x7a):
	case (0x7b):
	case (0x7c):
	case (0x7d):
	case (0x7e):
	case (0x7f):
		return (std_displ);
		break;
		/* jcc with full displacement */
	case (0x0f):
		if ((inst_src[1] & 0xf0) == 0x80)
			return (std_displ);
		break;
		/* jcxz */
	case (0xe3):
		return (std_displ);
		break;
		/* jump short and direct */
	case (0xeb):
	case (0xe9):
		return (std_displ);
		break;
		/* jmp direct intersegment */
	case (0xea):
		return (inst->opc.imm_value);
		break;
		/* loop* */
	case (0xe0):
	case (0xe1):
	case (0xe2):
		return (std_displ);
		break;
	default:
		ia32_debug (IA32_FATAL, "FATAL: (ia32_trace_control) "
			"invalid control flow instruction\n");

		exit (EXIT_FAILURE);
		break;
	}

	return (0xffffffff);
}


unsigned int
ia32_br_instruction_count (ia32_bblock *bb)
{
	ia32_instruction *	inst,
				inst_s;
	unsigned int		count = 0,
				mem_rel;

	for (mem_rel = 0 ; mem_rel < (bb->end - bb->start) ;
		mem_rel += inst->length)
	{
		assert (bb->mem != NULL);
		inst = ia32_decode_instruction (&bb->mem[mem_rel], &inst_s);
		assert (inst != NULL);

		count += 1;
	}

	return (count);
}


void
ia32_vcg_br_output (FILE *fp, ia32_bblock *root, void *func_2)
{
	ia32_bblock **	br_all;
	unsigned int	br_count,
			bn,	/* walker */
			i;	/* inner walker */
	ia32_bblock *	brw;
	ia32_function *	func = (ia32_function *) func_2;


	fprintf (fp, "graph: { title: \"control flow graph of '%s'\"\n",
		func->name == NULL ? "__unknown" : func->name);
	fprintf (fp, "\tlayoutalgorithm: minbackward\n"
		"\tdisplay_edge_labels: yes\n"
		"\tmanhatten_edges: yes\n"
		"\tlayout_nearfactor: 0\n"
		"\txspace: 25\n"
		"\n"
		"\tnode.color: white\n"
		"\tnode.textcolor: black\n"
		"\tedge.color: black\n"
		"\tedge.arrowsize: 15\n"
		"\tedge.thickness: 4\n"
		"\n");

	br_all = ia32_br_get_all (root, &br_count);

	ia32_vcg_loop_output_nested (fp, func, br_all, br_count, NULL, 0);
#if 0
	for (bn = 0 ; bn < br_count ; ++bn)
		ia32_vcg_br_output_node (fp, func, br_all[bn]);
#endif

	fprintf (fp, "\n");

	for (bn = 0 ; bn < br_count ; ++bn) {
		unsigned int	bwn;

		brw = br_all[bn];

		for (i = 0 ; i < brw->endbr_count ; ++i) {
			if (brw->endtype == BR_END_SWITCH) {
				for (bwn = 0 ; bwn < i ; ++bwn) {
					if (brw->endbr[i] == brw->endbr[bwn])
						break;
				}
				/* get rid of dupes
				 */
				if (bwn < i)
					continue;
			}

			fprintf (fp, "edge: { sourcename: \"0x%08x\" "
				"targetname: \"0x%08x\"",
				brw->start, brw->endbr[i]->start);

			if (brw->endtype == BR_END_IF) {
				fprintf (fp, "label: \"%s\" color: %s }\n",
					i == 0 ? "false" : "true",
					i == 0 ? "darkred" : "darkgreen");
			} else if (brw->endtype == BR_END_PASS) {
				fprintf (fp, "label: \"pass\" }\n");
			} else
				fprintf (fp, "}\n");
		}
	}

	fprintf (fp, "}\n");

	free (br_all);
}


void
ia32_vcg_br_output_node (FILE *fp, void *func_v, ia32_bblock *br,
	const char *attributes)
{
	ia32_df_bblock *	dfb;
	ia32_function *		func = (ia32_function *) func_v;
	ia32_instruction *	inst,	/* helper pointer for inst_s */
				inst_s;	/* instruction structure */
	unsigned int		vaddr;	/* current virtual address */
	unsigned char *		cur;	/* memory position of vaddr */
	char			inst_str[128];
	unsigned int		ilen = 0,
				i_count = 0,
				defn;
	unsigned int *		live_mask[4];


	fprintf (fp, "node: { title: \"0x%08x\"\n", br->start);
	if (attributes != NULL)
		fprintf (fp, "\t%s\n", attributes);

	dfb = (ia32_df_bblock *) br->user->dfb;
	if (dfb != NULL) {
		fprintf (fp, "\tlabel: \"\\fu   address\\fn  "
			"\\fuinstruction                                        \\fn "
			"\\fudef     \\fn \\fuuse     \\fn \\fuin      \\fn "
			"\\fuout     \\fn\n");
	} else {
		fprintf (fp, "\tlabel: \"\\fu   address\\fn  "
			"\\fuinstruction                                        \\fn\n");
	}


	for (vaddr = br->start ; vaddr < br->end ; vaddr += ilen) {
		char *	inst_2nd;

		cur = &func->mem[vaddr - func->start];
		inst = ia32_decode_instruction (cur, &inst_s);

		if (inst == NULL)
			break;

		ilen = inst->length;

		ia32_sprint (inst, inst_str, sizeof (inst_str));

		/* find second part of instruction string
		 */
		inst_2nd = inst_str;
		while (inst_2nd[0] != '\0' && inst_2nd[0] != '\t')
			++inst_2nd;
		if (inst_2nd[0] == '\t') {
			inst_2nd[0] = '\0';
			inst_2nd = &inst_2nd[1];
		} else
			inst_2nd = NULL;

		fprintf (fp, "0x%08x  %-10s %-40s", vaddr, inst_str,
			inst_2nd == NULL ? "" : inst_2nd);

		/* when no dataflow output is available, skip printing.
		 */
		if (dfb == NULL) {
			fprintf (fp, "\n");
			continue;
		}

		live_mask[0] = &dfb->df[i_count].def;
		live_mask[1] = &dfb->df[i_count].use;
		live_mask[2] = &dfb->df[i_count].in;
		live_mask[3] = &dfb->df[i_count].out;

		for (defn = 0 ; defn < 4 ; ++defn) {
			char	buf[128];

			ia32_df_set_snprint_single (*live_mask[defn], buf);
			fprintf (fp, " %s", buf);
		}
		fprintf (fp, "\n");

		i_count += 1;
	}

	fprintf (fp, "\" }\n");
}


void
ia32_graphviz_br_output (FILE *fp, ia32_bblock *root, void *func_2)
{
	ia32_function *	func = (ia32_function *) func_2;
	ia32_bblock **	br_all;
	unsigned int	br_count,
			n,
			i;
	ia32_bblock *	brw;	/* working bblock */


	fprintf (fp, "digraph %s {\n",
		(func->name != NULL) ? func->name : "__unknown");
#ifdef	DIN_A4
	fprintf (fp, "\tsize = \"8.2,11.0\"\n");
#endif

	fprintf (fp, "\tnode [\n");
	fprintf (fp, "\t\tstyle = filled\n");
	fprintf (fp, "\t\tshape = \"record\"\n");
	fprintf (fp, "\t\tfillcolor = \"lightskyblue\"\n");
	fprintf (fp, "\t];\n");

	br_all = ia32_br_get_all (root, &br_count);
	for (n = 0 ; n < br_count ; ++n) {
		brw = br_all[n];

		fprintf (fp, "\t\"0x%08x\" [\n", brw->start);
		fprintf (fp, "\t\tlabel = \"{ <fi> 0x%08x | { ",
			brw->start);

		ia32_graphviz_br_output_2 (fp, func, brw);

		fprintf (fp, "} | ");

#ifdef	XREF_PRINT
		for (i = 0 ; i < func->func_xref_count ; ++i)
			fprintf (fp, "xref: 0x%08x to 0x%08x\\l",
				func->func_xref[i]->from,
				func->func_xref[i]->to);
		fprintf (fp, "| ");
#endif

		fprintf (fp, "<fo> 0x%08x }\"\n", brw->end);

		/* find bblockes that contain external function references,
		 * and color those differently. color call bblockes red before.
		 */
		if (brw->endtype == BR_END_CALL && func->livereg_available == 0) {
			fprintf (fp, "\t\tfillcolor = \"red\"\n");
		} else if (brw->endtype == BR_END_UNPREDICT) {
			fprintf (fp, "\t\tfillcolor = \"orange\"\n");
		} else for (i = 0 ; i < func->func_xref_count ; ++i) {
			if (ia32_trace_range (brw->start, brw->end,
				func->func_xref[i]->from))
			{
				if (func->func_xref[i]->to == func->start)
					fprintf (fp, "\t\tfillcolor = \"limegreen\"\n");
				else
					fprintf (fp, "\t\tfillcolor = \"mediumturquoise\"\n");
			}
		}

		fprintf (fp, "\t];\n");
	}

	for (n = 0 ; n < br_count ; ++n) {
		unsigned int	bwn;

		brw = br_all[n];

		for (i = 0 ; i < brw->endbr_count ; ++i) {
			if (brw->endtype == BR_END_SWITCH) {
				for (bwn = 0 ; bwn < i ; ++bwn) {
					if (brw->endbr[i] == brw->endbr[bwn])
						break;
				}
				/* get rid of dupes
				 */
				if (bwn < i)
					continue;
			}

			fprintf (fp, "\t\"0x%08x\":fo -> \"0x%08x\":fi [concentrate=true]",
				brw->start, brw->endbr[i]->start);

			if (brw->endtype == BR_END_PASS)
				fprintf (fp, " [color=\"seagreen\"]");
			else if (brw->endtype == BR_END_IF)
				fprintf (fp, " [color=\"%s\"]",
					i == 0 ? "seagreen" : "maroon3");

			fprintf (fp, ";\n");
		}
	}

	fprintf (fp, "}\n");

	free (br_all);

	return;
}


static void
ia32_graphviz_br_output_2 (FILE *fp, ia32_function *func, ia32_bblock *br)
{
	ia32_instruction *	inst,	/* helper pointer for inst_s */
				inst_s;	/* instruction structure */
	unsigned int		vaddr;	/* current virtual address */
	unsigned char *		cur;	/* memory position of vaddr */
	unsigned int		ilen = 0,
				n,
				defn;
	char			inst_str[128];
	ia32_df_bblock *	dfb;
	static const char *	live_str[] = { "DEF", "USE", "IN", "OUT", NULL };
	unsigned int *		live_mask[4];


	/* print one extra line for the DEF/USE/IN/OUT descriptions */
	if (func->livereg_available)
		fprintf (fp, "\\l");

	for (vaddr = br->start ; vaddr < br->end ; vaddr += ilen) {
		cur = &func->mem[vaddr - func->start];
		inst = ia32_decode_instruction (cur, &inst_s);

		if (inst == NULL)
			break;
		
		fprintf (fp, "\xff""0x%08x\\l", vaddr);
		ilen = inst->length;
	}

	fprintf (fp, "|\xff");
	if (func->livereg_available)
		fprintf (fp, "\\l\xff");

	for (vaddr = br->start ; vaddr < br->end ; vaddr += ilen) {
		cur = &func->mem[vaddr - func->start];
		inst = ia32_decode_instruction (cur, &inst_s);
		
		assert (inst != NULL);

		ia32_sprint (inst, inst_str, sizeof (inst_str));
		fprintf (fp, "%s\\l ", inst_str);
		ilen = inst->length;
	}

	if (func->livereg_available == 0)
		return;

	dfb = (ia32_df_bblock *) br->user->dfb;
	if (dfb == NULL)
		return;

	for (defn = 0 ; defn < 4 ; ++defn) {
		fprintf (fp, "|\xff\\l\xff");

		fprintf (fp, "%s\\l\xff", live_str[defn]);

		for (n = 0 ; n < dfb->df_count ; ++n) {
			char	buf[128];

			live_mask[0] = &dfb->df[n].def;
			live_mask[1] = &dfb->df[n].use;
			live_mask[2] = &dfb->df[n].in;
			live_mask[3] = &dfb->df[n].out;

			ia32_df_set_snprint_single (*live_mask[defn], buf);
			fprintf (fp, "%s\\l\xff", buf);
		}
	}

	return;
}



#ifdef	TESTING

int
main (int argc, char *argv[])
{
	char *		fn;
	unsigned int	amount;
	FILE *		fp;
	unsigned char	buf[4096];
	ia32_function *	func;


	printf ("ia32 control flow tracer "IA32_TRACE_VERSION"\n");

	if (argc < 2) {
		fprintf (stderr, "usage: %s file.bin [file.dot]\n\n", argv[0]);

		exit (EXIT_FAILURE);
	}

	fp = fopen (argv[1], "rb");
	if (fp == NULL) {
		perror ("fopen");

		exit (EXIT_FAILURE);
	}


	for (fn = argv[1] ; *fn != '\0' && *fn != '.' ; ++fn)
		;
	if (*fn == '.')
		*fn = '\0';

	amount = fread (buf, 1, sizeof (buf), fp);
	fclose (fp);

	func = ia32_func_new ();
	func->name = argv[1];
	func->mem = buf;
	func->start = 0x01000000;
	func->end = func->start + amount;
	func->br_root = NULL;
	func->func_xref_count = 0;
	func->func_xref = NULL;

	func->br_root = ia32_func_breakup (func, NULL, NULL);

	fp = fopen (argc >= 3 ? argv[2] : "test.dot", "w");
	if (fp == NULL) {
		perror ("fopen");

		exit (EXIT_FAILURE);
	}

	ia32_graphviz_br_output (fp, func->br_root, func);
	fclose (fp);

	exit (EXIT_SUCCESS);
}

#endif


