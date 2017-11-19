/* ia32-codeflow.c - ia32 codeflow analysis
 *
 * by scut
 *
 * this is an additional module, implementing codeflow analysis methods. for
 * now, only dominator tree analysis and loop-detection is done.
 */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <ia32-trace.h>
#include <ia32-codeflow.h>
#include <ia32-function.h>

#include <common.h>


/*** static prototypes */

/* ia32_domtree_set_cmp
 *
 * compare two sets `set1' and `set2' if they contain exactly the same basic
 * blocks. the sets are `set1_count' and `set2_count' blocks long,
 * respectivly.
 *
 * return zero if they are equal
 * return non-zero if they differ
 */

static int
ia32_domtree_set_cmp (ia32_bblock **set1, unsigned int set1_count,
	ia32_bblock **set2, unsigned int set2_count);


/* ia32_domtree_set_subset_is
 *
 * check if `set1' is completely contained within `set2'.
 *
 * return zero if it is not contained (contains blocks outside of `set2')
 * return non-zero if it is completely within `set2'
 */

static int
ia32_domtree_set_subset_is (ia32_bblock **set1, unsigned int set1_count,
	ia32_bblock **set2, unsigned int set2_count);


/* ia32_domtree_set_cap
 *
 * modify set at *`dset', which is *`dset_count' items long. build the cap set
 * of it and the set `dom', which is `dom_count' items long.
 *
 * return zero if *`dset' remains unchanged
 * return non-zero in case it changed
 */

static int
ia32_domtree_set_cap (ia32_bblock ***dset, unsigned int *dset_count,
	ia32_bblock **dom, unsigned int dom_count);


/* ia32_domtree_set_cup
 *
 * build the union of *`dset' and `set2' into `dset'. `dset' and `set2' are
 * `dset_count' and `set2_count' items long, respectivly.
 *
 * return number of new elements merged into *`dset'.
 */

static int
ia32_domtree_set_cup (ia32_bblock ***dset, unsigned int *dset_count,
	ia32_bblock **set2, unsigned int set2_count);


/* ia32_loop_fix_head_levels
 *
 * fix the "innermost loop order" in case multiple loops share the same basic
 * block. rather obscure ;)
 *
 * return in any case
 */

static void
ia32_loop_fix_head_levels (ia32_loop *loop, ia32_bblock *bb);


/* TODO: remove */

static void
ia32_loop_debug_printnested (ia32_bblock **all, unsigned int all_count,
	ia32_loop *loop);


/*** IMPLEMENTATION */

/* dominator tree */

void
ia32_domtree_build (ia32_bblock *root)
{
	ia32_bblock **	all;
	unsigned int	all_count;

	/* current dominator set */
	unsigned int	dcur_count;
	ia32_bblock **	dcur;

	int		bn,		/* basic block index */
			bsn,		/* basic block subindex */
			first_union,
			changed;


	all = ia32_br_get_all (root, &all_count);

	/* free all previous dominator information
	 */
	for (bn = 0 ; bn < all_count ; ++bn) {
		if (all[bn]->dom != NULL) {
			free (all[bn]->dom);
			all[bn]->dom = NULL;
		}
		all[bn]->dom_count = 0;
	}

	/* (1) */
	root->dom_count = 1;
	root->dom = xcalloc (1, sizeof (ia32_bblock *));
	root->dom[0] = root;

	/* (2) */
	for (bn = 0 ; bn < all_count ; ++bn) {
		if (all[bn] == root)
			continue;

		all[bn]->dom_count = all_count;
		all[bn]->dom = xcalloc (all_count, sizeof (ia32_bblock *));
		memcpy (all[bn]->dom, all, all_count * sizeof (ia32_bblock *));

		/* swap blocks, so that the first is always a self reference
		 */
		for (bsn = 0 ; bsn < all[bn]->dom_count ; ++bsn) {
			ia32_bblock *	bb;

			if (all[bn]->dom[bsn] != all[bn])
				continue;

			bb = all[bn]->dom[bsn];
			all[bn]->dom[bsn] = all[bn]->dom[0];
			all[bn]->dom[0] = bb;

			break;
		}
	}

	/* (3) */
	do {
		changed = 0;

		/* (4) */
		for (bn = 0 ; bn < all_count ; ++bn) {
			if (all[bn] == root)
				continue;

			/* (5), D(n) = { n } .. */
			dcur_count = 1;
			dcur = xcalloc (1, sizeof (ia32_bblock *));
			dcur[0] = all[bn];

			first_union = 1;

			for (bsn = 0 ; bsn < all_count ; ++bsn) {
				ia32_bblock *	cur;

				cur = all[bsn];

				if (ia32_br_predecessor_is (cur, /* of */ all[bn]) == 0)
					continue;

				/* there are two possible cases when mergin a
				 * set:
				 *   1. its the first set, copy it completely
				 */
				if (first_union) {
					dcur_count += cur->dom_count;
					dcur = xrealloc (dcur, dcur_count *
						sizeof (ia32_bblock *));
					memcpy (&dcur[1], cur->dom,
						cur->dom_count *
						sizeof (ia32_bblock *));

					first_union = 0;
					continue;
				}

				/*   2. there are already other sets, so build
				 *      the intersection
				 */
				ia32_domtree_set_cap (&dcur, &dcur_count,
					cur->dom, cur->dom_count);
			}

			/* check if set differs from what is already there
			 */
			if (ia32_domtree_set_cmp (dcur, dcur_count,
				all[bn]->dom, all[bn]->dom_count))
				changed = 1;

			if (all[bn]->dom != NULL)
				free (all[bn]->dom);

			all[bn]->dom_count = dcur_count;
			all[bn]->dom = dcur;
		}
	} while (changed);

	free (all);
}


static int
ia32_domtree_set_cmp (ia32_bblock **set1, unsigned int set1_count,
	ia32_bblock **set2, unsigned int set2_count)
{
	if (ia32_domtree_set_subset_is (set1, set1_count, set2, set2_count) &&
		ia32_domtree_set_subset_is (set2, set2_count, set1, set1_count))
		return (0);

	return (1);
}


static int
ia32_domtree_set_subset_is (ia32_bblock **set1, unsigned int set1_count,
	ia32_bblock **set2, unsigned int set2_count)
{
	unsigned int	s1n,
			s2n;
	int		is_in_set2;

	for (s1n = 0 ; s1n < set1_count ; ++s1n) {
		is_in_set2 = 0;

		for (s2n = 0 ; s2n < set2_count ; ++s2n) {
			if (set1[s1n] == set2[s2n]) {
				is_in_set2 = 1;
				break;
			}
		}

		if (is_in_set2 == 0)
			return (0);
	}

	return (1);
}


static int
ia32_domtree_set_cup (ia32_bblock ***dset, unsigned int *dset_count,
	ia32_bblock **set2, unsigned int set2_count)
{
	ia32_bblock **	set1 = *dset;
	unsigned int	set1_count = *dset_count;
	unsigned int	bn,
			sn,
			new_count = 0;
	int *		set2_new;

	set2_new = xcalloc (set2_count, sizeof (int));

	for (bn = 0 ; bn < set2_count ; ++bn) {
		for (sn = 0 ; sn < set1_count ; ++sn)
			if (set1[sn] == set2[bn])
				break;

		if (sn < set1_count)
			continue;

		new_count += 1;
		set2_new[bn] = 1;
	}

	set1 = xrealloc (set1, (set1_count + new_count) * sizeof (ia32_bblock *));
	sn = 0;
	for (bn = 0 ; bn < set2_count ; ++bn) {
		if (set2_new[bn] == 0)
			continue;

		set1[set1_count + sn] = set2[bn];
		sn += 1;
	}
	*dset = set1;
	*dset_count = set1_count + new_count;

	free (set2_new);

	return (new_count);
}


static int
ia32_domtree_set_cap (ia32_bblock ***dset, unsigned int *dset_count,
	ia32_bblock **dom, unsigned int dom_count)
{
	ia32_bblock **	set = *dset;
	unsigned int	set_count = *dset_count,
			sidx,
			didx;
	int		seen,
			changed = 0;

	for (sidx = 1 ; sidx < set_count ; ++sidx) {
		seen = 0;
		for (didx = 0 ; didx < dom_count ; ++didx) {
			if (set[sidx] == dom[didx])
				seen += 1;
		}

		assert (seen == 0 || seen == 1);
		if (seen == 1)
			continue;

		set[sidx] = NULL;
	}

	/* compaction of the current dominator set
	 */
	for (sidx = 1, didx = 1 ; sidx < set_count ; ++sidx) {
		if (set[sidx] == NULL)
			continue;

		if (set[didx] != set[sidx])
			changed = 1;

		set[didx] = set[sidx];
		didx += 1;
	}

	set_count = didx;
	set = xrealloc (set, set_count * sizeof (ia32_bblock *));

	*dset_count = set_count;
	*dset = set;

	return (changed);
}


int
ia32_dom_dominates (ia32_bblock *b1, ia32_bblock *b2)
{
	unsigned int	dn;

	assert (b1->dom_count >= 1 && b2->dom_count >= 1);
	for (dn = 0 ; dn < b2->dom_count ; ++dn) {
		if (b2->dom[dn] == b1)
			return (1);
	}

	return (0);
}


void
ia32_vcg_domtree_output (FILE *fp, ia32_bblock *root)
{
	ia32_bblock **	all;
	unsigned int	all_count,
			bn,
			sbn;


	assert (root->dom_count == 1);

	all = ia32_br_get_all (root, &all_count);

	fprintf (fp, "graph: { title: \"dominator tree graph\"\n");
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

	/* print all nodes of the dominator tree
	 */
	for (bn = 0 ; bn < all_count ; ++bn) {
		fprintf (fp, "node: { title: \"0x%08x\"\n", all[bn]->start);
		fprintf (fp, "\tlabel: \"0x%08x-0x%08x\"\n",
			all[bn]->start, all[bn]->end);
		fprintf (fp, "}\n");
	}

	/* now the more tricky part, the edges. tricky, as we only store the
	 * dominators, no real tree information. we use a simple structure of
	 * the dominator tree: its level. just pick the dominator that is only
	 * one level above (dom->dom_count = this->dom_count - 1) and only
	 * output its edge to us.
	 */
	for (bn = 0 ; bn < all_count ; ++bn) {
		/* no edges for the first level :) */
		if (all[bn]->dom_count == 1)
			continue;

		for (sbn = 1 ; sbn < all[bn]->dom_count ; ++sbn) {
			if ((all[bn]->dom[sbn]->dom_count + 1) ==
				all[bn]->dom_count)
				break;
		}

		fprintf (fp, "edge: { sourcename: \"0x%08x\" "
			"targetname: \"0x%08x\" }\n",
			all[bn]->dom[sbn]->start, all[bn]->start);
	}

	fprintf (fp, "}\n");
}


/* loop detection */


void
ia32_loop_find (ia32_bblock *root, int nest_heuristic)
{
	ia32_bblock **	all;
	unsigned int	all_count,
			bn,		/* basic block index */
			en;		/* edge index */

	/* dominator analysis done? */
	assert (root->dom_count == 1);

	all = ia32_br_get_all (root, &all_count);
	for (bn = 0 ; bn < all_count ; ++bn) {
		for (en = 0 ; en < all[bn]->endbr_count ; ++en) {
			/* do not process inter-function references
			 */
			if (all[bn]->endbr_external != NULL &&
				all[bn]->endbr_external[en])
				continue;

			if (ia32_dom_dominates (all[bn]->endbr[en],
				all[bn]) == 0)
				continue;

			printf ("backedge: 0x%08x -> 0x%08x\n",
				all[bn]->start, all[bn]->endbr[en]->start);

			ia32_loop_find_single (all, all_count, all[bn],
				all[bn]->endbr[en], nest_heuristic);
		}
	}

#if 0
	/* TODO: remove this debug output */
	for (bn = 0 ; bn < all_count ; ++bn) {
		printf ("0x%08x-0x%08x  loop: 0x%08x   outer: 0x%08x\n",
			all[bn]->start, all[bn]->end,
			(unsigned int) all[bn]->innermost,
			((ia32_loop *) all[bn]->innermost) == NULL ?
			0x0 : (unsigned int) (((ia32_loop *)
				all[bn]->innermost)->outer));
	}

	printf ("\nbb nest: ");
	ia32_loop_debug_printnested (all, all_count, NULL);
	printf ("\n\n");
#endif

	free (all);
}


static void
ia32_loop_debug_printnested (ia32_bblock **all, unsigned int all_count,
	ia32_loop *loop)
{
	unsigned int	bn,
			sn,
			seen_sp = 0;
	ia32_loop *	seen_stack[512];
	ia32_loop *	bb_loop;
	int		is_done;


	memset (seen_stack, 0x0, sizeof (seen_stack));

	/* print all top-level nodes of this loop
	 */
	for (bn = 0 ; bn < all_count ; ++bn) {
		bb_loop = (ia32_loop *) all[bn]->innermost;

		if (bb_loop == loop)
			printf ("0x%x, ", all[bn]->start);
	}

	/* recurse to direct subloops of this loop
	 */
	for (bn = 0 ; bn < all_count ; ++bn) {
		bb_loop = (ia32_loop *) all[bn]->innermost;

		if (bb_loop == NULL)
			continue;

		if (bb_loop->outer != loop)
			continue;

		is_done = 0;
		for (sn = 0 ; sn < seen_sp ; ++sn) {
			if (seen_stack[sn] == bb_loop) {
				is_done = 1;
				break;
			}
		}
		if (is_done)
			continue;

		seen_stack[seen_sp++] = bb_loop;
		assert (seen_sp < 512);

		printf ("{ ");
		ia32_loop_debug_printnested (all, all_count,
			bb_loop);
		printf ("}, ");
	}
}


void
ia32_loop_find_single (ia32_bblock **all, unsigned int all_count,
	ia32_bblock *bb_n, ia32_bblock *bb_d, int nest_heuristic)
{
	unsigned int	bn,		/* basic block index */
			bb_sptr = 0;
	ia32_bblock *	bb_stack[1024];
	ia32_loop *	loop = NULL;
	ia32_bblock *	cur;
	ia32_loop *	loop_old;


	if (nest_heuristic == IA32_LOOP_DRAGON) {
		loop_old = (ia32_loop *) bb_d->innermost;
		if (loop_old != NULL) {
			if (loop_old->head == bb_d)
				loop = loop_old;
		} else {
			loop = ia32_loop_new ();
			loop->head = bb_d;
		}
	} else if (nest_heuristic == IA32_LOOP_NEST) {
		loop = ia32_loop_new ();
		loop->head = bb_d;
	}

	memset (bb_stack, 0x0, sizeof (bb_stack));

	ia32_loop_insert (loop, bb_d);
	if (ia32_loop_insert (loop, bb_n))
		bb_stack[bb_sptr++] = bb_n;

	/* special case: bb_d == bb_n, i.e. a loop with only one basic block
	 * note, we do not have to treat it any special, as if bb_d == bb_n,
	 * then there is nothing on the stack.
	 */
	/* if (bb_d == bb_n)
		return; */

	while (bb_sptr > 0) {
		bb_sptr -= 1;
		cur = bb_stack[bb_sptr];

		for (bn = 0 ; bn < all_count ; ++bn) {
			if (ia32_br_predecessor_is (all[bn], cur) == 0)
				continue;

			assert (bb_sptr < (1024 - 1));
			if (ia32_loop_insert (loop, all[bn]))
				bb_stack[bb_sptr++] = all[bn];
		}
	}

	/* decide which loop the head basic block belongs to, in case multiple
	 * loops share it.
	 */
	if (loop->head_shared)
		ia32_loop_fix_head_levels (loop, loop->head);
}


static void
ia32_loop_fix_head_levels (ia32_loop *loop, ia32_bblock *bb)
{
	ia32_loop *	bb_loop;


	bb_loop = (ia32_loop *) bb->innermost;
	assert (bb_loop != NULL);

	if (bb_loop->nodes_count > loop->nodes_count) {
		loop->outer = bb_loop;
		bb->innermost = loop;

		return;
	}

	do {
		if (bb_loop->outer == NULL) {
			bb_loop->outer = loop;
			loop->outer = NULL;

			return;
		} else if (bb_loop->outer->nodes_count >
			loop->nodes_count)
		{
			loop->outer = bb_loop->outer;
			bb_loop->outer = loop;

			return;
		}
		bb_loop = bb_loop->outer;
	} while (1);
}


int
ia32_loop_insert (ia32_loop *loop, ia32_bblock *bb)
{
	unsigned int	nn;

	printf ("ia32_loop_insert (0x%08x, 0x%08x (0x%x))\n",
		(unsigned int) loop, (unsigned int) bb, bb->start);

	for (nn = 0 ; nn < loop->nodes_count ; ++nn) {
		if (loop->nodes[nn] == bb)
			return (0);
	}

	loop->nodes = xrealloc (loop->nodes, (loop->nodes_count + 1) *
		sizeof (ia32_bblock *));
	loop->nodes[loop->nodes_count] = bb;
	loop->nodes_count += 1;

	printf ("   insert: 0x%08x (@ 0x%x) into 0x%08x (cur innermost: 0x%08x)\n",
		(unsigned int) bb, bb->start, (unsigned int) loop,
		(unsigned int) bb->innermost);

	/* update the loop information on basic block level:
	 * - if there is no innermost loop yet, put it there.
	 * - if there is already an innermost loop, check if we are more
	 *   "inner", by checking if the loop head block is enclosed in the
	 *   current innermost loop. if it is, our entire loop is contained
	 *   within the current innermost loop, hence insert ourself there.
	 */
	if (bb->innermost == NULL) {
		bb->innermost = loop;
	} else if (ia32_loop_is_in ((ia32_loop *) bb->innermost, loop->head)) {
		ia32_loop *	bb_loop;

		bb_loop = (ia32_loop *) bb->innermost;

		/* special case: shared head. dragon book advises to treat
		 * both loops as one, as any further analysis is very
		 * complicated (pp. 605, section 10.4). we do not treat them
		 * as one, because compiler generated loops are better visible
		 * when showing every possible loop (i.e. it is easier to
		 * group wrongly detected loops to one as one detected loop to
		 * multiple real loops).
		 */
		if (bb_loop->head == loop->head) {
			printf ("### LOOP: HEAD-SHARING at 0x%x\n",
				loop->head->start);

			loop->head_shared = 1;
			return (1);
		}

		loop->outer = (ia32_loop *) bb->innermost;
		bb->innermost = loop;
	} else
		ia32_loop_fix_head_levels (loop, bb);

	return (1);
}


int
ia32_loop_is_in (ia32_loop *loop, ia32_bblock *bb)
{
	unsigned int	bn;

	for (bn = 0 ; bn < loop->nodes_count ; ++bn) {
		if (loop->nodes[bn] == bb)
			return (1);
	}

	return (0);
}


ia32_loop *
ia32_loop_new (void)
{
	return ((ia32_loop *) xcalloc (1, sizeof (ia32_loop)));
}


void
ia32_loop_free (ia32_loop *loop)
{
	if (loop->nodes != NULL)
		free (loop->nodes);

	free (loop);
}


void
ia32_vcg_loop_output_nested (FILE *fp, ia32_function *func,
	ia32_bblock **all, unsigned int all_count, void *loop_v, int level)
{
	unsigned int	bn,	/* basic block walker */
			sn,	/* stack index walker */
			ln,	/* level walker */
			seen_sp = 0;	/* stack pointer */
	ia32_loop *	seen_stack[512];
	ia32_loop *	bb_loop;
	ia32_loop *	loop = (ia32_loop *) loop_v;
	int		is_done;
	char		attr_str[64];
	const char *	colors[] = { "lightgreen", "lightyellow", "lightblue",
		"lightred", "grey", "green", "yellow" };


	memset (seen_stack, 0x0, sizeof (seen_stack));

	/* print all top-level nodes of this loop
	 */
	for (bn = 0 ; bn < all_count ; ++bn) {
		bb_loop = (ia32_loop *) all[bn]->innermost;

		if (bb_loop == loop) {
			if (loop != NULL && loop->head == all[bn]) {
				snprintf (attr_str, sizeof (attr_str) - 1,
					"color: aquamarine vertical_order: %d",
					level + bn);
				attr_str[sizeof (attr_str) - 1] = '\0';

				ia32_vcg_br_output_node (fp, func, all[bn],
					attr_str);
			} else {
				ia32_vcg_br_output_node (fp, func, all[bn], NULL);
			}
		}
	}

	/* recurse to direct subloops of this loop
	 */
	for (bn = 0 ; bn < all_count ; ++bn) {
		bb_loop = (ia32_loop *) all[bn]->innermost;

		if (bb_loop == NULL)
			continue;

		if (bb_loop->outer != loop)
			continue;

		is_done = 0;
		for (sn = 0 ; sn < seen_sp ; ++sn) {
			if (seen_stack[sn] == bb_loop) {
				is_done = 1;
				break;
			}
		}
		if (is_done)
			continue;

		seen_stack[seen_sp++] = bb_loop;
		assert (seen_sp < 512);

		for (ln = 0 ; ln <= level ; ++ln)
			fprintf (fp, "\t");

		fprintf (fp, "graph: { title: \"loop 0x%08x\" label: \"level %d\""
			"status: clustered color: ", (unsigned int) bb_loop, level);
			/*"status: boxed color: ", (unsigned int) bb_loop, level);*/
		assert (level <= 6);
		fprintf (fp, "%s\n", colors[level]);

		ia32_vcg_loop_output_nested (fp, func, all, all_count,
			(void *) bb_loop, level + 1);

		fprintf (fp, "}\n");
	}
}



