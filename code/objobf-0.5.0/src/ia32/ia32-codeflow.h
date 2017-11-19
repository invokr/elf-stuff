/* ia32-codeflow.c - ia32 codeflow analysis
 * include file
 *
 * by scut
 */

#ifndef	IA32_CODEFLOW_H
#define	IA32_CODEFLOW_H

#include <ia32-trace.h>

/* ia32_loop, structure that defines a loop within a functions control flow
 * graph.
 */

typedef struct ia32_loop {
	/* NULL in case its a top level loop of the function,
	 * non-NULL in case there is an enclosing loop around this one,
	 *   pointing to the ia32_loop of it.
	 */
	struct ia32_loop *	outer;

	/* in case two or more loops share their head basic blocks, we can
	 * only decide afterwards, which is the innermost loop refering to the
	 * head basic block. this is just a flag to ease this processing.
	 */
	int		head_shared;

	/* `head' is the loop header basic block. `nodes_count' gives the
	 * number of basic blocks in the entire loop, which are listed in
	 * `nodes' (also contains head).
	 */
	ia32_bblock *	head;
	unsigned int	nodes_count;
	ia32_bblock **	nodes;
} ia32_loop;


/*** dominator tree functions */

/* ia32_domtree_build
 *
 * build a dominator tree within the basic block tree starting at `root'. do
 * this using algorithm 10.16 of the dragon book.
 *
 * return in any case
 */

void
ia32_domtree_build (ia32_bblock *root);


/* ia32_dom_dominates
 *
 * return non-zero if "b1 dom b2", otherwise return zero
 */

int
ia32_dom_dominates (ia32_bblock *b1, ia32_bblock *b2);


/* ia32_vcg_domtree_output
 *
 * output a dominator tree of an already created dominator tree. print
 * recursivly from `root' to file `fp'.
 *
 * return in any case
 */

void
ia32_vcg_domtree_output (FILE *fp, ia32_bblock *root);


/*** loop detection functions */


/* ia32_loop_find
 *
 * find all natural loops of the cfg, starting at `root'. the loops found are
 * directly annotated into the basic blocks. `nest_heuristics' can be used to
 * influence the heuristics used when multiple loops with the same head block
 * are encountered. see the manual page of objobf for details.
 *
 * return in any case
 */

#define	IA32_LOOP_NEST		0
#define	IA32_LOOP_DRAGON	1

void
ia32_loop_find (ia32_bblock *root, int nest_heuristic);


/* ia32_loop_find_single
 *
 * find a loop originating from a back edge at `bb'. insert the correct
 * ia32_loop structure into the basic blocks of the loop. (this function
 * implements algorithm 10.15 of the dragon book). `nest_heuristic' is the
 * same as in ia32_loop_find.
 *
 * return in any case
 */

void
ia32_loop_find_single (ia32_bblock **all, unsigned int all_count,
	ia32_bblock *bb_n, ia32_bblock *bb_d, int nest_heuristic);


/* ia32_loop_insert
 *
 * insert the basic block `bb' into the loop `loop', in case it is not already
 * there.
 *
 * return non-zero if it was inserted
 * return zero if it is already there
 */

int
ia32_loop_insert (ia32_loop *loop, ia32_bblock *bb);


/* ia32_loop_is_in
 *
 * return non-zero if the basic block `bb' is contained within `loop'
 * return zero otherwise
 */

int
ia32_loop_is_in (ia32_loop *loop, ia32_bblock *bb);


/* ia32_loop_new
 *
 * return a new loop structure.
 */

ia32_loop *
ia32_loop_new (void);


/* ia32_loop_free
 *
 * free the memory associated with `loop'.
 *
 * return in any case
 */

void
ia32_loop_free (ia32_loop *loop);


/*** OUTPUT functions */

/* ia32_vcg_loop_output_nested
 *
 * output a nested graph with loop information of function `func' to file
 * `fp'. all basic blocks in `all' are processed, which is `all_count' items
 * long. the current loop scope is given recursivly through `loop_v' and
 * should be set to NULL initially. `level' gives the current nesting level,
 * and should be set to zero initially.
 *
 * return in any case
 */

void
ia32_vcg_loop_output_nested (FILE *fp, ia32_function *func,
	ia32_bblock **all, unsigned int all_count, void *loop_v, int level);

#endif

