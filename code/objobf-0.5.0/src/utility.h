/* utility.c - burneye2 supporting functions, include file
 *
 * by scut
 */

#ifndef	UTILITY_H
#define	UTILITY_H


/* fnote
 *
 * output format message `fmt' to stderr when verbosity is set.
 *
 * return length of message send to stderr
 */

int
fnote (const char *fmt, ...);


/* be_randinit_file
 *
 * initialize the random functions from filename `filename'.
 *
 * return in any case
 */

void
be_randinit_file (const char *filename);


/* be_randinit
 *
 * initialize the random functions of burneye.
 *
 * return in any case
 */

void
be_randinit (void);


/* be_randend
 *
 * close the random file descriptor.
 *
 * return in any case
 */

void
be_randend (void);


/* be_random
 *
 * generate a random number
 *
 * return a random number between 0 and `max'-1.
 */

unsigned int
be_random (unsigned int max);


/* be_random_coin
 *
 * throw a biased coin with probability `prob'.
 *
 * return 1 in case the `prob'-probable case was the result
 * return 0 otherwise
 */

int
be_random_coin (double prob);


/* be_random_prob
 *
 * do a probabilistic random decision. probabilities are relative and given
 * through `items_prob', which should be an all-positive array with
 * `items_count' elements.
 *
 * return the index of the array that made it
 */

unsigned int
be_random_prob (unsigned int items_count, double *items_prob);

#endif

