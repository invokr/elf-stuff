/* ia32-debug.c - ia32 debug output functionality, include file
 *
 * by scut
 */

#ifndef	IA32_DEBUG_H
#define	IA32_DEBUG_H

#define	IA32_FATAL	0
#define	IA32_WARNING	1
#define	IA32_INFO	2
#define	IA32_DEBUG	3


/* ia32_verbose
 *
 * tests whether `vlevel' can be passed through the filter.
 *
 * return 0 if it is too verbose
 * return 1 if user wants this verbosity
 */

int
ia32_verbose (int vlevel);


/* ia32_debug
 *
 * output format message `fmt' to stderr when `vlevel' is higher or equal
 * to internal verbosity filter (ia32_verbosity).
 *
 * return length of message send to stderr
 */

int
ia32_debug (int vlevel, const char *fmt, ...);


/* ia32_confirm
 *
 * wait for a keypress (return).
 */

void
ia32_confirm (void);

#endif

