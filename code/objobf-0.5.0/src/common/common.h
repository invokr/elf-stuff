
#ifndef	COMMON_H
#define	COMMON_H

#include <stdio.h>

#ifdef	DEBUG
void	debugp (char *filename, const char *str, ...);
void	hexdump (char *filename, unsigned char *data, unsigned int amount);
#endif
/* exactly the same semantics like their non-x functions, but asserting a
 * successful non-NULL return.
 */
void * xrealloc (void *m_ptr, size_t newsize);
char * xstrdup (char *str);
void * xcalloc (int factor, size_t size);

/* array_compaction
 *
 * compact an array of pointers by removing all NULL pointers from it. the
 * array of pointers is at `arr_ptr' and holds `el_count' elements.
 *
 * return number of real elements in array after compaction
 */

unsigned int
array_compaction (void *arr_ptr, unsigned int el_count);

#endif

