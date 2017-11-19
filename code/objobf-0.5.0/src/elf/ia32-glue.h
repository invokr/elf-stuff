/* ia32-glue.h - synnergy functionality between ia32* and elf*, header file
 *
 * everything that uses/provides both of the elf and ia32 datatypes goes here
 *
 * by scut
 */

#ifndef	IA32_GLUE_H
#define	IA32_GLUE_H

#include <elf_file.h>
#include <elf_section.h>
#include <ia32-function.h>


/* elf_function_list_find
 *
 * search the function list `flist', which is `count' items long for a function
 * with the entry address `entry_addr'.
 *
 * return ia32_function pointer when function is found
 * return NULL on failure (function not found)
 */

ia32_function *
elf_function_list_find (ia32_function **flist, unsigned int count,
	unsigned int entry_addr);


/* elf_function_list_sort
 *
 * sort the function list `flist' by start addresses. the list is
 * `flist_count' items long.
 *
 * return in any case
 */

void
elf_function_list_sort (ia32_function **flist, unsigned int flist_count);


/* elf_function_list_create
 *
 * create a list of functions from the elf file `elf'. return `count' items
 * of ia32_function structures. `slist' is a loaded and sorted section list
 * of the elf file. `sec' is the code section that should be processed.
 *
 * return pointer array to all loadable functions on success
 * return NULL on failure
 */

ia32_function **
elf_function_list_create (elf_file *elf, elf_section_list *slist,
	elf_section *sec, unsigned int *count);

#endif

