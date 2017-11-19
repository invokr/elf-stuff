/* libxelf - base abstraction
 *
 * by scut / teso
 */

#ifndef	ELF_BASE_H
#define	ELF_BASE_H

#include <elf_section.h>
#include <elf_segment.h>


typedef struct {
	/* the original file this executeable was derived from.
	 * it is used for dumping purposes and to get certain data
	 * from the original Elf32_Ehdr structure, such as the e_flags
	 * and e_entry values. all the section/segment data is contained
	 * in the lists below though.
	 */
	elf_file *		elf;

	/* list of segments of the ELF file, which themself
	 * cover sections
	 */
	elf_segment_list *	seglist;

	/* uncovered section list
	 */
	elf_section_list *	seclist;

	/* symbol table section from seclist, or NULL
	 */
	elf_section *		symtab;
} elf_base;


/* elf_base_create
 *
 * create a new elf_base structure
 *
 * return pointer to new structure
 */

elf_base *
elf_base_create (void);


/* elf_base_destroy
 *
 * free the elf_base structure pointer to by `eb', recursivly freeing any
 * associated data. note that eb should only contain section data once,
 * or copies of it, there must not be two pointers to the same memory.
 *
 * return in any case
 */

void
elf_base_destroy (elf_base *eb);


/* elf_base_load
 *
 * completely abstract an ELF executeable from file at `pathname' into an
 * elf_base structure.
 *
 * return pointer to new elf_base structure on success
 * retrun NULL on failure
 */

elf_base *
elf_base_load (char *pathname);


/* elf_base_store
 *
 * create a new ELF executeable from the elf_base structure at `eb'. the new
 * executeable is placed at `pathname', possible overwritting any previous
 * file.
 *
 * return 0 on success
 * return 1 on failure
 */

int
elf_base_store (char *pathname, elf_base *eb);


/* elf_base_flatten
 *
 * 'flatten' a ELF file tree at `eb'. to do this we find sections that are
 * included twice within a segment but are still dangling in a non PT_LOAD
 * segment. this is the case for PT_INTERP segments, which "steal" away
 * sections, which have to be within a PT_LOAD segment to be written to
 * disk properly.
 *
 * return in any case
 */

void
elf_base_flatten (elf_base *eb);


/* elf_base_print
 *
 * print the basic structure of the ELF file pointed to by `eb'
 *
 * return in any case
 */

void
elf_base_print (elf_base *eb);


#endif


