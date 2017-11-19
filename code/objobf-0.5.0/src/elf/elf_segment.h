/* libxelf - segment abstraction module
 *
 * by scut / teso
 */

#ifndef	ELF_SEGMENT_H
#define	ELF_SEGMENT_H

#include <elf.h>

#include <elf_file.h>
#include <elf_section.h>


/* elf_segment structure
 *
 * this is a program header segment, which contains a variable number of
 * sections, the program header and extra information. executeables are
 * build of a number of elf_segment structures
 */
typedef struct {
	unsigned long int	ph_idx;	/* original index of header table */

	/* here we include an abstracted segment header,
	 * the `p_offset' value is the original value from the elf file
	 * this structure was read from, but it is read-only, and rebuild
	 * on creation of a new ELF file
	 */
	Elf32_Phdr		Phdr;

	/* sections that lie within this segment
	 */
	elf_section_list *	slist;
} elf_segment;


typedef struct {
	int		elem_count;	/* number of elements */

	elf_segment **	list;	/* array of elf_segment structure pointers */
} elf_segment_list;


/* elf_segment_create
 *
 * create a new elf_segment structure
 *
 * return pointer to new structure
 */

elf_segment *
elf_segment_create (void);


/* elf_segment_destroy
 *
 * free all resources within `seg' structure, including the section list
 *
 * return in any case
 */

void
elf_segment_destroy (elf_segment *seg);


/* elf_segment_load
 *
 * load a program segment described by the program header `Phdr', with
 * original program header table index `ph_idx' from elf_file `elf'.
 *
 * return NULL on failure
 * return pointer to new elf_segment structure on success
 */
elf_segment *
elf_segment_load (elf_file *elf, unsigned long int ph_idx, Elf32_Phdr *Phdr);


/* elf_segment_addsections
 *
 * add elf_section_list `slist' into the segment `seg', where the virtual
 * address mappings are fitting within the segments description headers'
 * virtual address. remove matching sections from `slist'.
 *
 * return number of added sections
 */

int
elf_segment_addsections (elf_segment *seg, elf_section_list *slist);


/* elf_segment_store
 *
 * store an elf segment `seg' with all its sections to a properly aligned file
 * `fp'
 *
 * return in any case
 */

void
elf_segment_store (FILE *fp, elf_segment *seg);


/* elf_segment_emptyhead
 *
 * count the number of bytes from the segments `seg' virtual start address
 * to the first real occupied byte by its first contained section
 * assume sections within segment are ordered.
 *
 * return distance on success
 * return -1 on failure
 */

long int
elf_segment_emptyhead (elf_segment *seg);


/* elf_segment_list_create
 *
 * create a new elf_segment_list structure
 *
 * return pointer to new structure
 */

elf_segment_list *
elf_segment_list_create (void);


/* elf_segment_list_destroy
 *
 * destroy the segment list `seglist' and all its elements, including any
 * sections associated with those segments
 *
 * return in any case
 */

void
elf_segment_list_destroy (elf_segment_list *seglist);


/* elf_segment_list_count
 *
 * return the number of segments within the segment list `seglist'
 */

int
elf_segment_list_count (elf_segment_list *seglist);


/* elf_segment_list_add
 *
 * add an elf_section structure `seg' to the segment list `seglist'
 *
 * return in any case
 */

void
elf_segment_list_add (elf_segment_list *seglist, elf_segment *seg);


/* elf_segment_list_del
 *
 * delete segment `seg' from the segment list `seglist'
 *
 * return 0 in case it was removed
 * return 1 in case it was not found
 */

int
elf_segment_list_del (elf_segment_list *seglist, elf_segment *seg);


/* elf_segment_list_print
 *
 * print a elf_segment_list `seglist' in a short "one-segment-one-line"
 * form
 *
 * return in any case
 */

void
elf_segment_list_print (elf_segment_list *seglist);


#endif


