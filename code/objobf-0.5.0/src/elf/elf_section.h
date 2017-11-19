/* libxelf - section abstraction module
 *
 * by scut / teso
 */

#ifndef	ELF_SECTION_H
#define	ELF_SECTION_H

#include <elf.h>

#include <elf_file.h>


/* elf_section structure
 * abstract, physically-position-independant section header and content
 * it is not virtual-memory position-independant however
 */
typedef struct {
	unsigned long int	sh_idx;
	char *			name;	/* section name or NULL */

	/* here we include an abstracted section header,
	 * the `sh_offset' element is read only, and contains the original
	 * value. on write into a new ELF file it is recomputed
	 */
	Elf32_Shdr		Shdr;

	unsigned long int	data_len;	/* original from sh_size */
	unsigned char *		data;		/* data if non-NULL */

	unsigned char *		data_backup;
} elf_section;


typedef struct {
	int		elem_count;	/* number of elements */

	elf_section **	list;	/* array of elf_section structure pointers */
} elf_section_list;


/* elf_section_create
 *
 * create a new elf_section structure
 *
 * return pointer to new structure
 */

elf_section *
elf_section_create (void);


/* elf_section_destroy
 *
 * destroy any associated memory with `sect'
 *
 * return in any case
 */

void
elf_section_destroy (elf_section *sect);


/* elf_section_load
 *
 * load a new section whose section header is passed through `Shdr'.
 *
 * return NULL on failure
 * return pointer to new elf_section structure on success
 */

elf_section *
elf_section_load (elf_file *elf, unsigned long int sh_idx, Elf32_Shdr *Shdr);


/* elf_section_secalloc
 *
 * extend all sections that do not cover real content in file to their real
 * in-memory size, filling the content with zeroes. this can be used to
 * operate in .bss, which does not take up space in the file and is not
 * allocated normally. all sections in `slist' are checked for this and
 * extended accordingly.
 *
 * return in any case
 */

void
elf_section_secalloc (elf_section_list *slist);


/* elf_section_name
 *
 * search for the section name of section `sect' in elf_file `elf'
 *
 * return NULL on failure
 * return pointer to constant string on success
 */

char *
elf_section_name (elf_file *elf, elf_section *sect);


/* elf_section_list_create
 *
 * create a new section list, which is empty
 *
 * return pointer to new list
 */

elf_section_list *
elf_section_list_create (void);


/* elf_section_list_destroy
 *
 * destroy the section list `slist' and all its elements.
 *
 * return in any case
 */

void
elf_section_list_destroy (elf_section_list *slist);


/* elf_section_list_add
 *
 * add elf_section `sect' to list `slist'
 *
 * return in any case
 */

void
elf_section_list_add (elf_section_list *slist, elf_section *sect);


/* elf_section_list_del
 *
 * remove elf_section `sect' from list `slist'
 *
 * return 0 in case it was removed
 * return 1 in case it was not found
 */

int
elf_section_list_del (elf_section_list *slist, elf_section *sect);


/* elf_section_list_count
 *
 * return number of elements in section list `slist'
 */

int
elf_section_list_count (elf_section_list *slist);


/* elf_section_list_sort
 *
 * sort section list `slist' by `slist.list[].Shdr.sh_addr', in ascending
 * order
 *
 * return in any case
 */

void
elf_section_list_sort (elf_section_list *slist);


/* elf_section_list_find_index
 *
 * find an elf_section structure within the list `slist', that has the
 * original sh_idx value of `idx'.
 *
 * return NULL on failure
 * return pointer to structure on success (static structure, do not free!)
 */

elf_section *
elf_section_list_find_index (elf_section_list *slist, unsigned long int idx);


/* elf_section_list_find_type
 *
 * find an elf_section structure within the list `slist', that has the
 * section type (Shdr.sh_type) of `sh_type'. when `old' is non-NULL, the
 * search is picked up after this item. this allows walking all sections of a
 * type.
 *
 * return NULL on failure
 * return pointer to first structure on success
 */

elf_section *
elf_section_list_find_type (elf_section_list *slist, Elf32_Word sh_type,
	elf_section *old);


/* elf_section_list_find_name
 *
 * find an elf_section structure within the list `slist' with the name `name'.
 *
 * return found section on success
 * return NULL on failure
 */

elf_section *
elf_section_list_find_name (elf_section_list *slist, char *name);

#endif


