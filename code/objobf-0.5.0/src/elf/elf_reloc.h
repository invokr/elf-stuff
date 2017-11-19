/* libxelf - relocation abstraction module, include file
 *
 * by scut / teso
 */

#ifndef	ELF_RELOC_H
#define	ELF_RELOC_H

#include <elf.h>
#include <elf_base.h>
#include <elf_section.h>
#include <elf_symbol.h>


typedef struct elf_rel_list {
	struct elf_rel_list *	next;

	/* _section = the relocation section that contains the relocation table
	 *     entries
	 * _symbol = the symbol table used for the relocation entries
	 * _modify = the section that is targeted relocation entries
	 */
	elf_section *	reloc_section;
	elf_section *	reloc_symbol;
	elf_section *	reloc_modify;

	/* relocation entries themselves
	 */
	unsigned int	reloc_count;
	Elf32_Rel *	reloc;
} elf_rel_list;


/* elf_reloc
 *
 * every elf_reloc structure has a context object it is refering to. this can
 * be a section or a function. the `offset_rel' offset is relative to the start
 * of the context object.
 *
 * for detailed information about the relocation types, see TIS-ELF_v1.2.pdf,
 * book 3 chapter a-4, book 2 chapter 1-4, book 1 chapter 1-22
 */
typedef struct elf_reloc {
	/* addr = load address of context + offset_rel */
	unsigned int	offset_rel;

	/* optional */
	elf_symbol *	sym;

	unsigned int	type;
#define	ELF_RELOC_SECTION	1
#define	ELF_RELOC_FUNCTION	2
#define	ELF_RELOC_EXTERNAL	3

	/* what the symbol is refering to */
	elf_section *		sec;
	struct ia32_function *	func;
/*TODO	elf_external *		ext; */

	/* (optional) an addend. this should only be used for data sections,
	 *     functions should be relocated using ia32_function structures
	 */
	unsigned int	addend;
	Elf32_Rel	orig;	/* original Elf32_Rel entry */
} elf_reloc;


typedef struct elf_reloc_hl {
	struct elf_reloc_hl *	next;
	elf_reloc *		rel_e;
} elf_reloc_hl;


/* elf_reloc_list
 *
 * relocations in our representation for one section.
 */
typedef struct {
	elf_section *	reloc_section;
	elf_section *	reloc_modify;

	/* pure sequential list of relocation records
	 */
	unsigned int	reloc_count;
	elf_reloc **	reloc;

	/* since relocation lookups can be very expensive with thousands of
	 * relocation entries, we organize them additionally in a hashtable,
	 * in 0 to (`reloc_hash_buckets' - 1) linked lists in `reloc_hash'.
	 * rel->reloc[n]->offset_rel is hashed.
	 * but `reloc_hash' and `reloc_hash_buckets' can both be NULL/0.
	 */
	unsigned int	reloc_hash_buckets;
	elf_reloc_hl **	reloc_hash;
} elf_reloc_list;

#include <ia32-glue.h>


/* elf_reloc_list_lookup
 *
 * lookup relocations from the list `rel' for the first relocation happening
 * for the address `vaddr_loc'.
 *
 * return NULL on failure
 * return matching relocation element on success
 */

elf_reloc *
elf_reloc_list_lookup (elf_reloc_list *rel, unsigned int vaddr_loc);


/* elf_reloc_list_hashgen
 *
 * generate the hash table for the relocation entries within `rel'. if
 * `buckets' is not zero, use the number of buckets for the hashtable
 * organization.
 *
 * return in any case
 */

void
elf_reloc_list_hashgen (elf_reloc_list *rel, unsigned int buckets);


/* elf_reloc_list_lookup_func
 *
 * look through the list `rel' for function address relocations happen directly
 * at `vaddr'.
 *
 * return the virtual address of the function relocated to on success
 * return 0xffffffff on failure
 */

unsigned int
elf_reloc_list_lookup_func (elf_reloc_list *rel, unsigned int vaddr);


/* elf_reloc_list_debug
 *
 * like lookup_func, but spilling any relocation at `vaddr' as output on
 * stderr.
 *
 * return in any case.
 */

void
elf_reloc_list_debug (elf_reloc_list *rel, unsigned int vaddr);


/* elf_reloc_list_create
 *
 * convert the section Elf32_Rel entries for one specific section found in
 * `secrel' to our representation (elf_reloc_list). additional information
 * about the executeable have to be passed through the `base' structure. a
 * function list has to be provided (`flist' and `flist_count'), so the
 * relocations can be abstracted to function targets instead of addresses.
 *
 * return a elf_reloc_list pointer relating to the specific section of `secrel'
 *     on success
 * return NULL on failure
 */

elf_reloc_list *
elf_reloc_list_create (elf_base *base, elf_rel_list *secrel,
	ia32_function **flist, unsigned int flist_count);


/* elf_reloc_list_destroy
 *
 * free any memory allocated for `list'.
 *
 * return in any case
 */

void
elf_reloc_list_destroy (elf_reloc_list *list);


/* elf_rel_list_find_byname
 *
 * within the elf relocation list starting at `rel', find the relocation
 * section named `name'.
 *
 * return NULL on failure
 * return elf_rel_list element on success
 */

elf_rel_list *
elf_rel_list_find_byname (elf_rel_list *rel, char *name);


/* elf_rel_list_find_bymodsection
 *
 * find the appropiate relocation data within the list `rel' for the
 * to-be-modified section `sec'. the comparison is done on the section data,
 * not on the pointer.
 *
 * return relocation data on success
 * return NULL on failure
 */

elf_rel_list *
elf_rel_list_find_bymodsection (elf_rel_list *rel, elf_section *sec);


/* elf_rel_list_find_byrelsection
 *
 * exactly the same as _bymodsection, just finding the appropiate relocation
 * list item for the relocation section `sec'.
 *
 * return relocation data on success
 * return NULL on failure
 */

elf_rel_list *
elf_rel_list_find_byrelsection (elf_rel_list *rel, elf_section *sec);


/* elf_rel_list_create
 *
 * create a linked list of relocation sections. every element refers to one
 * relocation section and provides all the data about it.
 *
 * return pointer to root element on success
 * return NULL when there are no relocation sections available
 */

elf_rel_list *
elf_rel_list_create (elf_base *base);

#endif


