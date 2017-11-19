/* datahandler.h - burneye2 .rodata/.data handling functions, include file
 *
 * by scut
 */

#ifndef	DATAHANDLER_H
#define	DATAHANDLER_H

typedef struct data_item {
	struct data_item *	next;	/* next linked list element or NULL */

	int		dangling;	/* 1 for "uncovered" space */
	int		endunsure;	/* 1 when the end is guessed */

	unsigned int	offset;	/* relative offset to section begin */
	unsigned int	length;	/* length of complete item */

	unsigned char *	data;	/* when non-NULL, its content */

	/* TODO: add other xref in here, also allow in-function jumps to branch
	 * level, for switch tables.
	 */
} data_item;


/* dh_item_new
 *
 * create a new data_item structure
 *
 * return pointer to new structure
 */

data_item *
dh_item_new (void);


/* dh_item_list_create_bysymreloc
 *
 * create an approximated item list of data section `datasec'. to do this,
 * first consult information from the symbol table given with `base', then
 * examine the relocation table `rel' for this section to find more subtile
 * data items within the section (switch tables, compile emitted constructs,
 * for which no symbol table entry is present).
 *
 * return root list element of data_item list on success
 * return NULL on failure
 */

data_item *
dh_item_list_create_bysymreloc (elf_base *base, elf_section *datasec,
	elf_rel_list *rel);


/* dh_carve
 *
 * carve the data object ranging `length' bytes from offset `offset' with its
 * data at `data' from the data item list `dh'. the space cut must be in
 * dangling state, else we will bail. assume the list going from `dh' is
 * sorted by dh_sort, with offset-ascending order.
 *
 * return new root data_item list item
 */

data_item *
dh_carve (data_item *dh, unsigned int offset, unsigned int length,
	unsigned char *data);

#endif

