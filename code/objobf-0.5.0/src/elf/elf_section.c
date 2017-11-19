/* libxelf - section abstraction module
 *
 * by scut / teso
 */

#include <elf.h>
#include <stdlib.h>
#include <string.h>

#include <common.h>
#include <elf_file.h>
#include <elf_section.h>


/* local functions
 */
static int
elf_section_list_sort_compar (const void *e1, const void *e2);


elf_section *
elf_section_create (void)
{
	return (xcalloc (1, sizeof (elf_section)));
}


void
elf_section_destroy (elf_section *sect)
{
	if (sect == NULL)
		return;

	if (sect->name != NULL)
		free (sect->name);

	if (sect->data != NULL)
		free (sect->data);

	free (sect);

	return;
}


elf_section *
elf_section_load (elf_file *elf, unsigned long int sh_idx, Elf32_Shdr *Shdr)
{
	elf_section *	new = NULL;

	if (fseek (elf->fp, Shdr->sh_offset, SEEK_SET) != 0) {
		fprintf (stderr, "elf_section_load: cannot seek to Shdr->sh_offset (0x%08lx)\n",
			(unsigned long int) Shdr->sh_offset);

		goto bail;
	}

	new = elf_section_create ();
	new->sh_idx = sh_idx;
	memcpy (&new->Shdr.sh_name, Shdr, sizeof (Elf32_Shdr));

	new->data_len = Shdr->sh_size;

	if (Shdr->sh_type != SHT_NOBITS) {
		new->data = xcalloc (1, Shdr->sh_size);

		if (fread (new->data, 1, Shdr->sh_size, elf->fp) != Shdr->sh_size) {
			fprintf (stderr, "elf_section_load: cannot read Shdr->sh_size (0x%08lx) bytes\n",
				(unsigned long int) Shdr->sh_size);

			goto bail;
		}
	}

	/* if possible, fill in name. else new->name remains NULL
	 */
	if (elf->sh_str != NULL)
		new->name = xstrdup (&elf->sh_str[Shdr->sh_name]);

	return (new);

bail:
	elf_section_destroy (new);

	return (NULL);
}


void
elf_section_secalloc (elf_section_list *slist)
{
	unsigned int	n;
	elf_section *	sec;


	for (n = 0 ; n < slist->elem_count ; ++n) {
		sec = slist->list[n];

		if (sec->data_len > 0 && sec->data == NULL) {
#ifdef DEBUG
			fprintf (stderr, "extend \"%s\" to 0x%08lx bytes\n",
				sec->name, sec->data_len);
#endif

			sec->data = xcalloc (1, sec->data_len);
		}
	}

	return;
}


char *
elf_section_name (elf_file *elf, elf_section *sect)
{
	if (elf == NULL || elf->sh_str == NULL || sect == NULL)
		return (NULL);

	return (&elf->sh_str[sect->Shdr.sh_name]);
}


elf_section_list *
elf_section_list_create (void)
{
	return (xcalloc (1, sizeof (elf_section_list)));
}


void
elf_section_list_destroy (elf_section_list *slist)
{
	if (slist == NULL)
		return;

	while (slist->elem_count > 0) {
		elf_section_destroy (slist->list[slist->elem_count - 1]);
		slist->elem_count -= 1;
	}

	free (slist->list);
	free (slist);

	return;
}


void
elf_section_list_add (elf_section_list *slist, elf_section *sect)
{
	if (slist == NULL || sect == NULL)
		return;

	/* add space, then append
	 */
	slist->elem_count += 1;
	slist->list = xrealloc (slist->list,
		slist->elem_count * sizeof (elf_section *));

	slist->list[slist->elem_count - 1] = sect;

	return;
}


int
elf_section_list_del (elf_section_list *slist, elf_section *sect)
{
	int	walker;

	if (slist == NULL || slist->elem_count == 0 || sect == NULL)
		return (1);

	for (walker = 0 ; walker < slist->elem_count ; ++walker) {
		if (slist->list[walker] != sect)
			continue;

		/* found element, decrease counter, if no elements left or
		 * found element was the last, then just return, else slide
		 * all remaining elements one slot up.
		 */
		slist->elem_count -= 1;
		if (slist->elem_count == 0 || slist->elem_count == walker)
			return (0);

		memcpy (&slist->list[walker], &slist->list[walker + 1],
			(slist->elem_count - walker) * sizeof (slist->list[0]));

		return (0);	/* assume no elements can be in two times */
	}

	return (1);
}


int
elf_section_list_count (elf_section_list *slist)
{
	if (slist == NULL)
		return (0);

	return (slist->elem_count);
}


void
elf_section_list_sort (elf_section_list *slist)
{
	/* nothing to sort ?
	 */
	if (slist == NULL || slist->elem_count <= 1)
		return;

	qsort (slist->list, slist->elem_count, sizeof (elf_section *),
		elf_section_list_sort_compar);

	return;
}


/* elf_section_list_sort_compar
 *
 * helper function to elf_section_list_sort/qsort
 */

static int
elf_section_list_sort_compar (const void *e1, const void *e2)
{
	elf_section *	s1;
	elf_section *	s2;

	s1 = (elf_section *) *((elf_section **) e1);
	s2 = (elf_section *) *((elf_section **) e2);

	if (s1->Shdr.sh_addr == s2->Shdr.sh_addr)
		return (0);

	if (s1->Shdr.sh_addr < s2->Shdr.sh_addr)
		return (-1);

	return (1);
}


elf_section *
elf_section_list_find_index (elf_section_list *slist, unsigned long int idx)
{
	int	walker;

	if (slist == NULL || slist->elem_count == 0)
		return (NULL);

	for (walker = 0 ; walker < slist->elem_count ; ++walker) {
		if (slist->list[walker]->sh_idx == idx)
			return (slist->list[walker]);
	}

	return (NULL);
}


elf_section *
elf_section_list_find_type (elf_section_list *slist, Elf32_Word sh_type,
	elf_section *old)
{
	int	walker;

	if (slist == NULL || slist->elem_count == 0)
		return (NULL);

	for (walker = 0 ; walker < slist->elem_count ; ++walker) {
		if (old != NULL) {
			if (slist->list[walker] == old)
				old = NULL;

			continue;
		}

		if (slist->list[walker]->Shdr.sh_type == sh_type)
			return (slist->list[walker]);
	}

	return (NULL);
}


elf_section *
elf_section_list_find_name (elf_section_list *slist, char *name)
{
	int	walker;

	if (slist == NULL)
		return (NULL);

	for (walker = 0 ; walker < slist->elem_count ; ++walker) {
		if (strcmp (slist->list[walker]->name, name) == 0)
			return (slist->list[walker]);
	}

	return (NULL);
}


