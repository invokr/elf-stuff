/* libxelf - segment abstraction module
 *
 * by scut / teso
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include <common.h>
#include <elf_dump.h>
#include <elf_section.h>
#include <elf_segment.h>


extern dump_elem	pt_tab[];



elf_segment *
elf_segment_create (void)
{
	elf_segment *	seg;

	seg = xcalloc (1, sizeof (elf_segment));
	seg->slist = elf_section_list_create ();

	return (seg);
}


void
elf_segment_destroy (elf_segment *seg)
{
	if (seg == NULL)
		return;

	/* TODO: find a cleaner way to not avoid clashes with elf->seclist and
	 *       elf->seglist.
	 */
#if 0
	if (seg->slist != NULL)
		elf_section_list_destroy (seg->slist);
#endif

	free (seg);

	return;
}


elf_segment *
elf_segment_load (elf_file *elf, unsigned long int ph_idx, Elf32_Phdr *Phdr)
{
	elf_segment *	new = NULL;

	if (fseek (elf->fp, Phdr->p_offset, SEEK_SET) != 0) {
		fprintf (stderr, "elf_segment_load: cannot seek to Phdr->p_offset (0x%08lx)\n",
			(unsigned long int) Phdr->p_offset);

		return (NULL);
	}

	new = elf_segment_create ();
	new->ph_idx = ph_idx;
	memcpy (&new->Phdr.p_type, Phdr, sizeof (Elf32_Phdr));

	return (new);
}


int
elf_segment_addsections (elf_segment *seg, elf_section_list *slist)
{
	int			walker,
				added = 0;
	unsigned long int	vaddr_start,
				vaddr_end;

	if (seg == NULL || slist == NULL)
		return (0);

	vaddr_start = seg->Phdr.p_vaddr;
	vaddr_end = vaddr_start + seg->Phdr.p_memsz;

	for (walker = 0 ; walker < slist->elem_count ; ++walker) {
		elf_section *	sect = slist->list[walker];

		/* detect incoherent sections, which are only partly within the
		 * segments virtual space
		 */
		if ((sect->Shdr.sh_addr < vaddr_end &&
			(sect->Shdr.sh_addr + sect->Shdr.sh_size > vaddr_end)) ||
			(sect->Shdr.sh_addr < vaddr_start &&
			(sect->Shdr.sh_addr + sect->Shdr.sh_size > vaddr_start)))
		{
			fprintf (stderr, "section (0x%08lx - 0x%08lx [0x%08lx])"
				"intrudes segment (0x%08lx - 0x%08lx [0x%08lx])",
				(unsigned long int) sect->Shdr.sh_addr,
				(unsigned long int) (sect->Shdr.sh_addr + sect->Shdr.sh_size),
				(unsigned long int) sect->Shdr.sh_size,
				vaddr_start, vaddr_end,
				(unsigned long int) seg->Phdr.p_memsz);

			exit (EXIT_FAILURE);	/* TODO: replace with elf_error */
		}

		/* not within segment -> next
		 */
		if (sect->Shdr.sh_addr < vaddr_start)
			continue;
		if (sect->Shdr.sh_addr >= vaddr_end)
			continue;

#if 0
		/* now we do have a perfect section, merge it into segment
		 * and remove it from source slist. also correct walker,
		 * because we cutted one element from slist and would ommit
		 * the next one.
		 */
		elf_section_list_del (slist, sect);
		walker -= 1;
#endif
		/* XXX: let the section remain in the original list
		 */
		elf_section_list_add (seg->slist, sect);
		added += 1;
	}

	if (added)
		elf_section_list_sort (seg->slist);

	return (added);
}


void
elf_segment_store (FILE *fp, elf_segment *seg)
{
	int			n;
	unsigned long int	last_end = 0;


	if (fp == NULL || seg == NULL)
		return;

	for (n = 0 ; n < elf_section_list_count (seg->slist) ; ++n) {
		elf_section *	sec = seg->slist->list[n];

		/* advance file position if necessary */
		if (last_end != 0 && sec->Shdr.sh_addr != last_end) {
			if (fseek (fp, sec->Shdr.sh_addr - last_end,
				SEEK_CUR) != 0)
			{
				perror ("elf_segment_store:fseek");
				exit (EXIT_FAILURE);
			}
		}
		if (sec->data_len != 0 && sec->data != NULL) {
			if (fwrite (sec->data, 1, sec->data_len, fp) !=
				sec->data_len)
			{
				perror ("elf_segment_store:fwrite");
				exit (EXIT_FAILURE);
			}
		}
		last_end = sec->Shdr.sh_addr + sec->Shdr.sh_size;
	}

	return;
}


long int
elf_segment_emptyhead (elf_segment *seg)
{
	unsigned long int	pv_start,
				pv_sec;

	pv_start = seg->Phdr.p_vaddr;

	/* assume ordered segment */
	if (seg->slist == NULL || seg->slist->elem_count <= 0)
		return (-1);

	pv_sec = seg->slist->list[0]->Shdr.sh_addr;
	if (pv_sec == 0)
		return (-1);

	if (pv_sec < pv_start)
		return (-1);

	return (pv_sec - pv_start);
}


/* TODO: check whether redundancy between elf_(section|segment)_list_* is
 *	 really necessary
 */

elf_segment_list *
elf_segment_list_create (void)
{
	return (xcalloc (1, sizeof (elf_segment_list)));
}


void
elf_segment_list_destroy (elf_segment_list *seglist)
{
	int	walker;

	if (seglist == NULL)
		return;

	for (walker = 0 ; walker < seglist->elem_count ; ++walker)
		elf_segment_destroy (seglist->list[walker]);

	if (seglist->list != NULL)
		free (seglist->list);

	free (seglist);

	return;
}


int
elf_segment_list_count (elf_segment_list *seglist)
{
	if (seglist == NULL)
		return (0);

	return (seglist->elem_count);
}


void
elf_segment_list_add (elf_segment_list *seglist, elf_segment *seg)
{
	if (seglist == NULL || seg == NULL)
		return;

	seglist->elem_count += 1;
	seglist->list = xrealloc (seglist->list,
		seglist->elem_count * sizeof (elf_segment *));

	seglist->list[seglist->elem_count - 1] = seg;

	return;
}


int
elf_segment_list_del (elf_segment_list *seglist, elf_segment *seg)
{
	int	walker;

	if (seglist == NULL || seglist->elem_count == 0 || seg == NULL)
		return (1);

	for (walker = 0 ; walker < seglist->elem_count ; ++walker) {
		if (seglist->list[walker] != seg)
			continue;

		seglist->elem_count -= 1;
		if (seglist->elem_count == 0 || seglist->elem_count == walker)
			return (0);

		memcpy (&seglist->list[walker], &seglist->list[walker + 1],
			(seglist->elem_count - walker) * sizeof (seglist->list[0]));

		return (0);
	}

	return (1);
}


void
elf_segment_list_print (elf_segment_list *seglist)
{
	int	sw,
		indent,
		walker;


	if (seglist == NULL)
		return;

	if (seglist->elem_count == 0) {
		printf ("elf_segment_list_print: empty segment list at 0x%08lx\n",
			(unsigned long int) seglist);
		return;
	}

	for (walker = 0 ; walker < elf_segment_list_count (seglist) ; ++walker) {
		elf_segment *	seg;

		seg = seglist->list[walker];
		printf ("(%2lu) | %-12s | 0x%08lx - 0x%08lx | %2lu sections\n",
			(unsigned long int) seg->ph_idx,
			elf_dump_tablookup (pt_tab, seg->Phdr.p_type),
			(unsigned long int) seg->Phdr.p_vaddr,
			(unsigned long int) (seg->Phdr.p_vaddr + seg->Phdr.p_memsz),
			(unsigned long int) elf_section_list_count (seg->slist));

		/* print section ames of sections contained within this
		 * segment
		 */
		indent = 0;
		for (sw = 0 ; sw < elf_section_list_count (seg->slist) ; ++sw) {
			elf_section *	sec;

			sec = seg->slist->list[sw];
			printf ("\t%-16s (0x%08lx - 0x%08lx)",
				sec->name == NULL ?  "???" : sec->name,
				(unsigned long int) sec->Shdr.sh_addr,
				(unsigned long int) (sec->Shdr.sh_addr +
					sec->Shdr.sh_size));

			if (++indent >= 1) {
				indent = 0;
				printf ("\n");
			}
		}
		if (indent != 0)
			printf ("\n");
	}

	printf ("\n");

	return;
}


