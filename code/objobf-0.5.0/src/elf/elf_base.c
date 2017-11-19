/* libxelf - base abstraction
 *
 * by scut / teso
 */

#include <stdio.h>
#include <stdlib.h>
#include <elf.h>

#include <common.h>
#include <elf_base.h>
#include <elf_dump.h>
#include <elf_file.h>
#include <elf_section.h>
#include <elf_segment.h>


extern dump_elem	pt_tab[];

/* local functions
 */
static void
elf_base_flatten_segseg (elf_segment *seg_m, elf_segment *seg_s);


elf_base *
elf_base_create (void)
{
	return (xcalloc (1, sizeof (elf_base)));
}


void
elf_base_destroy (elf_base *eb)
{
	if (eb == NULL)
		return;

	if (eb->elf != NULL)
		elf_file_destroy (eb->elf);

	if (eb->seglist != NULL)
		elf_segment_list_destroy (eb->seglist);

	if (eb->seclist != NULL)
		elf_section_list_destroy (eb->seclist);

	free (eb);

	return;
}


elf_base *
elf_base_load (char *pathname)
{
	int			n;
	elf_base *		new = elf_base_create ();

	/* load a slightly abstracted image of the ELF file into memory
	 */
	new->elf = elf_file_load (pathname);
	if (new->elf == NULL)
		goto bail;

	/* break the image up into sections and segments, mapping sections
	 * into section list, that correspond to loaded segment. for orphan
	 * sections, keep an extra list, so we do not lose them.
	 * FIXME: we trust the binary in all offsets etc, and do only minimal
	 *        verification and sanity checks. treat the binary as trusted.
	 */
	/* sections */
	new->seclist = elf_section_list_create ();

	for (n = 0 ; n < new->elf->Ehdr.e_shnum ; ++n) {
		elf_section *	swork;

		swork = elf_section_load (new->elf, n, &new->elf->Shdr[n]);
		elf_section_list_add (new->seclist, swork);
	}
	elf_section_list_sort (new->seclist);

	new->symtab = elf_section_list_find_type (new->seclist, SHT_SYMTAB,
		NULL);

	/* segments and mapping */
	new->seglist = elf_segment_list_create ();

	for (n = 0 ; n < new->elf->Ehdr.e_phnum ; ++n) {
		elf_segment *	seg;

		seg = elf_segment_load (new->elf, n, &new->elf->Phdr[n]);

		/* find contained sections and remove them from list */
		elf_segment_addsections (seg, new->seclist);
		elf_segment_list_add (new->seglist, seg);
	}

	/* XXX: free elf_file structures now ? (to avoid double dangling
	 *      pointers). XXX: does not seem to occur (double free) -sc.
	 */

	return (new);

bail:
	elf_base_destroy (new);

	return (NULL);
}


int
elf_base_store (char *pathname, elf_base *eb)
{
	int			walker;
	FILE *			fp;
	Elf32_Ehdr		Ehdr;
	long int		emptyhead;

	/* first create file and reserve space for the header we will insert
	 * later on
	 */
	fp = fopen (pathname, "a+b");
	if (fp == NULL)
		goto bail;

	if (fseek (fp, sizeof (Ehdr), SEEK_SET) != 0)
		goto bail;

	/* move all sections that are loaded into memory into PT_LOAD segments
	 * and order them to make linear writting easier
	 */
	elf_base_flatten (eb);

	/* TODO: order segments to minimize padding between segments
	 */
	for (walker = 0 ; walker < elf_segment_list_count (eb->seglist) ;
		++walker)
	{
		elf_segment *	seg;

		seg = eb->seglist->list[walker];

		/* sections that are not covered by PT_LOAD segments
		 * and are dangling in real segments should not occur,
		 * so bail. XXX: what should we do, now we just skip them ?
		 */
		if (seg->Phdr.p_type != PT_LOAD &&
			elf_section_list_count (seg->slist) != 0)
		{
			fprintf (stderr, "elf_base_store: segment %d, type "
				"%s is non-empty (%d sections)\n",
				walker,
				elf_dump_tablookup (pt_tab, seg->Phdr.p_type),
				elf_section_list_count (seg->slist));
		}

		if (seg->Phdr.p_type != PT_LOAD)
			continue;

		/* PT_LOAD segment, seek to correct padding and write to file
		 */
#ifdef DEBUG
		printf ("   file at 0x%08lx (0x%04lx [mod 0x1000]) (file)\n",
			ftell (fp), (unsigned long int) (ftell (fp) % 0x1000));
		printf ("segment at 0x%08lx (0x%04lx [mod 0x1000]) (virtual)\n",
			(unsigned long int) seg->Phdr.p_vaddr,
			(unsigned long int) (seg->Phdr.p_vaddr % 0x1000));
#endif
		emptyhead = elf_segment_emptyhead (seg);
		if (emptyhead == -1) {
			fprintf (stderr, "elf_base_store: emptyhead == -1\n");
			goto bail;
		} else if (emptyhead < (ftell (fp) % 0x1000)) {
			fprintf (stderr, "elf_base_store: emptyhead (%08lx) "
				"is smaller than fp (%08lx) mod 0x1000 "
				"(0x%08lx)\n", emptyhead, ftell (fp),
				ftell (fp) % 0x1000);
			emptyhead += 0x1000;
		}

		if (fseek (fp, (ftell (fp) & ~0x0fff) + emptyhead,
			SEEK_SET) != 0)
		{
			perror ("elf_base_store:fseek");
			goto bail;
		}

		/* store sections in a linear way, advancing fp */
		elf_segment_store (fp, seg);
	}

	fclose (fp);

	return (0);

bail:
	if (fp != NULL)
		fclose (fp);

	return (1);
}


void
elf_base_flatten (elf_base *eb)
{
	int	walker,
		sw;	/* subwalker */


	for (walker = 0 ; walker < elf_segment_list_count (eb->seglist) ;
		++walker)
	{
		if (eb->seglist->list[walker]->Phdr.p_type != PT_LOAD)
			continue;

		/* it is a PT_LOAD segment, find all sections that do belong
		 * here, but are stored within non PT_LOAD segments
		 */
		for (sw = 0 ; sw < elf_segment_list_count (eb->seglist) ;
			++sw)
		{
			if (sw == walker)	/* skip our current segment */
				continue;

			/* assume PT_LOAD segments do not overlap (requires
			 * in ELF specs
			 */
			if (eb->seglist->list[sw]->Phdr.p_type == PT_LOAD)
				continue;

			elf_base_flatten_segseg (eb->seglist->list[walker],
				eb->seglist->list[sw]);
		}
	}

	return;
}


/* elf_base_flatten_segseg
 *
 * sort any sections within `seg_s' into `seg_m' if they belong there
 *
 * return in any case
 */

static void
elf_base_flatten_segseg (elf_segment *seg_m, elf_segment *seg_s)
{
	int			n;
	unsigned long int	seg_m_start,
				seg_m_end,
				seg_s_start,
				seg_s_end;

	seg_m_start = seg_m->Phdr.p_vaddr;
	seg_m_end = seg_m_start + seg_m->Phdr.p_memsz;

	seg_s_start = seg_s->Phdr.p_vaddr;
	seg_s_end = seg_s_start + seg_s->Phdr.p_memsz;

	/* do they overlap ? (normal segments may overlap except PT_LOAD
	 * segments. sections may not overlap in any case
	 */
	if (seg_m_end <= seg_s_start || seg_s_end <= seg_m_start)
		return;

	/* they do overlap, and seg_m is the PT_LOAD section we have to
	 * feed. through recounting sections all the time we ensure that
	 * by removing sections we do not access them based on old counters.
	 */
	for (n = 0 ; n < elf_section_list_count (seg_s->slist) ; ++n) {
		elf_section *	sec;

		sec = seg_s->slist->list[n];
#ifdef DEBUG
		printf ("flattening: %-20s - ", sec->name != NULL ? sec->name : "?");
#endif
		if (sec->Shdr.sh_addr >= seg_m_start &&
			(sec->Shdr.sh_addr + sec->Shdr.sh_size) <= seg_m_end)
		{
#ifdef DEBUG
			printf ("moving to seg_m\n");
#endif
			elf_section_list_del (seg_s->slist, sec);
			elf_section_list_add (seg_m->slist, sec);
		}
#ifdef DEBUG
		else {
			printf ("keeping in seg_s\n");
		}
#endif
	}

	elf_section_list_sort (seg_m->slist);

	return;
}


void
elf_base_print (elf_base *eb)
{
}


