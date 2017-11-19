/* ia32-glue.c - synnergy functionality between ia32* and elf*
 *
 * by scut
 */

#include <stdio.h>
#include <stdlib.h>
#include <elf.h>
#include <string.h>
#include <assert.h>

#include <common.h>
#include <elf_section.h>
#include <elf_symbol.h>
#include <elf_reloc.h>
#include <ia32-glue.h>


static int
elf_function_list_create_compar (const void *el1, const void *el2);


ia32_function *
elf_function_list_find (ia32_function **flist, unsigned int count,
	unsigned int entry_addr)
{
	unsigned int	n;


	for (n = 0 ; n < count ; ++n)
		if (flist[n]->start == entry_addr)
			return (flist[n]);

	return (NULL);
}


ia32_function **
elf_function_list_create (elf_file *elf, elf_section_list *slist,
	elf_section *sec, unsigned int *count)
{
	unsigned int		n;

	ia32_function *		fwork;
	ia32_function **	flist = NULL;
	elf_section *		symtab_str;
	elf_section *		symtab;
	elf_section *		swork;
	Elf32_Sym		sent;


	/* create and load section list
	 */
	symtab = elf_section_list_find_type (slist, SHT_SYMTAB, NULL);
	if (symtab == NULL) {
		fprintf (stderr, "elf_function_list_create: "
			"binary has no symbol table\n");

		goto bail;
	}

	symtab_str = elf_section_list_find_index (slist, symtab->Shdr.sh_link);
	if (symtab_str == NULL) {
		fprintf (stderr, "elf_function_list_create: "
			"binary has no string table for symbol section\n");

		goto bail;
	}

	assert (sec != NULL);

	*count = 0;

	for (n = 0 ; n < symtab->Shdr.sh_size ; n += sizeof (sent)) {
		char *	fname;


		memcpy (&sent, &symtab->data[n], sizeof (sent));

		if (sent.st_shndx != sec->sh_idx)
			continue;

		if (ELF32_ST_TYPE (sent.st_info) != STT_FUNC) {
			if (ELF32_ST_TYPE (sent.st_info) != STT_NOTYPE)
				continue;
			if (ELF32_ST_BIND (sent.st_info) == STB_LOCAL)
				continue;

			if (sent.st_size == 0) {
				/* TODO: further filtering */
			}
		}


		/* STT_FUNC is the obvious case, the other is for broken
		 * manually written functions
		 */
		if ((ELF32_ST_TYPE (sent.st_info) != STT_NOTYPE ||
		/*	ELF32_ST_BIND (sent.st_info) != STB_GLOBAL || */
			sent.st_size != 0) &&
			ELF32_ST_TYPE (sent.st_info) != STT_FUNC)
			continue;

		/* gcc_compiled. is weird: local, no type, .text, val/size 0 */
		if (ELF32_ST_TYPE (sent.st_info) == STT_NOTYPE &&
			sent.st_value == 0 && sent.st_size == 0 &&
			ELF32_ST_BIND (sent.st_info) == STB_LOCAL)
			continue;

		fname = elf_string (symtab_str, sent.st_name);

		swork = elf_section_list_find_index (slist, sent.st_shndx);
		if (swork == NULL) {
			fprintf (stderr, "elf_function_list_create: "
				"FATAL: failed to locate section "
				"of \"%s\"\n", fname);

			goto bail2;
		}

		fwork = ia32_func_new ();
		fwork->name = fname;
		fwork->section_idx = sec->sh_idx;
		fwork->mem = (unsigned char *)(((unsigned int) sent.st_value -
			(unsigned int) swork->Shdr.sh_addr));
		fwork->mem += (unsigned int) swork->data;
		fwork->start = sent.st_value;
		fwork->end = sent.st_value + sent.st_size;
#if 0
		printf ("%-32s | %-12s | 0x%08x - 0x%08x (0x%08x)\n",
			fwork->name, elf_section_name (elf,
				elf_section_list_find_index (slist,
					sent.st_shndx)),
			fwork->start, fwork->end,
			(unsigned int) sent.st_size);
#endif

		/* sanity check
		 */
		if (ia32_trace_range (swork->Shdr.sh_addr,
			swork->Shdr.sh_addr + swork->Shdr.sh_size,
			fwork->start) == 0 ||
			ia32_trace_range (swork->Shdr.sh_addr,
			swork->Shdr.sh_addr + swork->Shdr.sh_size + 1,
			fwork->end) == 0)
		{
			fprintf (stderr, "elf_function_list_create: "
				"dumbnut function \"%s\" out of section "
				"\"%s\" boundaries, b00!\n", 
				fwork->name, elf_section_name (elf,
					elf_section_list_find_index (slist,
					sent.st_shndx)));
			free (fwork);

		/* we are only interested in real functions, i.e. those that
		 * are alive in the dead image ;)
		 */
		} else if (swork->Shdr.sh_type != SHT_PROGBITS) {
			free (fwork);

		/* yeah, found what we looked for, so lets pile it up
		 */
		} else {
			*count += 1;
			flist = xrealloc (flist,
				*count * sizeof (ia32_function *));
			flist[*count - 1] = fwork;
		}
	}

	elf_function_list_sort (flist, *count);


#ifdef	DEBUG
	printf ("\nsorted\n");
	for (n = 0 ; n < *count ; ++n) {
		fwork = flist[n];

		printf ("%-32s | %-12s | 0x%08x - 0x%08x\n",
			fwork->name, elf_section_name (elf,
				elf_section_list_find_index (slist,
					sent.st_shndx)),
			fwork->start, fwork->end);
	}
#endif

	return (flist);

	/* failure exception trunk
	 */
bail2:	if (flist != NULL) {
		for (n = 0 ; n < *count ; ++n)
			free (flist[n]);
	}

bail:
	return (NULL);
}


void
elf_function_list_sort (ia32_function **flist, unsigned int flist_count)
{
	unsigned int	n;
	unsigned int	waddr;	/* walking address */


	/* catch the quicksort worst case, so one can call this function
	 * without worries.
	 */
	waddr = 0;
	for (n = 0 ; n < flist_count ; ++n) {
		if (flist[n]->start < waddr)
			break;

		waddr = flist[n]->start;
	}

	if (n == flist_count)
		return;

	qsort (flist, flist_count, sizeof (flist[0]),
		elf_function_list_create_compar);
}


static int
elf_function_list_create_compar (const void *el1, const void *el2)
{
	ia32_function *	f1 = ((ia32_function **) el1)[0];
	ia32_function *	f2 = ((ia32_function **) el2)[0];

	if (f1->start < f2->start)
		return (-1);
	if (f1->start > f2->start)
		return (1);

	return (0);
}

