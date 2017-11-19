/* libxelf - relocation abstraction module
 *
 * by scut / teso
 */

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <common.h>
#include <elf_reloc.h>
#include <elf_symbol.h>
#include <elf_util.h>


#define	RELOC_HASH(relofs,buckets) ((relofs) % (buckets))

elf_reloc *
elf_reloc_list_lookup (elf_reloc_list *rel, unsigned int vaddr_loc)
{
	unsigned int	n;


	if (rel == NULL)
		return (NULL);

	if (rel->reloc_hash_buckets != 0) {
		elf_reloc_hl *	hwlk;	/* hash walker */

		hwlk = rel->reloc_hash
			[RELOC_HASH (vaddr_loc, rel->reloc_hash_buckets)];
		while (hwlk != NULL) {
			if (hwlk->rel_e->offset_rel == vaddr_loc)
				return (hwlk->rel_e);

			hwlk = hwlk->next;
		}

		return (NULL);
	}

	for (n = 0 ; rel != NULL && n < rel->reloc_count ; ++n) {
		if (vaddr_loc == rel->reloc[n]->offset_rel) {
			return (rel->reloc[n]);
		}
	}

	return (NULL);
}


void
elf_reloc_list_hashgen (elf_reloc_list *rel, unsigned int buckets)
{
	unsigned int	rn,	/* linear relocation walker */
			rhash;	/* hash value of relocation entry */
	elf_reloc *	rel_e;
	elf_reloc_hl *	rel_h;


	if (rel == NULL)
		return;

	assert (rel->reloc_hash_buckets == 0 && rel->reloc_hash == NULL);

	if (rel->reloc_count == 0)
		return;

	/* TODO: find a more optimal tradeoff
	 */
	if (buckets == 0)
		buckets = rel->reloc_count;

	rel->reloc_hash = xcalloc (buckets, sizeof (elf_reloc_hl *));
	rel->reloc_hash_buckets = buckets;

	for (rn = 0 ; rn < rel->reloc_count ; ++rn) {
		rel_e = rel->reloc[rn];
		rhash = RELOC_HASH (rel_e->offset_rel, buckets);

		/* printf ("RH: hash (0x%08x) = into %d of %d buckets\n",
			rel_e->offset_rel, rhash, buckets); */
		rel_h = xcalloc (1, sizeof (elf_reloc_hl));
		rel_h->rel_e = rel_e;
		rel_h->next = rel->reloc_hash[rhash];
		rel->reloc_hash[rhash] = rel_h;
	}

	return;
}

unsigned int
elf_reloc_list_lookup_func (elf_reloc_list *rel, unsigned int vaddr)
{
	unsigned int	n;


	if (rel == NULL)
		return (0xffffffff);


	if (rel->reloc_hash_buckets != 0) {
		elf_reloc_hl *	hwlk;

		hwlk = rel->reloc_hash
			[RELOC_HASH (vaddr, rel->reloc_hash_buckets)];
		while (hwlk != NULL) {
			if (hwlk->rel_e->offset_rel == vaddr &&
				hwlk->rel_e->type == ELF_RELOC_FUNCTION &&
				hwlk->rel_e->func != NULL)
			{
				return (hwlk->rel_e->func->start);
			}

			hwlk = hwlk->next;
		}

		return (0xffffffff);
	}

	for (n = 0 ; n < rel->reloc_count ; ++n) {
		if (vaddr == rel->reloc[n]->offset_rel &&
			rel->reloc[n]->type == ELF_RELOC_FUNCTION &&
			rel->reloc[n]->func != NULL)
		{
			return (rel->reloc[n]->func->start);
		}
	}

	return (0xffffffff);
}


void
elf_reloc_list_debug (elf_reloc_list *rel, unsigned int vaddr)
{
	unsigned int	n;

	assert (rel != NULL);
	/*fprintf (stderr, "RELOC DEBUG: searching for relocations at 0x%08x\n",
		vaddr);*/

	if (rel->reloc_hash_buckets != 0) {
		elf_reloc_hl *	hwlk;

		hwlk = rel->reloc_hash
			[RELOC_HASH (vaddr, rel->reloc_hash_buckets)];

		while (hwlk != NULL) {
			const char *	rel_str[] = {
				"?INVALID?", "ELF_RELOC_SECTION",
				"ELF_RELOC_FUNCTION", "ELF_RELOC_EXTERNAL", };

			if (hwlk->rel_e->offset_rel != vaddr) {
				hwlk = hwlk->next;
				continue;
			}

			/*fprintf (stderr, "== 0x%x: RELOCATION: %s", vaddr,
				rel_str[hwlk->rel_e->type]);*/

			/*
			if (hwlk->rel_e->type == ELF_RELOC_FUNCTION) {
				if (hwlk->rel_e->func != NULL)
					fprintf (stderr, ", function at 0x%08x\n",
						hwlk->rel_e->func->start);
				else
					fprintf (stderr, ", function NULL\n");
			} else
				fprintf (stderr, "\n");
			*/

			hwlk = hwlk->next;
		}

		return;
	}

	for (n = 0 ; n < rel->reloc_count ; ++n) {
		const char *	rel_str[] = {
			"?INVALID?", "ELF_RELOC_SECTION",
			"ELF_RELOC_FUNCTION", "ELF_RELOC_EXTERNAL", };

		if (rel->reloc[n]->offset_rel != vaddr)
			continue;

		fprintf (stderr, "== 0x%x: RELOCATION: %s", vaddr,
			rel_str[rel->reloc[n]->type]);

		if (rel->reloc[n]->type == ELF_RELOC_FUNCTION) {
			if (rel->reloc[n]->func != NULL)
				fprintf (stderr, ", function at 0x%08x\n",
					rel->reloc[n]->func->start);
			else
				fprintf (stderr, ", function NULL\n");
		} else
			fprintf (stderr, "\n");
	}
}

elf_reloc_list *
elf_reloc_list_create (elf_base *base, elf_rel_list *secrel,
	ia32_function **flist, unsigned int flist_count)
{
	unsigned int		n;
	elf_reloc_list *	new;
	elf_reloc *		relnew,
				rel;


	if (secrel == NULL)
		return (NULL);

	new = xcalloc (1, sizeof (elf_reloc_list));

	new->reloc_section = secrel->reloc_section;
	new->reloc_modify = secrel->reloc_modify;
	new->reloc_count = 0;
	new->reloc = NULL;

	for (n = 0 ; n < secrel->reloc_count ; ++n) {
		memset (&rel, 0x00, sizeof (rel));

		memcpy (&rel.orig, &secrel->reloc[n], sizeof (Elf32_Rel));

		switch (ELF32_R_TYPE (secrel->reloc[n].r_info)) {

		/* usually section references, section offset + addend
		 */
		case (R_386_32):
			rel.offset_rel = secrel->reloc[n].r_offset;
			ia32_decode_value (&secrel->reloc_modify->data
				[rel.offset_rel], IA32_WIDTH_WORD,
				&rel.addend);

			rel.sym = elf_sym_fetch_byindex (base,
				ELF32_R_SYM (secrel->reloc[n].r_info));

			if (rel.sym == NULL)
				;
			break;

		/* usually function references, section + addend + position */
		case (R_386_PC32):
			rel.offset_rel = secrel->reloc[n].r_offset;
			ia32_decode_value (&secrel->reloc_modify->data
				[rel.offset_rel], IA32_WIDTH_WORD,
				&rel.addend);

			rel.sym = elf_sym_fetch_byindex (base,
				ELF32_R_SYM (secrel->reloc[n].r_info));

			if (rel.sym == NULL)
				continue;

			if (flist == NULL)
				continue;

			/* all relocations have to be within the current
			 * sections context. for .text we assume its a
			 * function definition then. ugly, but required for
			 * broken libraries, such as dietlibc
			 *
			 * for undefined sections (external references), we
			 * make an exception. XXX: is this ok?
			 */
			/* FIXME:SEC
			if (rel.sym->sent.st_shndx != SHN_UNDEF &&
				rel.sym->sent.st_shndx !=
				secrel->reloc_modify->sh_idx)
				continue;
			*/

			/* kludge: for "functions" like __unified_syscall in
			 *         dietlibc, which do not have a proper symbol
			 * table entry, we use this heuristics. otherwise, in
			 * the obvious case of this being a function symbol,
			 * find appropiate function.
			 */
			if ((ELF32_ST_TYPE (rel.sym->sent.st_info) == STT_NOTYPE &&
		/*		ELF32_ST_BIND (rel.sym->sent.st_info) == STB_GLOBAL && */
				rel.sym->sent.st_size == 0) ||
				ELF32_ST_TYPE (rel.sym->sent.st_info) == STT_FUNC)
			{
				unsigned int	destaddr;

				destaddr = elf_sym_addr (rel.sym);
#ifdef	DYN_LINKER_WOULD_DO_THIS
				destaddr += rel.addend;
				destaddr -= rel.offset_rel;
#endif

				if (rel.sym->sent.st_shndx == SHN_UNDEF) {
					rel.func = NULL;
				} else {
					rel.func = elf_function_list_find
						(flist, flist_count, destaddr);

					if (rel.func == NULL) {
						elf_error (base->elf, "failed to "
							"locate at destaddr 0x%08x",
							destaddr);

						exit (EXIT_FAILURE);
					}
				}

				rel.type = ELF_RELOC_FUNCTION;
			} else if (ELF32_ST_TYPE (rel.sym->sent.st_info)
				== STT_SECTION)
			{
				/* could still mean it relocates a function
				 * offset, just that it does it through a
				 * section start, not within the section
				 * itself. this is most likely an
				 * inter-section call, such as from
				 * .init:_init to some .text function.
				 */
				rel.type = ELF_RELOC_SECTION;
				rel.func = NULL;
			}

			break;

		default:
			continue;
		}

		relnew = xcalloc (1, sizeof (elf_reloc));
		memcpy (relnew, &rel, sizeof (elf_reloc));

		new->reloc_count += 1;
		new->reloc = xrealloc (new->reloc, new->reloc_count *
			sizeof (elf_reloc *));
		new->reloc[new->reloc_count - 1] = relnew;
	}

	return (new);
}


void
elf_reloc_list_destroy (elf_reloc_list *list)
{
	if (list->reloc != NULL)
		free (list->reloc);

	if (list->reloc_hash != NULL)
		free (list->reloc_hash);

	free (list);
}


elf_rel_list *
elf_rel_list_find_byname (elf_rel_list *rel, char *name)
{
	while (rel != NULL) {
		if (rel->reloc_section->name != NULL &&
			strcmp (rel->reloc_section->name, name) == 0)
		{
			return (rel);
		}

		rel = rel->next;
	}

	return (NULL);
}


elf_rel_list *
elf_rel_list_find_bymodsection (elf_rel_list *rel, elf_section *sec)
{
	while (rel != NULL) {
		if (memcmp (&rel->reloc_modify->Shdr, &sec->Shdr,
			sizeof (sec->Shdr)) == 0)
		{
			return (rel);
		}

		rel = rel->next;
	}

	return (NULL);
}


elf_rel_list *
elf_rel_list_find_byrelsection (elf_rel_list *rel, elf_section *sec)
{
	while (rel != NULL) {
		if (memcmp (&rel->reloc_section->Shdr, &sec->Shdr,
			sizeof (sec->Shdr)) == 0)
		{
			return (rel);
		}

		rel = rel->next;
	}

	return (NULL);
}


elf_rel_list *
elf_rel_list_create (elf_base *base)
{
	unsigned int	n;
	elf_section *	srel;	/* one relocation section */

	elf_rel_list *	root = NULL;
	elf_rel_list *	last = NULL;
	elf_rel_list *	cur;


	for (n = 0 ; n < base->elf->Ehdr.e_shnum ; ++n) {
		if (base->elf->Shdr[n].sh_type != SHT_REL)
			continue;

		srel = elf_section_list_find_index (base->seclist, n);

#ifdef DEBUG
		fprintf (stderr, "rel section: \"%s\", idx %lu, len %lu\n",
			srel->name == NULL ? "__unknown" : srel->name,
			srel->sh_idx, srel->data_len);
#endif

		/* create new list element and link it into the main list
		 */
		cur = xcalloc (1, sizeof (elf_rel_list));
		if (root == NULL)
			root = cur;

		if (last == NULL) {
			last = root;
		} else {
			last->next = cur;
			last = cur;
		}

		/* set values, sh_link being the symbol-, sh_info the modified
		 * section
		 */
		cur->reloc_section = srel;
		cur->reloc_symbol =
			elf_section_list_find_index (base->seclist,
				srel->Shdr.sh_link);
		cur->reloc_modify =
			elf_section_list_find_index (base->seclist,
				srel->Shdr.sh_info);
		cur->reloc_count = srel->data_len / sizeof (Elf32_Rel);
		cur->reloc = (Elf32_Rel *) srel->data;

#ifdef DEBUG
		fprintf (stderr, "\tsh_link = \"%s\", sh_info = \"%s\"\n",
			cur->reloc_symbol->name, cur->reloc_modify->name);
		fprintf (stderr, "\tentries = %u\n", cur->reloc_count);
#endif
	}

	return (root);
}


