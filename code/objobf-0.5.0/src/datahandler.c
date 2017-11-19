/* datahandler.c - burneye2 .rodata/.data handling functions
 *
 * by scut
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <elf.h>

#include <common.h>
#include <utility.h>
#include <elf_reloc.h>
#include <elf_section.h>
#include <datahandler.h>


data_item *
dh_item_new (void)
{
	return (xcalloc (1, sizeof (data_item)));
}


data_item *
dh_item_list_create_bysymreloc (elf_base *base, elf_section *datasec,
	elf_rel_list *rel)
{
	unsigned int	n,
			sym_size;
	data_item *	dh = dh_item_new ();


	/* start with a section-sized item that is dangling, then carve the
	 * used space out of it incrementally
	 */
	dh->dangling = 1;
	dh->offset = 0;
	dh->length = datasec->Shdr.sh_size;

	/* first carve the 100% known symbol table entries
	 */
	sym_size = base->symtab->data_len / sizeof (Elf32_Sym);
	for (n = 0 ; n < sym_size ; ++n) {
		elf_symbol *	sym;

		sym = elf_sym_fetch_byindex (base, n);
		assert (sym != NULL);

		if (sym->sec == NULL || sym->sec->sh_idx != datasec->sh_idx) {
			free (sym);

			continue;
		}

		fnote ("item: %s\n", sym->name);
		if (sym->sent.st_size == 0) {
			fnote ("  size is zero, skipping.\n");
			continue;
		}

		assert (sym->sent.st_value < datasec->data_len);
		dh = dh_carve (dh, sym->sent.st_value, sym->sent.st_size,
			&datasec->data[sym->sent.st_value]);
		assert (dh != NULL);
	}
 

#if 0
	/* search for correct relocation frame in list
	 */
	while (rel != NULL) {
		if (rel->reloc_modify->sh_idx == datasec->sh_idx)
			break;

		rel = rel->next;
	}

	for (n = 0 ; n < rel->reloc_count ; ++n) {
	}
#endif

	return (dh);
}


data_item *
dh_carve (data_item *dh, unsigned int offset, unsigned int length,
	unsigned char *data)
{
	data_item *	ret = dh;
	data_item *	wlk;
	data_item *	wlk_last = NULL;
	data_item *	new;


	for (wlk = dh ; wlk != NULL ; wlk = wlk->next) {
		/* ignore space already given to someone else or blocks that
		 * do not cover our range
		 */
		if (wlk->dangling == 0 ||
			(wlk->offset + wlk->length) < (offset + length))
		{
			wlk_last = wlk;
			continue;
		}

		/* since we know the list is ordered we can safely abort once
		 * we are past our offset
		 */
		if (wlk->offset > offset)
			break;

		/* now we've found the block we have to cut
		 */
		if (wlk->offset < offset) {
			data_item *	nbf = dh_item_new ();

			nbf->offset = wlk->offset;
			nbf->length = offset - wlk->offset;
			nbf->dangling = 1;
			nbf->data = wlk->data;
			nbf->next = wlk;

			if (wlk_last == NULL)
				ret = nbf;
			else
				wlk_last->next = nbf;

			wlk_last = nbf;
			wlk->offset += nbf->length;
			wlk->length -= nbf->length;
			wlk->data += nbf->length;
		}

		assert (wlk->offset == offset);

		new = dh_item_new ();
		new->next = wlk;
		new->offset = offset;
		new->length = length;
		new->data = wlk->data;

		wlk->length -= length;
		wlk->offset = offset + length;
		wlk->data += length;

		if (wlk->length == 0) {
			new->next = wlk->next;
			free (wlk);
		}

		if (wlk_last == NULL)
			ret = new;
		else
			wlk_last->next = new;

		return (ret);
	}

	return (NULL);
}


