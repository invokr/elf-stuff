/* libxelf - symbol information abstraction module
 *
 * by scut / teso
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <common.h>
#include <elf_symbol.h>
#include <elf_util.h>


unsigned int
elf_sym_addr (elf_symbol *sym)
{
	return (sym->sent.st_value);
}


elf_symbol *
elf_sym_fetch_byindex (elf_base *base, unsigned int symidx)
{
	unsigned int	sym_size;
	Elf32_Sym	sym;
	elf_section *	strtab;
	elf_symbol *	new;


	assert (base->symtab != NULL);

	sym_size = base->symtab->data_len / sizeof (Elf32_Sym);
	if (symidx >= sym_size) {
		elf_error (base->elf, "symidx (%u) out of bounds (0-%u)",
			symidx, sym_size - 1);

		return (NULL);
	}

	memcpy (&sym, &base->symtab->data[symidx * sizeof (Elf32_Sym)],
		sizeof (Elf32_Sym));

	strtab = elf_section_list_find_index (base->seclist,
		base->symtab->Shdr.sh_link);
	if (strtab == NULL) {
		elf_error (base->elf, "no string table for symbol table "
			"(sh_idx = %lu)", base->symtab->sh_idx);
	}

	/* allocate and fill structure
	 */
	new = xcalloc (1, sizeof (elf_symbol));
	new->name = elf_string (strtab, sym.st_name);
	memcpy (&new->sent, &sym, sizeof (Elf32_Sym));
	new->sec = elf_section_list_find_index (base->seclist, sym.st_shndx);

	return (new);
}


char *
elf_string (elf_section *strtab, unsigned int offset)
{
	if (strtab == NULL)
		return ("__unknown_str");

	if (offset >= strtab->data_len) {
		elf_error (NULL, "FATAL: offset (0x%08x) out of bounds for "
			"string table \"%s\" (0-0x%08x)",
			offset, (strtab->name == NULL) ? "__unknown" :
			strtab->name, strtab->data_len);

		exit (EXIT_FAILURE);
	}

	return (&strtab->data[offset]);
}


