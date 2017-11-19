/* libxelf - symbol information abstraction module
 *
 * by scut / teso
 */

#ifndef	ELF_SYMBOL_H
#define	ELF_SYMBOL_H

#include <elf.h>

#include <elf_base.h>
#include <elf_section.h>


/* elf_symbol structure that can be used as linked list
 */
typedef struct elf_symbol {
	char *			name;

	/* section this symbol relates to
	 */
	elf_section *		sec;

	Elf32_Sym		sent;
} elf_symbol;


/* elf_sym_addr
 *
 * return address the symbol `sym' is refering to
 */

unsigned int
elf_sym_addr (elf_symbol *sym);


/* elf_sym_fetch_byindex
 *
 * fetch a symbol with index `symidx' from the elf file `base' structure
 *
 * return pointer to elf_symbol structure on success
 * return NULL on failure (out of bounds symidx)
 */

elf_symbol *
elf_sym_fetch_byindex (elf_base *base, unsigned int symidx);


/* elf_string
 *
 * locate the string at `offset' within the string table `strtab', doing range
 * checks.
 *
 * return the pointer to the string on success
 * return "__unknown_str" pointer on mishit or if string table is NULL
 * abort on fatal failure (out of range)
 */

char *
elf_string (elf_section *strtab, unsigned int offset);

#endif

