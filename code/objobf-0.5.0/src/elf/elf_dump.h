/* libxelf - elf_dump.h - human representation of ELF files include file
 *
 * by scut / teso
 */

#ifndef	ELF_DUMP_H
#define	ELF_DUMP_H

#include <elf_file.h>


typedef struct {
	int		value;
	char *		name;
} dump_elem;

typedef struct {
	char *			elem_name;	/* struct elem name */
	char *			type;		/* type, a/w/o, h, m */
	unsigned long int	advance;	/* how many bytes */
	unsigned long int	data_val;	/* optional: value */
	dump_elem *		data_tab;	/* optional: decode table */
} dump_header;


/* elf_dump_header
 *
 * dump the Elf32_Ehdr structure of ELF file `elf'
 *
 * return in any case
 */

void
elf_dump_header (elf_file *elf);


/* elf_dump_phtab
 *
 * dump the program header table of ELF file `elf'
 *
 * return in any case
 */

void
elf_dump_phtab (elf_file *elf);


/* elf_dump_shtab
 *
 * dump the section header table of ELF file `elf'
 *
 * return in any case
 */

void
elf_dump_shtab (elf_file *elf);


/* elf_dump_desc
 *
 * dump using dump_header description table `desc', for file `elf', start at
 * `src', not exceeding `len' bytes
 *
 * return in any case
 */

void
elf_dump_desc (elf_file *elf, dump_header *desc, unsigned char *src,
	unsigned long int len);


/* elf_dump_print
 *
 * dump an ELF structure entry associated with file `elf'. dump accordingly
 * to the format string `format'. `formatparam' may be an extra parameter to
 * the format. `entname' is the symbolic structure name, `val' the pointer to
 * the value.
 *
 * return in any case
 *
 * `format' is:
 *	h = Elf32_Half
 *	m = memory (just dump)
 *	a/o/w = Elf32_(Addr|Off|Word)
 *	i = ignore, just advance
 * h and w can be prepended with "f", then formatparam denotes a flagtable.
 * on "m" formatparam contains the number of bytes to dump. every other case
 * can have NULL as formatparam. if it has non-NULL symbols are looked up
 * through it.
 * everything can be prepended with "s", which shortens output as much as
 * possible, also omitting a newline
 */

void
elf_dump_print (elf_file *elf, char *format, void *formatparam, char *entname,
	unsigned char *val);


/* elf_dump_tablookup
 *
 * lookup a small integer `val' to its symbolic representation using `table'
 *
 * return static string
 */

char *
elf_dump_tablookup (dump_elem *tab, unsigned long int val);


#endif

