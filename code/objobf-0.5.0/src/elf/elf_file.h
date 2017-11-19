/* libxelf - elf_file access routines include file
 *
 * by scut / teso
 */

#ifndef	ELF_FILE_H
#define	ELF_FILE_H

#include <elf.h>
#include <stdio.h>


/* core structure that represents an entire ELF file
 */
typedef struct {
	char *		pathname;
	FILE *		fp;

	Elf32_Ehdr	Ehdr;
	Elf32_Phdr *	Phdr;
	Elf32_Shdr *	Shdr;

	/* ELF section string table
	 * not loaded if sh_str is NULL. use elf_str_hdr to look them up.
	 */
	unsigned long int	sh_str_len;
	unsigned char *		sh_str;
} elf_file;

#include <elf_section.h>


/* elf_file_new
 *
 * allocate a new elf_file structure and set default values
 *
 * return a pointer to the new structure
 */

elf_file *
elf_file_new (void);


/* elf_file_destroy
 *
 * destroy an elf_file structure `elf', completely freeing any resources
 * it occupied.
 *
 * return in any case
 */

void
elf_file_destroy (elf_file *elf);


/* elf_load
 *
 * load an ELF file from `pathname' into an elf_file parse tree
 *
 * return parse tree on success
 * return NULL on failure
 */

elf_file *
elf_file_load (char *pathname);

#endif


