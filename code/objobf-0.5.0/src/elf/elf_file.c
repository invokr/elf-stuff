/* libxelf - elf_file access routines
 *
 * by scut / teso
 */

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>

#include <common.h>
#include <elf_file.h>
#include <elf_verify.h>
#include <elf_util.h>


elf_file *
elf_file_new (void)
{
	elf_file *	new = xcalloc (1, sizeof (elf_file));

	return (new);
}


void
elf_file_destroy (elf_file *elf)
{
	if (elf == NULL)
		return;

	if (elf->pathname != NULL)
		free (elf->pathname);

	if (elf->fp != NULL)
		fclose (elf->fp);

	if (elf->Phdr != NULL)
		free (elf->Phdr);

	if (elf->Shdr != NULL)
		free (elf->Shdr);

	if (elf->sh_str != NULL)
		free (elf->sh_str);

	free (elf);

	return;
}


elf_file *
elf_file_load (char *pathname)
{
	elf_file *	new;


	new = elf_file_new ();

	new->fp = fopen (pathname, "rb");
	if (new->fp == NULL) {
		elf_error (NULL, "cannot open file: %s", pathname);
		goto bail;
	}

	/* allocate and setup new ELF description structure
	 */
	new->pathname = xstrdup (pathname);

	/* read in ELF header
	 */
	if (fread (&new->Ehdr, sizeof (new->Ehdr), 1, new->fp) != 1) {
		elf_error (new, "failed to read ELF header");
		goto bail;
	}

	if (elf_verify_header (new)) {
		elf_error (new, "invalid ELF header");
		goto bail;
	}

	/* read program header table
	 */
	new->Phdr = xcalloc (new->Ehdr.e_phnum, new->Ehdr.e_phentsize);
	if (fseek (new->fp, new->Ehdr.e_phoff, SEEK_SET) != 0) {
		elf_error (new, "failed to seek to ELF program header table at 0x%08x",
			new->Ehdr.e_phoff);
		goto bail;
	}
	if (fread (new->Phdr, new->Ehdr.e_phentsize, new->Ehdr.e_phnum,
		new->fp) != new->Ehdr.e_phnum)
	{
		elf_error (new, "failed to read ELF program header table");
		goto bail;
	}

	/* read section header table
	 */
	new->Shdr = xcalloc (new->Ehdr.e_shnum, new->Ehdr.e_shentsize);
	if (fseek (new->fp, new->Ehdr.e_shoff, SEEK_SET) != 0) {
		elf_error (new, "failed to seek to ELF section header table at 0x%08x",
			new->Ehdr.e_shoff);
		goto bail;
	}
	if (fread (new->Shdr, new->Ehdr.e_shentsize, new->Ehdr.e_shnum,
		new->fp) != new->Ehdr.e_shnum)
	{
		elf_error (new, "failed to read ELF section header table");
		goto bail;
	}

	/* read section header string table, if available
	 * XXX: this has to be done before any other section operations are
	 *      done to set section->name correctly. -sc
	 */
	if (new->Ehdr.e_shstrndx == SHN_UNDEF)
		return (new);

	if (fseek (new->fp, new->Shdr[new->Ehdr.e_shstrndx].sh_offset,
		SEEK_SET) != 0)
	{
		elf_error (new, "failed to seek to ELF string table section at 0x%08x",
			new->Shdr[new->Ehdr.e_shstrndx].sh_offset);
		goto bail;
	}
#ifdef DEBUG
	fprintf (stderr, "ELF section string table: %2d. at 0x%08lx\n",
		new->Ehdr.e_shstrndx,
		(unsigned long int) new->Shdr[new->Ehdr.e_shstrndx].sh_offset);
#endif

	new->sh_str_len = new->Shdr[new->Ehdr.e_shstrndx].sh_size;
	new->sh_str = xcalloc (1, new->sh_str_len);

	if (fread (new->sh_str, 1, new->sh_str_len, new->fp) !=
		new->sh_str_len)
	{
		elf_error (new, "failed to read ELF section string table");
		goto bail;
	}

	return (new);

bail:
	elf_file_destroy (new);

	return (NULL);
}


