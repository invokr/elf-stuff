/* libxelf - elf_verify ELF verification routines
 *
 * by scut / teso
 */

#include <elf.h>
#include <stdlib.h>
#include <string.h>

#include <elf_file.h>
#include <elf_verify.h>
#include <elf_util.h>


int
elf_verify_header (elf_file *elf)
{
	unsigned char	e_ident[EI_NIDENT] = {
		ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,	/* FIXED */
		ELFCLASS32, ELFDATA2LSB,		/* x86 dependant */
		EV_CURRENT,				/* ELF version dependant */
		0, 0, 0, 0, 0,				/* ELF version dependant */
		0, 0, 0, 0 };


	if (memcmp (&elf->Ehdr.e_ident[0], e_ident, EI_NIDENT) != 0) {
		elf_error (elf, "Ehdr.e_ident not as expected");
		return (1);
	}

#if 0
	if (elf->Ehdr.e_type != ET_EXEC) {
		elf_error (elf, "Ehdr.e_type is not ET_EXEC");
		return (1);
	}
#endif

	if (elf->Ehdr.e_machine != EM_386) {
		elf_error (elf, "Ehdr.e_machine is not EM_386");
		return (1);
	}

	if (elf->Ehdr.e_version != EV_CURRENT) {
		elf_error (elf, "Ehdr.e_version is not EV_CURRENT");
		return (1);
	}

#if 0
	if (elf->Ehdr.e_phoff == 0 || elf->Ehdr.e_phnum == 0 ||
		elf->Ehdr.e_phentsize != sizeof (Elf32_Phdr))
	{
		elf_error (elf, "Ehdr.e_phoff is zero");
		return (1);
	}
#endif

	return (0);
}

