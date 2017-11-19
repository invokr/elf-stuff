/* libxelf - elf_verify ELF verification routines include file
 *
 * by scut / teso
 */

#ifndef	ELF_VERIFY_H
#define	ELF_VERIFY_H


/* elf_verify_header
 *
 * a basic verification of the ELF header contained in the `elf' structure. no
 * active checks, just sanity of the values.
 *
 * return 0 in case verification is ok
 * return != 0 in case it is invalid
 */

int
elf_verify_header (elf_file *elf);

#endif


