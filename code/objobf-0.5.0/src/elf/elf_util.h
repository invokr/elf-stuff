/* libxelf - helper functions include file
 *
 * by scut / teso
 */

#ifndef	ELF_UTIL_H
#define	ELF_UTIL_H


/* elf_error
 *
 * complain about a ELF file associated with structure `elf'. the message
 * we complain with is given as format string in `str'.
 *
 * return in any case
 */

void
elf_error (elf_file *elf, const char *str, ...);

#endif

