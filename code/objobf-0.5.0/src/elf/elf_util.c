/* libxelf - helper functions
 *
 * by scut / teso
 */

#include <stdio.h>
#include <stdarg.h>

#include <elf_file.h>
#include <elf_util.h>


void
elf_error (elf_file *elf, const char *str, ...)
{
	va_list		vl;

	if (elf == NULL || elf->pathname == NULL) {
		fprintf (stderr, "?: ");
	} else {
		fprintf (stderr, "%s: ", elf->pathname);
	}

	va_start (vl, str);
	vfprintf (stderr, str, vl);
	va_end (vl);

	fprintf (stderr, "\n");

	return;
}


