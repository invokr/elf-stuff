/* ia32-debug.c - ia32 debug output functionality
 *
 * by scut
 */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include <ia32-debug.h>


int	ia32_verbosity = 1;
int	ia32_confirm_all = 0;


int
ia32_verbose (int vlevel)
{
	if (vlevel > ia32_verbosity)
		return (0);

	return (1);
}


int
ia32_debug (int vlevel, const char *fmt, ...)
{
	int	len;
	va_list	ap;


	if (ia32_verbose (vlevel) == 0)
		return (0);

	va_start (ap, fmt);
	len = vfprintf (stderr, fmt, ap);
	va_end (ap);

	return (len);
}


void
ia32_confirm (void)
{
	char	rdummy[2];

	fprintf (stderr, "CONFIRM: press return");
	if (ia32_confirm_all) {
		fprintf (stderr, "\n");
		return;
	}

	read (0, rdummy, 1);
}


