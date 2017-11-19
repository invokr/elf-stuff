
#include <sys/time.h>
#include <netinet/in.h>
#include <time.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "common.h"


#ifdef	DEBUG
void
debugp (char *filename, const char *str, ...)
{
	FILE		*fp;	/* temporary file pointer */
	va_list		vl;

	fp = fopen (filename, "a");
	if (fp == NULL)
		return;

	va_start (vl, str);
	vfprintf (fp, str, vl);
	va_end (vl);

	fclose (fp);

	return;
}

void
hexdump (char *filename, unsigned char *data, unsigned int amount)
{
	FILE		*fp;	/* temporary file pointer */
	unsigned int	dp, p;	/* data pointer */
	const char	trans[] =
		"................................ !\"#$%&'()*+,-./0123456789"
		":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
		"nopqrstuvwxyz{|}~...................................."
		"....................................................."
		"........................................";

	fp = fopen (filename, "a");
	if (fp == NULL)
		return;

	fprintf (fp, "\n-packet-\n");

	for (dp = 1; dp <= amount; dp++) {
		fprintf (fp, "%02x ", data[dp-1]);
		if ((dp % 8) == 0)
			fprintf (fp, " ");
		if ((dp % 16) == 0) {
			fprintf (fp, "| ");
			p = dp;
			for (dp -= 16; dp < p; dp++)
				fprintf (fp, "%c", trans[data[dp]]);
			fflush (fp);
			fprintf (fp, "\n");
		}
		fflush (fp);
	}
	if ((amount % 16) != 0) {
		p = dp = 16 - (amount % 16);
		for (dp = p; dp > 0; dp--) {
			fprintf (fp, "   ");
			if (((dp % 8) == 0) && (p != 8))
				fprintf (fp, " ");
			fflush (fp);
		}
		fprintf (fp, " | ");
		for (dp = (amount - (16 - p)); dp < amount; dp++)
			fprintf (fp, "%c", trans[data[dp]]);
		fflush (fp);
	}
	fprintf (fp, "\n");

	fclose (fp);
	return;
}

#endif


void *
xrealloc (void *m_ptr, size_t newsize)
{
	void	*n_ptr;

	n_ptr = realloc (m_ptr, newsize);
	if (n_ptr == NULL && newsize != 0) {
		fprintf (stderr, "realloc failed\n");
		assert (0);

		exit (EXIT_FAILURE);
	}

	return (n_ptr);
}


char *
xstrdup (char *str)
{
	char	*b;

	b = strdup (str);
	if (b == NULL) {
		fprintf (stderr, "strdup failed\n");
		exit (EXIT_FAILURE);
	}

	return (b);
}


void *
xcalloc (int factor, size_t size)
{
	void	*bla;

	bla = calloc (factor, size);

	if (bla == NULL) {
		fprintf (stderr, "no memory left\n");
		assert (0);
		exit (EXIT_FAILURE);
	}

	return (bla);
}


unsigned int
array_compaction (void *arr_ptr, unsigned int el_count)
{
	unsigned int	sidx,	/* source index */
			didx;	/* destination index */
	char **		arr = (char **) arr_ptr;

	for (sidx = 0, didx = 0 ; sidx < el_count ; ++sidx) {
		if (arr[sidx] == NULL)
			continue;

		arr[didx] = arr[sidx];
		didx += 1;
	}

	return (didx);
}


