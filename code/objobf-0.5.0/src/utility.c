/* utility.c - burneye2 supporting functions
 *
 * by scut
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>

#include <utility.h>

int	quiet = 0;
int	rand_fd = -1;


int
fnote (const char *fmt, ...)
{
	int	len;
	va_list	ap;


	if (quiet)
		return (0);

	va_start (ap, fmt);
	len = vfprintf (stderr, fmt, ap);
	va_end (ap);

	return (len);
}


void
be_randinit_file (const char *filename)
{
	if (rand_fd != -1)
		return;

	rand_fd = open (filename, 0);
	if (rand_fd < 0)
		exit (EXIT_FAILURE);
}

void
be_randinit (void)
{
	be_randinit_file ("/dev/urandom");
}


void
be_randend (void)
{
	close (rand_fd);
	rand_fd = -1;
}


unsigned int
be_random (unsigned int max)
{
	ssize_t		nret;
	unsigned int	tmp;


	if (rand_fd == -1)
		be_randinit ();

	nret = read (rand_fd, &tmp, sizeof (tmp));
	if (nret != sizeof (tmp)) {
		if (nret < 0)
			perror ("be_random, read random-file");
		else
			fprintf (stderr, "be_random, random data depleted\n");

		exit (EXIT_FAILURE);
	}

	/* 0 denotes special 0 to 2^32 - 1 range
	 */
	if (max == 0)
		return (tmp);

	return (tmp % max);
}


int
be_random_coin (double prob)
{
	double	rand;

	rand = (double) be_random (UINT_MAX);
	rand /= (double) UINT_MAX;
	if (rand <= prob)
		return (1);

	return (0);
}


unsigned int
be_random_prob (unsigned int items_count, double *items_prob)
{
	double		sum = 0.0,
			rand;
	unsigned int	in;

	for (in = 0 ; in < items_count ; ++in)
		sum += items_prob[in];

	in = be_random (UINT_MAX);
	rand = in;
	rand /= (double) UINT_MAX;
	rand *= sum;

	sum = 0.0;
	for (in = 0 ; sum < rand && in < items_count ; ++in)
		sum += items_prob[in];

	if (in > 0)
		in -= 1;

	return (in);
}


