

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "rs.h"


extern unsigned int	KK;

unsigned int
rs_kkcompute (unsigned int n, unsigned int fix);

void
rs_trans (unsigned char *buffer, unsigned long int buf_len,
	unsigned int *trans, unsigned long int trans_len);

void
rs_detrans (unsigned char *buffer, unsigned long int buf_len,
	unsigned int *trans, unsigned long int trans_len);


int
main (int argc, char *argv[])
{
	int		n;
	unsigned char	buffer[6144];
	unsigned int	transform[4096];


	memset (buffer, '\0', sizeof (buffer));
	strcpy (buffer, "This is a test for the Reed Solomon encoder/decoder");
	printf ("before: %s\n", buffer);

	rs_trans (buffer, strlen (buffer), transform, sizeof (transform) /
		sizeof (transform[0]));
	memset (buffer, '\0', sizeof (buffer));

	KK = rs_kkcompute (NN, (36 * 8) / 12 + 1);
	encode_rs (&transform[0], &transform[KK]);

	srandom (time (NULL));
	for (n = 0 ; n < 25 ; ++n) {
		unsigned int	ai;

		do {
			ai = random () % KK;
		} while ((transform[ai] & 0x1000) == 0x1000);

		transform[ai] = (random () & 0x0fff) | 0x1000;
	}
	for (n = 0 ; n < KK ; ++n)
		transform[n] &= ~ 0x1000;

//	printf (" trash: %s\n", buffer);
	n = eras_dec_rs (transform, NULL, 0);

	rs_detrans (buffer, sizeof (buffer), transform, sizeof (transform) /
		sizeof (transform[0]));
	printf ("c (%2d): %s\n", n, buffer);


	exit (EXIT_SUCCESS);
}


/* rs_kkcompute
 *
 * for our fingerprint deviation method we need to go the reverse way in error
 * correction. instead of trying to find the optimum signal-noise/correction
 * ratio, we know exactly how many bytes we want to fix and can guarantee a
 * perfect reliability for our parity check bits. so this is the function that
 * computes the correct KK value for `n' symbols, where we want to be able to
 * fixup up to `fix' symbols.
 *
 * return the correct value for KK
 */

unsigned int
rs_kkcompute (unsigned int n, unsigned int fix)
{
	/* assume sanity of all input values */
	return (n - (2 * fix));
}


void
rs_trans (unsigned char *buffer, unsigned long int buf_len,
	unsigned int *trans, unsigned long int trans_len)
{
	unsigned int	n,
			t;


	memset (trans, '\0', sizeof (trans[0]) * trans_len);
	if (((((buf_len + 1) * 12) / 8)) > trans_len) {
		fprintf (stderr, "translation output size too low\n");
		exit (EXIT_FAILURE);
	}

	/* 8 to 12 bit expander to use 2^12 galois field */
	for (n = 0, t = 0 ; n < buf_len ; ++n) {
		switch (n % 3) {
		case (0):
			trans[t] = buffer[n];
			break;
		case (1):
			trans[t] |= (buffer[n] & 0x0f) << 8;
			trans[t + 1] = buffer[n] >> 4;
			t += 1;
			break;
		case (2):
			trans[t] |= buffer[n] << 4;
			t += 1;
			break;
		}
	}

	return;
}


/* and the reverse (12 to 8 bit)
 */
void
rs_detrans (unsigned char *buffer, unsigned long int buf_len,
	unsigned int *trans, unsigned long int trans_len)
{
	unsigned int	n,
			t;


	memset (buffer, '\0', buf_len);

	if (((trans_len * 12) / 8) > buf_len) {
		fprintf (stderr, "translation output buffer too low\n");
		exit (EXIT_FAILURE);
	}

	for (n = 0, t = 0 ; t < trans_len ; ++t) {
		switch (t % 2) {
		case (0):
			buffer[n] = trans[t] & 0xff;
			buffer[n + 1] = trans[t] >> 8;
			n += 1;
			break;
		case (1):
			buffer[n] |= (trans[t] & 0x0f) << 4;
			buffer[n + 1] = trans[t] >> 4;
			n += 2;
			break;
		}
	}

	return;
}


