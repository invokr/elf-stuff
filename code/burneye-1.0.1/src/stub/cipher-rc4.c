/* rc4 */

#include "cipher-rc4.h"
#include "cipher-sha1.h"

#ifdef IN_STUB
#include "helper.h"
#else
#include <stdio.h>
#endif


static void swap_byte (unsigned char *a, unsigned char *b);

void
rc4_prepare_key (unsigned char *key_data_ptr, int key_data_len, rc4_key *key)
{
	unsigned char	i1, i2;
	unsigned char	*s;
	short		c;

	s = &key->state[0];
	for (c = 0; c < 256; c++)
		s[c] = c;

	key->x = key->y = 0;
	i1 = i2 = 0;

	for (c = 0; c < 256; c++) {
		i2 = (key_data_ptr[i1] + s[c] + i2) % 256;
		swap_byte (&s[c], &s[i2]);
		i1 = (i1 + 1) % key_data_len;
	}
}


void
rc4_encipher (unsigned char *buffer, unsigned long int buffer_len, char *key)
{
	rc4_key		key_r;
	unsigned char	hash[20];	/* hash of the key */

	if (key == NULL || buffer == NULL || buffer_len == 0)
		return;

	SHA1HashLen (key, strlen (key), hash);
	rc4_prepare_key (hash, sizeof (hash), &key_r);
	rc4_cipher (buffer, buffer_len, &key_r);

	return;
}


void
rc4_cipher (unsigned char *buffer_ptr, int buffer_len, rc4_key *key)
{ 
	unsigned char	x;
	unsigned char	y;
	unsigned char	*state;
	unsigned char	xi;
	unsigned int	counter;
   
	x = key->x;
	y = key->y;
   
	state = &key->state[0];
	for(counter = 0; counter < buffer_len; counter ++) {
		x = (x + 1) % 256;
		y = (state[x] + y) % 256;
		swap_byte(&state[x], &state[y]);
		xi = (state[x] + state[y]) % 256;
		buffer_ptr[counter] ^= state[xi];
	}

	key->x = x;
	key->y = y;
}


static void
swap_byte (unsigned char *a, unsigned char *b)
{
	unsigned char	sb; 

	sb = *a;
	*a = *b;
	*b = sb;
}

