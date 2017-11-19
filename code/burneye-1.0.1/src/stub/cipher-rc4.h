
#ifndef	CIPHER_RC4_H
#define	CIPHER_RC4_H

#ifdef IN_STUB
#include "helper.h"
#endif


typedef struct	rc4_key {
	unsigned char	state[256];
	unsigned char	x;
	unsigned char	y;
} rc4_key;


void	rc4_prepare_key (unsigned char *key_data_ptr, int key_data_len, rc4_key *key);
void	rc4_encipher (unsigned char *buffer, unsigned long int buffer_len, char *key);
#define	rc4_decipher rc4_encipher
void	rc4_cipher (unsigned char *buffer_ptr, int buffer_len, rc4_key *key);


#endif

