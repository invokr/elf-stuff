/* sha-1 implementation
 *
 * by steve reid <steve@edmweb.com>
 * modified by scut
 *
 * include file
 */

#ifndef CIPHER_SHA1_H
#define	CIPHER_SHA1_H


/* SHA1Hash
 *
 * hash an binary string `data' with `data_len' bytes into a 20 byte long hash
 * byte buffer pointed to by `hash'
 *
 * return in any case
 */

void	SHA1HashLen (unsigned char *data, unsigned long int data_len,
	unsigned char *hash);


/* SHA1Hash
 *
 * hash an ASCIIZ password into a 20 byte long hash byte buffer
 *
 * return in any case
 */

void	SHA1Hash (char *password, unsigned char *hash);


#endif

