/* cipher-glfsr.h - galois linear feedback shifting register include file
 *
 * -scut
 */

#ifndef	CIPHER_GLFSR_H
#define	CIPHER_GLFSR_H


/* glfsr_crypt
 *
 * main encryption and decryption function. its a symmetric 32bit key stream
 * cipher. it is not secure, only used here for obfuscation. the same key is
 * used for encryption and decryption.
 * encrypt 'len' bytes from 'src' to 'dst' with key 'key'. 'src' and 'dst' can
 * overlap as they want, only if 'src' >= 'dst'.
 *
 * return in any case
 */

void
glfsr_crypt (unsigned char *dest, unsigned char *src,
	unsigned int len, unsigned int key);

#endif

