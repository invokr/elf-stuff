/*
	funcs.c
	Various functions for the stub code in order to avoid libc
	ryan@bitlackeys.com
*/

#include <sys/types.h>

void
_memset (void *dst, unsigned char c, unsigned int len)
{
	unsigned char *p = (unsigned char *) dst;

	while (len--)
		*p++ = c;
}


void *
_memcpy (void *destaddr, void const *srcaddr, size_t len)
{
	char *dest = destaddr;
	char const *src = srcaddr;

	while (len-- > 0)
		*dest++ = *src++;
	return destaddr;
}

int
_strlen (unsigned char *str)
{
	int n = 0;

	while (*str++)
		n++;

	return (n);
}

char *
_strcpy (char *dst, char *src)
{
	while (*src)
		*dst++ = *src++;

	return dst;
}
