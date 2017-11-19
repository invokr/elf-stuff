#include "../includes/wrap.h"

unsigned char S[256];
unsigned int i, j;

void
swap (unsigned char *s, unsigned int i, unsigned int j)
{
	unsigned char temp = s[i];
	s[i] = s[j];
	s[j] = temp;
}

/* KSA */
void
rc4_init (unsigned char *key, unsigned int key_length)
{
	for (i = 0; i < 256; i++)
		S[i] = i;

	for (i = j = 0; i < 256; i++)
	{
		j = (j + key[i % key_length] + S[i]) & 255;
		swap (S, i, j);
	}

	i = j = 0;
}

/* PRGA */
unsigned char
rc4_output ()
{
	i = (i + 1) & 255;
	j = (j + S[i]) & 255;

	swap (S, i, j);

	return S[(S[i] + S[j]) & 255];
}




int rc4_crypt (unsigned char *mem, int mem_len, unsigned char *key, int key_len)
{
	int y;

	rc4_init (key, key_len);
	for (y = 0; y < strlen (mem); y++)
		mem[y] ^= rc4_output();
	return 0;
}

/*
int main(void)
{
	unsigned char msg[10];
	strcpy(msg, "123456789");
	unsigned char key[4] = "\xff\xc0\xd0\xe0";
	int x;

	rc4_crypt(msg, 9, key, 4);
	for (x = 0; x < 9; x++)
		printf("%02x ", msg[x]);
	printf("\n");
	 rc4_crypt(msg, 9, key, 4);
	printf("%s\n", msg);
	printf("\n");

}
*/
