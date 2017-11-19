#include "../includes/wrap.h"

void md5_digest_key(uint8_t *);


void GENERATE_KEY(uint8_t *key)
{
	if (GetSystemKey(key) == -1)
	{
		printf("Unable to generate a System key taken from the systems ROM\n");
		exit(-1);
	}
	
	/* Create 16 byte hash sum for key */
	md5_digest_key(key);

}
void md5_digest_key(uint8_t *key)
{
	MD5_CTX ctx;
	int i;
	char *digest = alloca(16);

        MD5_Init (&ctx);
        MD5_Update (&ctx, (uint8_t *)key, KEY_LEN);
        MD5_Final ((uint8_t *)digest, &ctx);
	for (i = 0; i < 16; i++)
		key[i] = digest[i] & 0xFF;
	
}

int GetSystemKey (unsigned char *key)
{
        int c, kfd;
	int bytes = KEY_LEN;
	unsigned long off = 0xffff; // where bios memory starts

	if ((kfd = open("/dev/mem", O_RDONLY)) < 0)
	{
		printf("Unable to generate key from /dev/mem\n", strerror(errno));
		return -1;
	}
	
        if (lseek64 (kfd, (unsigned long long) off, SEEK_SET) != off)
                return -1;

        if ((c = read (kfd, key, bytes)) != bytes)
 		return -1;      
	
	return 0;
}

void show_key(unsigned char *key)
{
        int i;
        printf("Using the following key: ");
        for (i = 0; i < 16; i++)
                printf("%02x", key[i]);
        printf("\n");
}

