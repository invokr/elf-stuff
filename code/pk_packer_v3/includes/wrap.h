#include <openssl/md5.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/mman.h>

#include "types.h"
#include "opts.h"

#define KEY_LEN 32
#define DIGEST_LEN 16

#define PRODUCT_NAME "ELFCrypt"

typedef struct {
	int dynamic;
	uint8_t *mem;
	ElfX_Ehdr *ehdr;
	ElfX_Phdr *phdr;
	ElfX_Shdr *shdr;
	
	ElfX_Word size; // total size of binary

	ElfX_Word text_filesz;
	ElfX_Addr text_vaddr;
	ElfX_Off text_offset;
	
	ElfX_Word data_filesz;
	ElfX_Addr data_vaddr;
	ElfX_Off data_offset;

} elf_ctx_t;

int elf_arch_class;

#ifdef X86_64
#define PAGE_SIZE 8192
#else
#define PAGE_SIZE 4096
#endif

int ExtractArgs(char ***argvp, char *delim, char *s);
