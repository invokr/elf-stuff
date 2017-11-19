#include "../stub/stub.h"

#define PRODUCT_NAME "ELFArmor Elite v1.0"

typedef struct {
	uint8_t *mem;
	ElfX_Ehdr *ehdr;
	ElfX_Phdr *phdr;
	ElfX_Shdr *shdr;
} elf_ctx_t;
