#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include "opts.h"
#include "types.h"

#ifdef X86_64
#define PAGE_SIZE 4096*2
#else
#define PAGE_SIZE 4096 
#endif
#define PAGE_ALIGN_UP(x) (x + PAGE_SIZE - (x & (PAGE_SIZE - 1)))
#define PAGE_ALIGN_DOWN(x) (x & ~(PAGE_SIZE - 1))

/* Userland execve loader requires we create a stack */
#define STACK_SIZE 1024 * 500
#define STACK_BASE 0xa0000000
 
/* ERROR CODES */
/* For int target_type in prepare_elf_for_loading() */
#define DYNAMIC_LINKER 0
#define TARGET_EXECUTABLE 1

/* For mprotect errors */
#define MP_TEXT_ERR 0
#define MP_PAGE_ERR 1
#define MP_DATA_ERR 2

#define MMAP_FAILED 0

typedef struct
{
        int count;
        int len;
        char *args;
} argstr_t;

typedef struct
{
	argstr_t argv;
	argstr_t envp;
} argvec_t;

/* Info about embedded target executable */
struct payload
{
	unsigned long vaddr;
	unsigned long length;
	unsigned long phrase;
	unsigned char stub_key[16];
	uint8_t *exec;
	ElfX_Ehdr *ehdr;
	ElfX_Phdr *phdr;
};

/*      
 * elfobj_align_t contains an ELF objects values
 * aligned so that the executable file may be
 * properly loaded into memory.
 */

typedef struct
{
 	uint8_t *mem;
        uint8_t *text, *text_mem;
	uint8_t *data, *data_mem;
	uint8_t *page;

 	ElfX_Addr entry_point;
	
	ElfX_Addr phdr_start; 
	int phdr_count;
        ElfX_Off text_offset;
        ElfX_Addr text_vaddr;
        ElfX_Word text_memsz;
        ElfX_Word text_filesz;
        long text_flags;

        ElfX_Off data_offset;
        ElfX_Addr data_vaddr;
        ElfX_Word data_memsz;
        ElfX_Word data_filesz;
        long data_flags;
        long bss_size;

        unsigned long image_len;
} elfobj_align_t;

