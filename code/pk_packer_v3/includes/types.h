#include <elf.h>
#define MAGIC_WORD 0xb4b0b4b0
#define DATA_PAD_LEN 64

#ifdef X86_64 
        typedef Elf64_Ehdr ElfX_Ehdr;
        typedef Elf64_Phdr ElfX_Phdr;
        typedef Elf64_Shdr ElfX_Shdr;
        typedef Elf64_Addr ElfX_Addr;
        typedef Elf64_Off  ElfX_Off;
        typedef Elf64_Word ElfX_Word;
#else
        typedef Elf32_Ehdr ElfX_Ehdr;
        typedef Elf32_Phdr ElfX_Phdr;
        typedef Elf32_Shdr ElfX_Shdr;
        typedef Elf32_Addr ElfX_Addr;
        typedef Elf32_Off  ElfX_Off;
        typedef Elf32_Word ElfX_Word;

#endif

