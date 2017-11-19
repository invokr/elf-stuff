#include "../includes/wrap.h"
#include <sys/mman.h>
#include <string.h>

void VERIFY_ELF_AND_CLASS(char *file, ElfX_Ehdr *ehdr, int8_t class)
{
        uint16_t e_type;

	/* Is this even an ELF file */
	if (ehdr->e_ident[0] != 0x7f && strcmp(&ehdr->e_ident[1], "ELF") != 0)
	{
		printf(" is not an ELF file\n", file);
		exit(-1);
	}
	
	/* Is the target the right architecture */
	if (ehdr->e_ident[EI_CLASS] != class)
	{
		switch(ehdr->e_ident[EI_CLASS])
		{
		case ELFCLASS32:
			printf("The executable file '%s' is a 32bit compiled binary, but %s is compiled to protect 64 bit executables\n", file, PRODUCT_NAME);
			exit(-1);
		
		case ELFCLASS64:
			printf("The executable file '%s' is a 64bit compiled binary, but %s is compiled to protect 32 bit executables\n", file, PRODUCT_NAME);
                        exit(-1);
		
		case ELFCLASSNONE:
			printf("The executable file '%s' is of an unknown architecture type, therefore it is unsupported by %s\n", file, PRODUCT_NAME);
			exit(-1);
		}
			
	}
        
}

int FreeElf(elf_ctx_t *elf)
{
	munmap(elf->mem, elf->size);
}

int LoadElf(char *path, elf_ctx_t *elf, int flags)
{
	
	int fd, i, class;
	struct stat st;
	

	if ((fd = open(path, O_RDWR)) < 0)
	{
		printf("Unable to open file: %s\n", path);
		return -1;
	}

	if (fstat(fd, &st) < 0)
	{
		perror("LoadElf failure - fstat");
		return -1;
	}
	
	elf->size = st.st_size;
	
	elf->mem = (uint8_t *)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, flags, fd, 0);
	
	if (elf->mem == MAP_FAILED)
	{
		perror("LoadElf failed mmap");
		return -1;
	}

	elf->ehdr = (ElfX_Ehdr *)elf->mem;
	
#ifdef X86_64
	class = ELFCLASS64;
#else
	class = ELFCLASS32;
#endif

	VERIFY_ELF_AND_CLASS(path, elf->ehdr, class);

	elf->phdr = (ElfX_Phdr *)(elf->mem + elf->ehdr->e_phoff);
	elf->shdr = (ElfX_Shdr *)(elf->mem + elf->ehdr->e_shoff);

	for (i = 0; i < elf->ehdr->e_phnum; i++)
	{
		/* ELF is dynamically linked */
		if (elf->phdr[i].p_type == PT_INTERP)
			elf->dynamic++;

		if (elf->phdr[i].p_offset == 0 && elf->phdr[i].p_type == PT_LOAD)
		{
			elf->text_vaddr = elf->phdr[i].p_vaddr;
			elf->text_offset = elf->phdr[i].p_offset;
			elf->text_filesz = elf->phdr[i].p_filesz;
			i++;

			elf->data_vaddr = elf->phdr[i].p_vaddr;
			elf->data_offset = elf->phdr[i].p_offset;
			elf->data_filesz = elf->phdr[i].p_filesz;
		}
	}
	
	close(fd);
	/* Should not get here */
	return 0;
}
	
