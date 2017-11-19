/*
 * All ELF and Binary related code.
 */

#include "../includes/stub.h"
#include <string.h>


extern int exec_is_static;

int validate_text(ElfX_Phdr *phdr)
{
	if (phdr->p_type == PT_LOAD && !phdr->p_offset && phdr->p_flags & PF_X)
		return 1;
	return 0;
}

int validate_data(ElfX_Phdr *phdr)
{
	if (phdr->p_type == PT_LOAD && phdr->p_offset && phdr->p_flags & PF_W)
                return 1;
        return 0;
}

int prepare_elf_for_loading(uint8_t *mem, elfobj_align_t *elf, int target_type)
{
	
	ElfX_Ehdr *ehdr;
	ElfX_Phdr *phdr;
	int i, j;
	
	ehdr = (ElfX_Ehdr *)mem;
	phdr = (ElfX_Phdr *)(mem + ehdr->e_phoff);
	
	elf->entry_point = ehdr->e_entry;
	elf->phdr_count = ehdr->e_phnum;

	for (i = 0; i < ehdr->e_phnum; i++)
	{
		/*
		 * Found the text segment here, and the data
		 * segment phdr generally follows.
		 */
		if (validate_text(&phdr[i]))
		{
			elf->text_offset = phdr[i].p_offset;
			elf->text_vaddr = phdr[i].p_vaddr;
			elf->text_filesz = phdr[i].p_filesz;
			elf->phdr_start = phdr[i].p_offset + ehdr->e_phoff;
			
			/* Loadable segments are page aligned in memory */
			elf->text_memsz = PAGE_ALIGN_UP(phdr[i].p_memsz);
			
			if ((elf->text_mem = malloc(elf->text_filesz)) == NULL)
			{
				perror("malloc");
				return -1;
			}
			
			/* Copy text segment into elf->text_mem */
			memcpy(elf->text_mem, mem, elf->text_filesz);

			elf->text_flags = 0;	
			if (phdr[i].p_flags & PF_X)
				elf->text_flags |= PROT_EXEC;
			if (phdr[i].p_flags & PF_R)
				elf->text_flags |= PROT_READ;
			if (phdr[i].p_flags & PF_W)
				elf->text_flags |= PROT_WRITE; // really don't want this
	
		
			/*
			 * The phdr for the data segment is always
			 * directly after the text segment 
			 */
	
			j = i + 1;
			
			/*
			 * Any properly compiled glibc executable
			 * should have a data segment in order to
			 * to house the dynamic segment, and GOT.
			 * we actually bail if the data segment
			 * does not exist.
			 */
			if (validate_data(&phdr[j]) == 0)
				no_data_err(target_type);

			elf->data_offset = phdr[j].p_offset;
			elf->data_vaddr = phdr[j].p_vaddr;
			elf->data_filesz = phdr[j].p_filesz;
		
			elf->data_memsz = PAGE_ALIGN_UP(phdr[j].p_memsz);
			
			if ((elf->data_mem = malloc(elf->data_filesz)) == NULL)
			{
				perror("malloc"); 
				return -1;
			}
				
			/* Copy data segment into elf->data_mem */
			memcpy(elf->data_mem, &mem[elf->data_offset], elf->data_filesz);
	
			printf("data_mem[0]: %02x\n", elf->data_mem[0]);

			elf->data_flags = phdr[j].p_flags;
			elf->bss_size = phdr[j].p_memsz - phdr[j].p_filesz;
			
			elf->data_flags = 0;
			if (phdr[j].p_flags & PF_X)
                                elf->data_flags |= PROT_EXEC;
                        if (phdr[j].p_flags & PF_R)
                                elf->data_flags |= PROT_READ;
                        if (phdr[j].p_flags & PF_W)
                                elf->data_flags |= PROT_WRITE; 
			
			/*
			 * calculate complete program image size
			 * We add a page of padding in between text and data 
			 * For the proper alignment, and make room for .bss 
                         */
			elf->image_len = elf->data_memsz + elf->text_memsz; 
			elf->image_len += elf->bss_size;
			
			/* Only dynamic executables have a read-only page 
			 * between the text and the data segment.
			 */
			if (exec_is_static == 0)
				elf->image_len += PAGE_SIZE;
		
		}
	}
	elf->mem = mem;
	return 0;
} 

/* 
 * This function loads any type of ELF object really.
 * Primarily used for ET_EXEC (Target) and ET_DYN (linker)
 * It has two purposes:
 * 1. Load linker (/lib/ld-vers.so)
 * 2. Load encrypted/embedded payload (protected executable) 
 * This code only loads ET_EXEC as a payload not from a file.
 */
int load_binary(elfobj_align_t *elf)
{
	unsigned char *exec, *p, *text, *data, *page;
	unsigned int offset;
	int i, DYNAMICALLY_LINKED = 0;
	int LOADING_LINKER = 0;

	/* Really just for readability down below */
	if (exec_is_static == 0)
		DYNAMICALLY_LINKED = 1;
	/*
 	 * If the text segment starts at 0
	 * then we don't need MAP_FIXED since
	 * this is probably relocatable code.
	 */
	int mmap_flags = MAP_ANONYMOUS|MAP_PRIVATE;
	if (elf->text_vaddr != 0)
		mmap_flags |= MAP_FIXED;
	else
		LOADING_LINKER = 1;
	/* 
	 * Create enough room for the following setup --
	 * [text]
	 * [PAGE]
	 * [data]
	 * [.bss]
	 */
	text = (uint8_t *)mmap((uint8_t *)elf->text_vaddr, elf->text_memsz, PROT_READ|PROT_WRITE, mmap_flags, -1, 0);
	if (text == MAP_FAILED)
	{
		printf("mmap() failed at loading text segment: %s\n", strerror(errno));
		return -1;
	}
	
	memcpy(text, elf->text_mem, elf->text_filesz);
	
	if (mprotect((uint8_t *)text, elf->text_memsz, elf->text_flags))
	{
		perror("mprotect");
		return -1;
	}
	
	if (DYNAMICALLY_LINKED)
		page = mmap((uint8_t *)elf->text_vaddr + elf->text_memsz, PAGE_SIZE, PROT_READ, mmap_flags, -1, 0);
  
	uint32_t d_off = elf->data_vaddr - (elf->data_vaddr & ~(PAGE_SIZE - 1));
	
	data = (uint8_t *)mmap((uint8_t *)(elf->data_vaddr & ~(PAGE_SIZE - 1)), elf->data_memsz + elf->bss_size, PROT_READ|PROT_WRITE, mmap_flags, -1, 0);
	if (data == MAP_FAILED)
	{
		printf("mmap() failed at loading data segment: %s\n", strerror(errno));
		return -1;	
	}
	
	memcpy(&data[d_off], elf->data_mem, elf->data_filesz);
	
	if (mprotect((uint8_t *)data, elf->data_memsz, elf->data_flags))
	{
		perror("mprotect");
		return -1;
	}

	elf->text = text;
	elf->data = data;
	
	return 0;
}	
	
uint8_t * load_linker(char *path)
{
	struct stat st;
	int fd, ret = 0;
	elfobj_align_t elf;
	uint8_t *mem, *map;
	
	printf("Opening linker: %s\n", path);

	if ((fd = open(path, O_RDONLY)) < 0)
	 	linker_err();	
	
	if (fstat(fd, &st) < 0)
	{
		printf("Failure in loading dynamic linker: %s\n", strerror(errno));
		return NULL;
	}
	
	mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mem == MAP_FAILED)
	{	
		printf("Failure in loading dynamic linker: %s\n", strerror(errno));
		return NULL;
	}	
	
	/* 
         * Get our dynamic linker ready for being mapped
	 * into the process address space.
	 */
	prepare_elf_for_loading(mem, &elf, DYNAMIC_LINKER);
		
	if (load_binary(&elf) == -1)
	{
		printf("Failed loading dynamic linker segments into memory\n");
		exit(-1);
	}

	return elf.text;
}
 
/* 
 * Returns 1 on success
 * stores linker "/lib/ld-vers.so" in global
 * buffer called 'ld_so'
 * return 0 means the executable is static.
 */
int extract_linker(uint8_t *mem, char *ld_so)
{
	ElfX_Ehdr *ehdr;
	ElfX_Phdr *phdr;
	int i;

	ehdr = (ElfX_Ehdr *)mem;
	phdr = (ElfX_Phdr *)(mem + ehdr->e_phoff);
	
	for (i = 0; i < ehdr->e_phnum; i++)
		if (phdr[i].p_type == PT_INTERP)
		{	
			memcpy(ld_so, &mem[phdr[i].p_offset], strlen(&mem[phdr[i].p_offset]));		
			return 1;
		}
	return 0;
}

