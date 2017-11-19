/*
 * Source: elfcrypt.c
 * ELF Encryption code
 * ELFCrypt - Ryan O'Neill (C) 2009
 * <ryan@bitlackeys.com>
 */


#include "../includes/wrap.h"

#define DELIMITERS ",\t "

#define STUB "stubcode"
#define TMP ".stubby"

#define MAGIC_LEN 12

#define PAGEUP(x) (x + PAGE_SIZE - (x & (PAGE_SIZE - 1)))

long PARASITE_PAGE_ALIGNED;


int main (int argc, char **argv)
{
	char *host, *last_chunk;
	int newfd;
	int i, j, c, len, found_text = 0;
	uint8_t *ptr;
	char null = 0;

	mode_t mode;
	struct stat st;

	uint8_t *mem;
	
	/* Array of shared libraries to protect */
	char **shared_libs;
	char *target;

	elf_ctx_t stub; // the stub code
	elf_ctx_t exec; // the executable to protect 
	
	unsigned char seed[32];
	unsigned char key[16];
	
	memset(&global_opts, 0, sizeof(struct global_opts));	
	memset(&stub, 0, sizeof(elf_ctx_t));
	memset(&exec, 0, sizeof(elf_ctx_t));

	if (argc < 2)
		usage();
	
	target = argv[1];
	
	while ((c = getopt(argc, argv, "PSs:dvh")) != -1)
	{
		switch(c)
		{
		case 's':
			ExtractArgs(&shared_libs, DELIMITERS, optarg);
			global_opts.prot_shared_objects++;
			break;
		case 'd':
			global_opts.disable_local_lockdown++;
			break;	
		case 'S':
			printf("Keeping stub section headers (This should only be done for debugging)\n");
			global_opts.keep_shdrs++;
			break;
		case 'P':
			printf("Disabling PTRACE protection (This should only be done for debugging)\n");
			global_opts.disable_ptrace_protection++;
			break;
		case 'h':
			usage();
		case 'v':
			printf("Enabled verbose mode\n");
			global_opts.verbose++;
			break;
		}
			

	}
	
	if (global_opts.disable_ptrace_protection)
		printf("DISABLED PTRACE PROTECTION\n");

	GENERATE_KEY(seed);
	memcpy(key, seed, DIGEST_LEN);
	show_key(key);
	
	/* 
	 * Open target executable 
	 */
	
	if (global_opts.verbose)
		printf("Performing LoadElf() on %s\n", target);

	/* Shrink target executable as much as */
	/* possible -- shed anything we don't need */

	printf("Stripping target executable of unnecessary symbols and sections to reduce size.\n");

	exec_string("/usr/bin/strip %s", target);

	if (LoadElf(target, &exec, MAP_PRIVATE) == -1)
		goto done;
	
	char *StringTable = &exec.mem[exec.shdr[exec.ehdr->e_shstrndx].sh_offset];
	if (global_opts.verbose)
	{
		printf("The following ELF sections will be protected\n");
		for (i = 0; i < exec.ehdr->e_shnum; i++)
			printf("%s\n", &StringTable[exec.shdr[i].sh_name]);
		printf("\n");
	}
	/*
	 * Open stub code executable
	 */
	if (global_opts.verbose)
		printf("Performing LoadElf() on %s\n", STUB);
	
	if (LoadElf(STUB, &stub, MAP_PRIVATE) == -1)
		goto done;

	if (*(long *)&exec.mem[exec.size - 4] == MAGIC_WORD)		
	{
		printf("%s appears to already be protected\n", target);
		exit(-1);
	}

	if (global_opts.verbose)
		printf("Encrypting target executable using rc4 cipher against system key digest\n");

	/* encrypt the target executable into a single blob of data */
	if (global_opts.verbose)
		printf("Body to encrypt is %d bytes\n", exec.size);

	rc4_crypt (exec.mem, exec.size, key, 16);

	printf("After encryption first byte of %s is %02x\n", target, exec.mem[0]);
	PARASITE_PAGE_ALIGNED = PAGEUP(exec.size);

	/*  	
	 * Modify program headers as needed
	 * to make room for the payload which
	 * is the protected executable 
	 */
	ElfX_Word orig_stub_text_filesz;
	ElfX_Off  orig_stub_text_offset;

	/* Modifying stub ELF phdrsz */
	
	for (i = 0; i < stub.ehdr->e_phnum; i++)
	{
		/* extend segment offsets after text */
		if (found_text)
		{
			stub.phdr[i].p_offset += PARASITE_PAGE_ALIGNED;
			continue;
		}
		if (stub.phdr[i].p_type == PT_LOAD && stub.phdr[i].p_offset == 0)
		{
			orig_stub_text_filesz = stub.phdr[i].p_filesz;
			orig_stub_text_offset = stub.phdr[i].p_offset;
			
			stub.phdr[i].p_filesz += exec.size;
			stub.phdr[i].p_memsz += exec.size;
			stub.phdr[i].p_flags |= PF_W;
			found_text = 1;
		}
	}


        /* Clear out string tables for extra obfuscation in static executables */
	/*
	if (exec.dynamic == 0)
	{
		for (i = 0; i < stub.ehdr->e_shnum; i++)
                	if (stub.shdr[i].sh_type == SHT_STRTAB)
                	{
                        	ptr = (stub.mem + stub.shdr[i].sh_offset);
                        		for (j = 0; j < stub.shdr[i].sh_size; j++, ptr++)
                                		*ptr = 0x00;
                	}
	}
	*/
	/*
 	 * update section headers even though
	 * e_shoff will be 0, a smart tool could
	 * locate the section header table and
	 * utilize them with objdump or the likes.
	 */
	for (i = 0; i < stub.ehdr->e_shnum; i++)
	{
		if (stub.shdr[i].sh_offset > (orig_stub_text_offset + orig_stub_text_filesz))
			stub.shdr[i].sh_offset += PARASITE_PAGE_ALIGNED;
		
		if ((stub.shdr[i].sh_addr + stub.shdr[i].sh_size) == 
		    (stub.text_vaddr + orig_stub_text_filesz))
			stub.shdr[i].sh_size += exec.size; // increase it by payload size to account for it
	}

	printf("global_opts.keep_shdrs: %d\n", global_opts.keep_shdrs);
	switch(global_opts.keep_shdrs)
	{
		case 1:
		if (global_opts.verbose)
			printf("Keeping section headers available for more accessable binary analysis\n");
		stub.ehdr->e_shoff += PARASITE_PAGE_ALIGNED;
		break;
		
		case 0:
		stub.ehdr->e_shnum = 0;
        	stub.ehdr->e_shoff = 0;
        	stub.ehdr->e_shentsize = 0;
        	stub.ehdr->e_shstrndx = 0;
		break;
	}

#define _S_IWUSR 00200
#define _S_IXUSR 00100
#define _S_IRUSR 00400

	if ((newfd = open(TMP, O_TRUNC|O_CREAT|O_WRONLY, _S_IWUSR|_S_IXUSR|_S_IRUSR)) == -1)
	{
		printf("Unable to create initial stub code: %s\n", strerror(errno));
		goto done;
	}

	/* Write text segment of stub */
	if (write (newfd, stub.mem, stub.text_offset + stub.text_filesz) == -1)
	{
		perror ("writing stub");
		goto done;
	}

	/* write the payload which is the target executable */
	if (write (newfd, exec.mem, exec.size) == -1)
	{
		perror ("writing payload");
		goto done;
	}

	/*
	 * Increase stub memory map pointer to end of text
	 * segment so that it can write the data segment
         * after where we stored the page aligned parasite.
	 */

	stub.mem += stub.text_offset + stub.text_filesz;
	
	/* Seek to stub_text + PAGE_ALIGNED_PARASITE + <Data segment goes here for stub> */
	if (lseek (newfd, PARASITE_PAGE_ALIGNED - exec.size, SEEK_CUR) == -1)
	{
		perror ("lseek");
		goto done;
	}

	/* Write out stub data segment, which is after payload */
	if (write (newfd, stub.mem, stub.size - stub.text_filesz) == -1)
	{
		perror ("writing payload");
		goto done;
	}

	
	printf("Writing %d bytes of 0 to make room for magic info\n", DATA_PAD_LEN);

	if (write (newfd, &null, DATA_PAD_LEN) == -1)
	{
		perror ("writing padding");
		goto done;
	}

	if (fchown (newfd, st.st_uid, st.st_gid) < 0)
	{
		perror ("chown");
		goto done;
	}

	if (rename (TMP, target) < 0)
	{
		perror ("rename");
		goto done;
	}

	close (newfd);
	
	FreeElf(&stub);
	/*
	 * By now the executable is protected
	 * and is essentially an encrypted payload
	 * within the stub code. Lets reload that
	 * file and add some magic to it and a key.
	 * so it knows how to decrypt itself, and
 	 * elfcrypt can recognize packed files as
	 * well.
	 */

	if (LoadElf(target, &stub, MAP_SHARED) < 0)
		goto done;
	
	/* 
	 * At the end of the data segment of the stub code
	 * we must embed:
	 * 1. Location of protected executable that we will load.
	 * 2. Length of protected executable.
	 * 3. RC4 Key to decrypt executable.
	 */
		
	uint8_t * embedded_data = &stub.mem[stub.size - DATA_PAD_LEN];
	uint8_t * kp;
	uint8_t *magic;

	printf("storing Entry point for target executable within stub: 0x%lx\n", stub.text_vaddr + orig_stub_text_filesz);
	*(unsigned int *) &embedded_data[0] = stub.text_vaddr + orig_stub_text_filesz;
		
	printf("storing target executable file size: %d bytes\n", exec.size);
	*(unsigned int *) &embedded_data[4] = exec.size;
	
	/* Key ptr */	
	kp = &embedded_data[8];
	for (i = 0; i < DIGEST_LEN; i++)
	{
		kp[i] = key[i];
		printf("kp[%d] %02x\n", i, kp[i]);
	}
	
	magic = &stub.mem[stub.size - sizeof(long)];
	*(int *)magic = MAGIC_WORD;

	printf("+ Target program \"%s\" has been armored and encrypted using the key generated from this system\n", target);
	
	if (global_opts.verbose)
	{
		printf("The stub code will be looking for this data about target executable:\n");
		for (i = 0; i < DATA_PAD_LEN; i++)
			printf("%02x ", embedded_data[i]);
		printf("\n");
	}

	if (msync (stub.mem, stub.size, MS_SYNC) < 0)
	{
		perror ("msync failure");
		goto done;
	}
	
	FreeElf(&exec);
	FreeElf(&stub);

	exit(0);
done:
	printf("Exiting on error..., see --help\n");
	exit(-1);
}
