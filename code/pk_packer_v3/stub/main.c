#include "../includes/stub.h"
#include <string.h>
#include <sys/ptrace.h>

extern struct global_opts global_opts;

int main(int argc, char **argv)
{
	
        int fd, i;
        char *file = argv[0];
        char stub_info[DATA_PAD_LEN], *p;
        long len;
        struct stat st;
        uint8_t *mem;
	struct payload payload;

        /* 
	 * Open ourself up and look for the magic 
         * that defines the payloads location etc. 
         */
	
	printf("global_opts.disable_ptrace_protection = %d\n", global_opts.disable_ptrace_protection);
	/*
	if (!global_opts.disable_ptrace_protection)
	{
		if (global_opts.verbose)
			printf("Enabling ptrace protection\n");

		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
        	{
                	perror("ptrace");
                	exit(0);
        	}
	}
	*/
        if ((fd = open(file, O_RDONLY)) == -1)
                exit(-1);
        
        if (fstat(fd, &st) < 0)
                exit(-1);
	
	printf("Stubcode is %d bytes\n", st.st_size);

        mem = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
        if (mem == MAP_FAILED)
                exit(-1);
 	
	if (*(unsigned int *)&mem[st.st_size - sizeof(long)] != MAGIC_WORD)
	{
		printf("This wrapped ELF executable is missing its magic (or is just the stubcode)\n");
		exit(-1);
	}

	memcpy(stub_info, (mem + st.st_size - DATA_PAD_LEN), DATA_PAD_LEN);
 
	printf("payload info and key\n");	
	for (i = 0; i < DATA_PAD_LEN; i++)
		printf("%02x ", stub_info[i]);       

	/* Payload offset/address */
        if ((*(unsigned int *)&stub_info[0]) == 0)
        {
		printf("This wrapped ELF executable is missing its magic\n");
                exit(0);
        }

	/* Payload Length */
        if ((*(unsigned int *)&stub_info[4]) == 0)
        {
	  	printf("This wrapped ELF executable is missing its magic\n");
                exit(0);

        }

	/* 16 byte key */
	for (p = &stub_info[8], i = 0; i < 16; i++, p++)
		payload.stub_key[i] = *p;
	
	payload.vaddr  = *(unsigned int *)&stub_info[0];
	payload.length = *(unsigned int *)&stub_info[4];
	
	printf("payload.vaddr: 0x%x\n", payload.vaddr);
	printf("Calling load and exec\n");
        load_and_exec(argc, argv, NULL, payload);
};


