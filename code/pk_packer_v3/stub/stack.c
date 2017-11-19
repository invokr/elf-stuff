/*
 * Anything stack related
 */

#include "../includes/stub.h"
#include <string.h>

/* 
 * This macro sets esp to our properly setup stack
 * and then returns into our new entry point.
 */

#ifdef X86_64
#define SET_STACK_AND_JMP(stack, addr)__asm__ __volatile__("mov %0, %%rsp\n" \
                                            "push %1\n" \
                                            "mov $0, %%rax\n" \
                                            "mov $0, %%rbx\n" \
                                            "mov $0, %%rcx\n" \
                                            "mov $0, %%rdx\n" \
                                            "mov $0, %%rsi\n" \
                                            "mov $0, %%rdi\n" \
                                            "mov $0, %%rbp\n" \
                                            "ret" :: "r" (stack), "g" (addr))
#else

#define SET_STACK_AND_JMP(stack, addr)__asm__ __volatile__("mov %0, %%esp\n" \
                                            "push %1\n" \
                                            "mov $0, %%eax\n" \
                                            "mov $0, %%ebx\n" \
                                            "mov $0, %%ecx\n" \
                                            "mov $0, %%edx\n" \
                                            "mov $0, %%esi\n" \
                                            "mov $0, %%edi\n" \
                                            "mov $0, %%ebp\n" \
                                            "ret" :: "r" (stack), "g" (addr)) 
#endif


/*
 * Here we temporarily store the cmdline and environment vars that were
 * passed into the protected program. We will eventually set them up on
 * our custom stack at STACK_BASE - stack_data + auxv
 *
 * hold_initial_stack_args(argc, argv, envp, &argvec);
 */

int hold_initial_stack_args(int argc, char **argv, char **envp, argvec_t *argvec)
{
	int i, c, len, PAD_LEN = 12;
	char *p;

	/* must initialize it */
	argvec->argv.len = 0;
	argvec->argv.count = 0;
	argvec->envp.len = 0;
	argvec->envp.count = 0;

	/* Get length of argv strings in total */
	for (len = 0, i = 0, c = argc; c > 0; c--, i++)
		len += strlen(argv[i]);
	len += argc; // create a room for null bytes
	
	printf("argc: %d\n", argc);
	printf("argv[0]: %s\n", argv[0]);
	printf("Len of argc strings: %d\n", len);

	argvec->argv.count = argc;
	argvec->argv.len = len;
	
	if ((argvec->argv.args = (char *)malloc(argvec->argv.len + PAD_LEN)) == NULL)
	{
		printf("malloc failed\n");
		return -1;
	}

	for (p = argvec->argv.args, i = 0, len = 0; i < argc; i++)
	{
		_strcpy(p, argv[i]);
		printf("p: %s\n", p);
		p += strlen(argv[i]) + 1;
	}
	
	if (envp == NULL)
		goto out;

	/* Get count and length of envp strings */
	for (len = 0, i = 0; *envp != NULL; envp++)
	{
		len += _strlen(*envp);
		i++;
	}	
	
	argvec->envp.count = i;
	argvec->envp.len = len + i;
	
	argvec->envp.args = (char *)mmap(NULL, argvec->envp.len, PROT_READ|PROT_WRITE, MAP_PRIVATE, -1, 0); 
	if (argvec->envp.args == MAP_FAILED)
		return -1;

	for (p = argvec->envp.args, i = 0, len = 0; i < argc; i++)
	{
		_strcpy(p, envp[i]);
		p += _strlen(envp[i]) + 1;
	}

	out:
	return 0;

}

#ifdef X86_64
typedef Elf64_auxv_t auxv_t;
#else
typedef Elf32_auxv_t auxv_t;
#endif

/*
 * From user space we can only pass 13 of the 16
 * AUXV entries that the kernel uses for the program
 * linker
 */
#define AUXV_COUNT 9
#define STACK_ALIGN 4 // usermode stack aligns in words
#define STACK_ROUND(x) (x + STACK_ALIGN - (x & (STACK_ALIGN - 1)))

void empty_func(void)
{

} 

int setup_usermode_stack_and_jmp(argvec_t *argvec, elfobj_align_t *exec, uint8_t *linker_ptr)
{
	int count = 0, argc, ascii_offset;
	uint8_t *stack;
	unsigned long *esp, *esp_start, *argv, *envp;
	char *arg, *s;
	int len;
	unsigned long *auxv;
	ElfX_Ehdr *linker_ehdr = (ElfX_Ehdr *)linker_ptr;
	void (*entry)();
	unsigned long esp_start_vaddr;

	int uid, gid, euid;

	count += sizeof(int); // argc
	count += argvec->argv.count * sizeof(char *); // argv...
	count += sizeof(char *); // NULL after argv
	count += sizeof(char *); // for devoid envp
	/*
	count += argvec->envp.count * sizeof(char *); // envp...
	count += sizeof(char *); // NULL
	*/ 

	if (linker_ptr)
		count += AUXV_COUNT * sizeof(auxv_t);
	ascii_offset = count;
	
	count += argvec->argv.len; // length of argv ascii strings
	count += argvec->envp.len; // length of envp ascii strings
	
	count = STACK_ROUND(count);
	
	/* Use existing stub stack */
	stack = (uint8_t *)alloca(STACK_SIZE);
	memset(stack, 0, STACK_SIZE);

	printf("Allocated stack at: %p\n", stack);
	argc = argvec->argv.count;

	printf("Count is: %d STACK_SIZE is: %d\n", count, STACK_SIZE);
	//esp = (unsigned long *)stack + STACK_SIZE - 4;
	//esp -= count;
	esp = (unsigned long *)(stack + STACK_SIZE);
	esp -= count;
	esp_start = esp;
	esp_start_vaddr = (unsigned long)esp_start;

	*(unsigned *)esp++ = argc;
	
	printf("esp is now at: %p\n", esp);
	arg = (char *)esp_start + ascii_offset;
	printf("arg points to %p\n", arg);
	s = (char *)argvec->argv.args;

	printf("ascii_offset should be 0x%lx\n", esp_start_vaddr + ascii_offset);
	/* Put ascii onto stack while at the same time creating the argv ptrs to them */
	while (argc--)
	{
		strcpy(arg, s);
		len = strlen(s) + 1;
		printf("len of %s was: %d stored at %p\n", arg, len, arg);
		s += len;
		*esp++ = (unsigned long *)(arg);
		arg += len;
	}
	
	/* NULL after argv */
	
	*(long *)esp = 0x00000000;
	esp++;
	
	/* NULL for envp */
	*(long *)esp = 0x00000000;
	esp++;

	uid = getuid();
	euid = geteuid();
	gid = getgid();

	printf("Filling in Aux stuff\n");
	
	if (linker_ptr)
	{
	        auxv = esp;
		 
                /* PAGE SIZE */
                *auxv++ = AT_PAGESZ;
                *auxv++ = PAGE_SIZE;
               
                /* PTR TO PROGRAM HEADER TABLE */
                *auxv++ = AT_PHDR;
                *auxv++ = (unsigned long)exec->text_vaddr + exec->phdr_start;
        
                /* SIZE OF PROGRAM HEADER ENTRIES */
                *auxv++ = AT_PHENT;
                *auxv++ = sizeof(ElfX_Phdr);
                
                /* NUMBER OF PROGRAM HEADERS */
                *auxv++ = AT_PHNUM;
                *auxv++ = exec->phdr_count;
                
                /* TARGET EXEC ENTRY POINT */	
		printf("entry point is: %x\n", exec->entry_point);
                *auxv++ = AT_ENTRY;
                *auxv++ = exec->entry_point;
                
		/* Current UID */
		*auxv++ = AT_UID;
		*auxv++ = uid;
		
		/* Current EUID */
		*auxv++ = AT_EUID;
		*auxv++ = euid;
	
		/* Current GID */	
		*auxv++ = AT_GID;
		*auxv++ = gid;

                /* DO I HAVE TO SAY? */
                *auxv++ = AT_NULL;
                *auxv++ = 0;
        }
	int i, j;
	printf("Stack looks like: \n");
	for (i = 0, j = 0; i < count; i++, j += 4)
	{
		if (i % 4 == 0)
			printf("\n");
		printf("(0x%08lx) %x ", esp_start_vaddr + j, esp_start[i]);

	}
	printf("\n");
	entry = (linker_ptr == NULL ? (void(*)())exec->entry_point : (void(*)())(linker_ptr + linker_ehdr->e_entry));
	printf("Entry = %p\n", entry);
	printf("Setting stack (%p) and jumping to %p\n", esp_start, entry);
		
	
	printf("stub eip before jump: 0xc049b7c\n");

	SET_STACK_AND_JMP(esp_start, entry);
	
	printf("Something went wrong\n");
		
}






