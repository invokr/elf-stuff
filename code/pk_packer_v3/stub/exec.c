#include "../includes/stub.h"

int exec_is_static = 0;

int load_and_exec(int argc, char **argv, char **envp, struct payload payload)
{
	/*
 	 * Create a pointer to our encrypted payload
	 * which resides within the text segment of
	 * the actual stub code 
	 */
	
	elfobj_align_t target_elf;
	uint8_t *linker_ptr = NULL;
	uint8_t *exec_ptr;
	argvec_t argvec;
	int i;
	void *ptr;

	char ld_so[32] = {0};
	
	printf("payload.vaddr: 0x%x\n", payload.vaddr);
	payload.exec = (uint8_t *)payload.vaddr;
	
	payload.ehdr = (ElfX_Ehdr *)payload.exec;
	payload.phdr = (ElfX_Phdr *)(payload.exec + payload.ehdr->e_phoff);
		
	rc4_crypt(payload.exec, payload.length, payload.stub_key, 16);
	
	printf("First byte of payload executable: %02x\n", payload.exec[0]);

	prepare_elf_for_loading(payload.exec, &target_elf, TARGET_EXECUTABLE);
	printf("target_elf.text_vaddr: 0x%x\n", target_elf.text_vaddr);
	printf("Loading target_elf into memory\n");
	
        if (extract_linker(payload.exec, ld_so) == 0)
                exec_is_static++;

	if(load_binary(&target_elf) == -1)
	{
		printf("Unable to load protected app into memory\n");
		exit(-1);
	}

	printf("Executable is %s compiled\n", exec_is_static ? "statically" : "dynamically");
	if (!exec_is_static) 
	{
		/*
		 * load_linker creates an ELF context and makes sure
		 * that alignment is properly done along with mprotects.
		 */
			
		linker_ptr = (uint8_t *)load_linker(ld_so); 
	}
	
	printf("Hold initial stack args\n");
	if (hold_initial_stack_args(argc, argv, NULL, &argvec) == -1)
	{
		printf("hold_initial_stack_args failed\n");
		exit(-1);
	}
	printf("setup usermode stack\n");
	setup_usermode_stack_and_jmp(&argvec, &target_elf, linker_ptr);

			
}	
	
