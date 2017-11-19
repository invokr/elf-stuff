#include "../includes/wrap.h"

void usage(void)
{
	printf("\nELFCrypt Elite v1.0\n");
	printf("%s <target> [-slvh]\n", PRODUCT_NAME);
	printf("[-s] Add a list of shared libraries to protect.\n"
	       "[-d] Do not enforce local lockdown mode (This allows the executable to run on other systems)\n"
	       "[-P] Disable ptrace protection (NOT RECOMMENDED FOR REAL SECURITY\n"
	       "[-S] Keep ELF Section headers. This allows objdump, gdb and other tools to be able to analyze the binary (NOT RECOMMENDED FOR REAL SECURITY)\n"
	       "[-v] Verbose mode.\n"
	       "[-h] This menu\n\n");
	exit(0);
}

