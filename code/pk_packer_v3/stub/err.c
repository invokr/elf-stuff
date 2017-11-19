#include "../includes/stub.h"

void no_data_err(int type)
{	
	char *linker = "Dynamic linker appears to have no data segment\n";
	char *target = "Target executable appears to have no data segment\n";

	switch(type)
	{
	case DYNAMIC_LINKER:
		printf("%s\n", linker);
		break;
	case TARGET_EXECUTABLE:
		printf("%s\n", target);
		break;
	}
	exit(0);
}

void mprotect_err(int type)
{
	char *page = "Could not set memory protection for PAGE size padding\n";
	char *text = "Could not set memory protection for text segment in a target\n";
	char *data = "Could not set memory protection for data segment in a target\n";
	
	switch(type)
	{
	case MP_TEXT_ERR:
		printf("%s\n", text);
		break;
	case MP_PAGE_ERR:
		printf("%s\n", page);
		break;
	case MP_DATA_ERR:
		printf("%s\n", data);
		break;
	}

	exit(0);
}

void linker_err(void)
{
	char *linker = "Unable to open dynamic linker for loading\n";
	printf("%s\n", linker);
	exit(-1);
}

