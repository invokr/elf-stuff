/*
 * [Elfscure] - The ELF binary obfuscator - by Gerard`De Nerval aka Elf 
 * Soon to have many more features.
 * gcc elfscure.c -o elfscure
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <elf.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <time.h>

#define SHT_VERSYM 0x6fffffff
#define SHT_VERNEED 0x6ffffffe

#define W 1	 /* SHF_WRITE */
#define A 2	 /* SHF_ALLOC */
#define X 4	 /* SHF_EXECINSTR */

struct options
{
	/* section mixup */
	char smix;
	char verbose;
	char sh_type;
	char sh_flags;

} opts;
struct stat st;
struct section_type 
{
	char name[64];
	uint32_t type;
	int flags;
};

struct section_type section_type[] = {
{".interp", 	SHT_PROGBITS,  	A },
{".hash", 	SHT_HASH, 	A },
{".note.ABI-tag", SHT_NOTE, 	A },
{".gnu.hash", 	SHT_GNU_HASH, 	A },
{".dynsym",	SHT_DYNSYM, 	A },
{".dynstr",	SHT_STRTAB, 	A },
{".gnu.version",SHT_VERSYM, 	A },
{".gnu.version_r",SHT_VERNEED,	A },
{".rel.dyn",	SHT_REL,	A },
{".rel.plt",	SHT_REL, 	A },
{".init",	SHT_PROGBITS,	A|X},
{".plt",	SHT_PROGBITS,	A|X},
{".text",	SHT_PROGBITS,	A|X},
{".fini",	SHT_PROGBITS,	A|X},
{".rodata",	SHT_PROGBITS,	A },
{".eh_frame_hdr",SHT_PROGBITS,	A },
{".eh_frame", 	SHT_PROGBITS,	A },
{".ctors",	SHT_PROGBITS,	W|A},
{".dtors",	SHT_PROGBITS,	W|A},
{".jcr",	SHT_PROGBITS,	W|A},
{".dynamic",	SHT_DYNAMIC,	W|A},
{".got",	SHT_PROGBITS,	W|A},
{".got.plt",	SHT_PROGBITS,	W|A},
{".data",	SHT_PROGBITS,	W|A},
{".bss",	SHT_NOBITS,	W|A},
{".shstrtab",	SHT_STRTAB,	0 },
{".symtab",	SHT_SYMTAB,	0 },
{".strtab",	SHT_STRTAB,	0 },
{"",	SHT_NULL}
};

/* function to get new offsets for section names*/
int STBL_OFFSET(char *p, char *string, int count)
{
	char *offset = p;
	while (count-- > 0)
	{
		while (*offset++ != '.')
			;
		if (strcmp(string, offset-1) == 0)
			return ((offset - 1) - p);
		/* some section names have two periods, thus messing us up */
		/* this will take care of that */
		if (!strncmp(offset-1, ".rel.", 5) || !strncmp(offset-1, ".gnu.", 5) 
		||  !strncmp(offset-1, ".not.", 5) || !strncmp(offset-1, ".got.", 5))
			while (*offset++ != '.');
    	 	
	}
	return 0;
}

int strused(char *s, char **used_strings, int count)
{
	int i;

	for (i = 0; i < count; i++)
		if (!strcmp(s, used_strings[i]))
			return 1;
	return 0;
}

int main(int argc, char **argv)
{	
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr, *shp;
	Elf32_Phdr *phdr;
	
	char *StringTable, *NewStringTable;
	char **STBL, **STBL_USED_STRINGS;
	char *p, exec[255];
	char tmp[64];

	uint8_t *mem;

	int fd;
	int i, j, k, count;
	int strcnt, slen;
	char c, failed = 0;
	
	struct timeval tv;
	struct timezone tz;

	opts.smix = 0;
	opts.verbose = 0;
	opts.sh_type = 0;
	opts.sh_flags = 0;

	if (argc < 3)
	{
		printf("\nElfScure v1.0 - Elf Binary Obfuscator\n" 
		"Usage: %s <file> [options]\n"
		"[-s]	String table randomization\n"
		"[-t]	Keep section types consistent with string names\n"
		"[-f]    Keep section flags consistent with string names\n"	
		"Examples: \n"
		"%s evilprog -stf\n",
		argv[0], argv[0]);	
		exit(0);
	}
	
	strcpy(exec, argv[1]);

	while ((c = getopt(argc, argv, "fstv")) != -1)
	{
		switch(c)
		{
			case 's':
				opts.smix++;
				break;
			case 't':
				opts.sh_type++;
				break;
			case 'f':
				opts.sh_flags++;
				break;
			case 'v':
				opts.verbose++;
				break;
		}
	}

	if ((fd = open(exec, O_RDWR)) == -1)
	{
		perror("open");
		exit(-1);
	}

	if (fstat(fd, &st) < 0)
	{
		perror("fstat");
		exit(-1);
	}

	mem = mmap(0, st.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED)
	{
		perror("mmap");
		exit(-1);
	}

	ehdr = (Elf32_Ehdr *)mem;
	phdr = (Elf32_Phdr *)(mem + ehdr->e_phoff);
	shdr = (Elf32_Shdr *)(mem + ehdr->e_shoff);

	/* setup string table pointer */	
	StringTable = &mem[shdr[ehdr->e_shstrndx].sh_offset];

	printf("[+] ELF Section obfuscation ->\n");
	printf("[+] Beginning string table randomization\n");
	if (opts.sh_type)
		printf("[+] sh_type consistency enabled\n");
	if (opts.sh_flags)
		printf("[+] sh_flag consistency enabled\n");

	/* trust me */
	if (opts.sh_type || opts.sh_flags)
		ehdr->e_shnum = 0;

	if ((STBL = calloc(ehdr->e_shnum, sizeof(char *))) == NULL)
	{
		perror("calloc");
		exit(-1);
	}
	
	if ((STBL_USED_STRINGS = calloc(ehdr->e_shnum, sizeof(char *))) == NULL)
	{
		perror("calloc");
		exit(-1);
	}
	
	for (i = 0, shp = shdr; i < ehdr->e_shnum; shp++, i++)
		STBL[i] = strdup(&StringTable[shp->sh_name]); 
	strcnt = i - 1;

	for (slen = 0, i = 0; i < strcnt; i++, slen += strlen(STBL[i]) + 1);

	if ((NewStringTable = (char *)malloc(slen)) == NULL)
	{
		perror("malloc");
		exit(-1);
	}
	
	for (p = NewStringTable, i = 0; i < strcnt; i++)
	{
		strcpy(p, STBL[i]); 
		p += strlen(p) + 1;
		*p = 0;
	}
	
	if (opts.verbose)
	{
		for (i = 0; i < slen; i++)
			printf("%c", NewStringTable[i]);
		printf("\n");
	}
	
	for (i = 0; i < strcnt; i++)
		STBL_USED_STRINGS[i] = malloc(64);
	j = 0;
	for (i = 0, shp = shdr; i < ehdr->e_shnum; i++, shp++)
	{
		
		memset(tmp, 0, sizeof(tmp));
		gettimeofday(&tv, NULL);
		srand(tv.tv_usec);
		/* copy a random section name into tmp */
		strcpy(tmp, STBL[rand() % strcnt]); 

		/* is the string already used? */
		if (strused(tmp, STBL_USED_STRINGS, strcnt))
		{
			--i;
			--shp;
			continue;
		}
		/* confirm that were not assigning a duplicate of itself */
		/* i.e .symtab to .symtab */
		if (!strcmp(&StringTable[shp->sh_name], tmp))
		{
			--i; --shp;
			continue;
		} 
		if (shp->sh_type == SHT_NULL)
			continue;

		/* dynamic section should be kept in place */
		if (!strcmp(&StringTable[shp->sh_name], ".dynamic") || !strcmp(tmp, ".dynamic"))
		{
			if ((shp->sh_name = STBL_OFFSET(NewStringTable, ".dynamic", strcnt)) == 0)
			{
				  printf("STBL_OFFSET failed, could not find section name: %s, moving on\n", tmp);
 	                          goto done;
			}
			continue;
		}
		/* lets create its new offset */
		if ((shp->sh_name = STBL_OFFSET(NewStringTable, tmp, strcnt)) == 0)
			printf("STBL_OFFSET failed, could not find section name: %s\n", tmp);
	
		/* lets keep .text marked with 0x8048000 */
		if (!strcmp(tmp, ".text"))
			shp->sh_addr = 0x8048000;
		
		/* change the section type to match its name */
		/* symtab, rel and dynsym types require a specific entry size */
		if (opts.sh_type)
			for (count = 0; count < strcnt; count++)
				if (!strcmp(tmp, section_type[count].name))
				{	
					shp->sh_type = section_type[count].type;
					if (shp->sh_type == SHT_SYMTAB)
						shp->sh_entsize = 0x10;
					else
					if (shp->sh_type == SHT_DYNSYM)
						shp->sh_entsize = 0x10;
					else
					if (shp->sh_type == SHT_REL)
						shp->sh_entsize = 0x08;
				}
		
		if (opts.sh_flags)
			for (count = 0; count < strcnt; count++)
				if (!strcmp(tmp, section_type[count].name))
					shp->sh_flags = section_type[count].flags;

		strcpy(STBL_USED_STRINGS[j++], tmp);
	}
	memcpy(&mem[shdr[ehdr->e_shstrndx].sh_offset], NewStringTable, shdr[ehdr->e_shstrndx].sh_size);
	
	if (msync(mem, st.st_size, MS_SYNC) == -1)
	{
		perror("msync");
		failed++;
	}

	done:
	munmap(mem, st.st_size);
	for (i = 0; i < strcnt; i++)
	{	free(STBL[i]);
		free(STBL_USED_STRINGS[i]);
	} 
	if (!failed)
		printf("Finished section obfuscation sucessfully\n");
	else
		printf("section obfuscation did not complete sucessfully\n");
	exit(0);
}

	
