/* libxelf - elf_dump.c - human representation of ELF files
 *
 * by scut / teso
 */

#include <elf.h>
#include <stdio.h>

#include <common.h>
#include <elf_dump.h>


dump_elem	et_tab[] = {
	{ ET_NONE,	"ET_NONE" },
	{ ET_REL,	"ET_REL" },
	{ ET_EXEC,	"ET_EXEC" },
	{ ET_DYN,	"ET_DYN" },
	{ ET_CORE,	"ET_CORE" },
	{ ET_LOPROC,	"ET_LOPROC" },
	{ ET_HIPROC,	"ET_HIPROC" },
	{ 0, NULL },
};

dump_elem	em_tab[] = {
	{ EM_NONE,	"EM_NONE" },
	{ EM_M32,	"EM_M32" },
	{ EM_SPARC,	"EM_SPARC" },
	{ EM_386,	"EM_386" },
	{ EM_68K,	"EM_68K" },
	{ EM_88K,	"EM_88K" },
	{ EM_860,	"EM_860" },
	{ EM_MIPS,	"EM_MIPS" },
	{ 0, NULL },
};

dump_elem	ev_tab[] = {
	{ EV_NONE,	"EV_NONE" },
	{ EV_CURRENT,	"EV_CURRENT" },
	{ 0, NULL },
};


/* Elf32_Ehdr dump table
 */
dump_header	dh_Ehdr[] = {
	{ "Elf32_Ehdr.e_ident", "m", EI_NIDENT, EI_NIDENT, NULL },
	{ "Elf32_Ehdr.e_type", "h", sizeof (Elf32_Half), 0, et_tab },
	{ "Elf32_Ehdr.e_machine", "h", sizeof (Elf32_Half), 0, em_tab },
	{ "Elf32_Ehdr.e_version", "w", sizeof (Elf32_Word), 0, ev_tab },
	{ "Elf32_Ehdr.e_entry", "a", sizeof (Elf32_Addr), 0, NULL },
	{ "Elf32_Ehdr.e_phoff", "o", sizeof (Elf32_Off), 0, NULL },
	{ "Elf32_Ehdr.e_shoff", "o", sizeof (Elf32_Off), 0, NULL },
	{ "Elf32_Ehdr.e_flags", "w", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Ehdr.e_ehsize", "h", sizeof (Elf32_Half), 0, NULL },
	{ "Elf32_Ehdr.e_phentsize", "h", sizeof (Elf32_Half), 0, NULL },
	{ "Elf32_Ehdr.e_phnum", "h", sizeof (Elf32_Half), 0, NULL },
	{ "Elf32_Ehdr.e_shentsize", "h", sizeof (Elf32_Half), 0, NULL },
	{ "Elf32_Ehdr.e_shnum", "h", sizeof (Elf32_Half), 0, NULL },
	{ "Elf32_Ehdr.e_shstrndx", "h", sizeof (Elf32_Half), 0, NULL },
	{ NULL, NULL, 0, 0, NULL },
};


dump_elem	pt_tab[] = {
	{ PT_NULL,	"PT_NULL" },
	{ PT_LOAD,	"PT_LOAD" },
	{ PT_DYNAMIC,	"PT_DYNAMIC" },
	{ PT_INTERP,	"PT_INTERP" },
	{ PT_NOTE,	"PT_NOTE" },
	{ PT_SHLIB,	"PT_SHLIB" },
	{ PT_PHDR,	"PT_PHDR" },
	{ PT_LOPROC,	"PT_LOPROC" },
	{ PT_HIPROC,	"PT_HIPROC" },
	{ 0, NULL },
};

dump_elem	pf_tab[] = {
	{ PF_R,	"PF_R" },
	{ PF_W, "PF_W" },
	{ PF_X, "PF_X" },
	{ 0, NULL },
};

/* Elf32_Phdr dump table
 */
dump_header	dh_Phdr[] = {
	{ "Elf32_Phdr.p_type", "w", sizeof (Elf32_Word), 0, pt_tab },
	{ "Elf32_Phdr.p_offset", "o", sizeof (Elf32_Off), 0, NULL },
	{ "Elf32_Phdr.p_vaddr", "a", sizeof (Elf32_Addr), 0, NULL },
	{ "Elf32_Phdr.p_paddr", "a", sizeof (Elf32_Addr), 0, NULL },
	{ "Elf32_Phdr.p_filesz", "w", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Phdr.p_memsz", "w", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Phdr.p_flags", "fw", sizeof (Elf32_Word), 0, pf_tab },
	{ "Elf32_Phdr.p_align", "w", sizeof (Elf32_Word), 0, NULL },
	{ NULL, NULL, 0, 0, NULL },
};


dump_elem	sht_tab[] = {
	{ SHT_NULL,	"SHT_NULL" },
	{ SHT_PROGBITS,	"SHT_PROGBITS" },
	{ SHT_SYMTAB,	"SHT_SYMTAB" },
	{ SHT_STRTAB,	"SHT_STRTAB" },
	{ SHT_RELA,	"SHT_RELA" },
	{ SHT_HASH,	"SHT_HASH" },
	{ SHT_DYNAMIC,	"SHT_DYNAMIC" },
	{ SHT_NOTE,	"SHT_NOTE" },
	{ SHT_NOBITS,	"SHT_NOBITS" },
	{ SHT_REL,	"SHT_REL" },
	{ SHT_SHLIB,	"SHT_SHLIB" },
	{ SHT_DYNSYM,	"SHT_DYNSYM" },
	{ SHT_LOPROC,	"SHT_LOPROC" },
	{ SHT_HIPROC,	"SHT_HIPROC" },
	{ SHT_LOUSER,	"SHT_LOUSER" },
	{ SHT_HIUSER,	"SHT_HIUSER" },
	{ 0, NULL },
};


dump_elem	shf_tab[] = {
	{ SHF_WRITE,		"SHF_WRITE" },
	{ SHF_ALLOC,		"SHF_ALLOC" },
	{ SHF_EXECINSTR,	"SHF_EXECINSTR" },
	{ SHF_MASKPROC,		"SHF_MASKPROC" },
	{ 0, NULL },
};

/* Elf32_Shdr dump table
 */
dump_header	dh_Shdr[] = {
	{ "Elf32_Shdr.sh_name", "w", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_type", "w", sizeof (Elf32_Word), 0, sht_tab },
	{ "Elf32_Shdr.sh_flags", "fw", sizeof (Elf32_Word), 0, shf_tab },
	{ "Elf32_Shdr.sh_addr", "a", sizeof (Elf32_Addr), 0, NULL },
	{ "Elf32_Shdr.sh_offset", "o", sizeof (Elf32_Off), 0, NULL },
	{ "Elf32_Shdr.sh_size", "w", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_link", "w", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_info", "w", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_addralign", "w", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_entsize", "w", sizeof (Elf32_Word), 0, NULL },
	{ NULL, NULL, 0, 0, NULL },
};

dump_header	dh_Shdr_short[] = {
	{ "Elf32_Shdr.sh_name", "iw", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_type", "sw", sizeof (Elf32_Word), 0, sht_tab },
	{ "Elf32_Shdr.sh_flags", "ifw", sizeof (Elf32_Word), 0, shf_tab },
	{ "Elf32_Shdr.sh_addr", "sa", sizeof (Elf32_Addr), 0, NULL },
	{ "Elf32_Shdr.sh_offset", "so", sizeof (Elf32_Off), 0, NULL },
	{ "Elf32_Shdr.sh_size", "sw", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_link", "iw", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_info", "iw", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_addralign", "iw", sizeof (Elf32_Word), 0, NULL },
	{ "Elf32_Shdr.sh_entsize", "iw", sizeof (Elf32_Word), 0, NULL },
	{ NULL, NULL, 0, 0, NULL },
};


void
elf_dump_header (elf_file *elf)
{
	elf_dump_desc (elf, dh_Ehdr, &elf->Ehdr.e_ident[0],
		sizeof (elf->Ehdr));

	return;
}


void
elf_dump_phtab (elf_file *elf)
{
	int	walker;

	for (walker = 0 ; walker < elf->Ehdr.e_phnum ; ++walker) {
		fprintf (stderr, "=== Elf32_Phdr at 0x%08lx\n",
			(unsigned long int) (elf->Ehdr.e_phoff + walker * elf->Ehdr.e_phentsize));
		elf_dump_desc (elf, dh_Phdr, (void *) &elf->Phdr[walker],
			elf->Ehdr.e_phentsize);
	}

	return;
}


void
elf_dump_shtab (elf_file *elf)
{
	int	walker;

	for (walker = 0 ; walker < elf->Ehdr.e_shnum ; ++walker) {
		fprintf (stderr, "=== Elf32_Shdr at 0x%08lx\n",
			(unsigned long int) (elf->Ehdr.e_shoff + walker * elf->Ehdr.e_shentsize));
		elf_dump_desc (elf, dh_Shdr, (void *) &elf->Shdr[walker],
			elf->Ehdr.e_shentsize);
	}

	return;
}


void
elf_dump_desc (elf_file *elf, dump_header *desc, unsigned char *src,
	unsigned long int len)
{
	if (desc == NULL || src == NULL || len == 0)
		return;

	while (desc->elem_name != NULL && len >= desc->advance) {
		elf_dump_print (elf, desc->type,
			(desc->data_val == 0 ? desc->data_tab :
			(void *) &desc->data_val),
			desc->elem_name, src);

		src += desc->advance;
		len -= desc->advance;

		desc++;
	};

	return;
}


void
elf_dump_print (elf_file *elf, char *format, void *formatparam, char *entname,
	unsigned char *val)
{
	int			flagged = 0,	/* use flagtable */
				isshort = 0;	/* do short print */
	int			gotbaseformat = 0;
	unsigned long int	cval = 0;	/* temporary conversion value */

	if (format == NULL)
		return;

	while (gotbaseformat == 0 && *format != '\0') {
		switch (*format) {
		case 'f':
			flagged = 1;
			break;
		case 's':
			isshort = 1;
			break;

		case 'h':	/* Elf32_Half */
		case 'm':	/* memory */
		case 'a':	/* Elf32_Addr  (handled as if Word) */
		case 'o':	/* Elf32_Off (handled as if Word) */
		case 'w':	/* Elf32_Word */
			gotbaseformat = 1;
			break;

		case 'i':	/* ignore */
			return;
		}

		format += 1;
	}

	if (gotbaseformat == 0)
		return;

	format -= 1;

	if (isshort == 0) {
		fprintf (stderr, "%.15s | %-25s | ",
			(elf != NULL && elf->pathname != NULL) ? elf->pathname : "?",
			entname != NULL ? entname : "?");
	}

	switch (*format) {
	case 'h':
		cval = *((unsigned short int *) val);

		fprintf (stderr, (isshort) ? "%04x " : "0x%04x",
			*((unsigned short int *) val));

		if (flagged == 0 && formatparam != NULL) {
			fprintf (stderr, (isshort) ? " %-12s | " : " = (%s)",
				elf_dump_tablookup ((dump_elem *) formatparam,
					*((unsigned short int *) val)));
		}
		break;

	case 'a':
	case 'o':
	case 'w':
		cval = *((unsigned long int *) val);

		fprintf (stderr, (isshort) ? "%08lx " : "0x%08lx",
			*((unsigned long int *) val));

		if (flagged == 0 && formatparam != NULL) {
			fprintf (stderr, (isshort) ? " %-12s | " : " = (%s)",
				elf_dump_tablookup ((dump_elem *) formatparam,
				*((unsigned long int *) val)));
		}
		break;

	case 'm': {
		unsigned long int	count = 0;

		while (count < *((unsigned long int *) formatparam)) {
			fprintf (stderr, (isshort) ? "%02x " : "0x%02x ",
				val[count]);
			count += 1;
		}
	}
	}

	if (isshort == 0 && flagged != 0 && formatparam != NULL) {
		int		fcount = 0;
		dump_elem *	tab = (dump_elem *) formatparam;

		fprintf (stderr, " = (");

		while (tab->name != NULL) {
			if ((cval & tab->value) == tab->value) {
				if (fcount > 0)
					fprintf (stderr, " | ");
				fprintf (stderr, "%s", tab->name);
				fcount += 1;
			}
			cval &= ~tab->value;

			++tab;
		}

		fprintf (stderr, ")");
		if (cval != 0)
			fprintf (stderr, " INVALID FLAGS: 0x%08lx", cval);
	}

	if (isshort == 0)
		fprintf (stderr, "\n");

	return;
}


char *
elf_dump_tablookup (dump_elem *tab, unsigned long int val)
{
	if (tab == NULL)
		return ("");

	/* TODO: lookup */
	while (tab->name != NULL) {
		if (tab->value == val)
			return (tab->name);
		++tab;
	}

	return ("INVALID");
}


