/* objwriter.c - ELF relocateable/relinkable object file writing code
 *
 * by scut / teso
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>

#include <common.h>
#include <elf/elf_base.h>
#include <ia32/ia32-decode.h>
#include <ia32/ia32-encode.h>
#include <ia32/ia32-function.h>
#include <ia32/ia32-trace.h>
#include <objwriter.h>
#include <codegen.h>
#include <morph.h>
#include <utility.h>


/*** EXTERNS */

extern obfuscation_param	obf;


/*** STATIC prototypes */

static void
obj_write_section (FILE *fp, elf_section *sec);

static void
obj_symtab_correct_sections (elf_section *symtab);

static Elf32_Sym *
obj_sec_find_syment (elf_base *base, unsigned int old_secidx);

static elf_section *
obj_build_relocation_section (unsigned int this_idx, elf_section *codesec,
	ia32_function **flist, unsigned int flist_count);

static void
obj_bblock_memlift (ia32_bblock *bb);

static void
obj_bblock_fold (ia32_bblock *bb);

static void
obj_bblock_fold_reloc (ia32_bblock *bb, unsigned int bb_rel_start,
	unsigned int add_len);

static void
obj_func_linearize (unsigned int start, ia32_bblock **bbl,
	unsigned int bbl_count, unsigned char **dest, unsigned int *dest_len,
	int nice);

static void
bblock_grow (unsigned char **mem, unsigned int *mem_len, unsigned int mem_start,
	ia32_bblock *bb, unsigned int grow_size,
	ia32_bblock **bbl, unsigned int bbl_count);

static unsigned int
bblock_fixup_end (unsigned char *mem, unsigned int mem_start, ia32_bblock *bb);

static int
bblock_fixup_end_single (ia32_bblock *bb, unsigned int i_vaddr,
	unsigned char *i_mem, int br_idx);

static int
obj_ia32_bbconv_pass_to_transfer (ia32_bblock *source, unsigned char *i_mem,
	ia32_bblock *target);

static long file_advance_roundup (FILE *fp, unsigned int padding);

static void
obj_bblist_randomize (ia32_bblock **all, unsigned int all_count);


/* global constants
 */
	/* bytes needed to convert a BR_END_PASS branch end to a
	 * BR_END_TRANSFER end, one for the opcode one for the 8 bit
	 * displacement.
	 */
#define	OBJ_BBCONV_PASS_TO_TRANSFER_8	(1 + 1)
#define	OBJ_BB_IF_FIXUP_SIZE		(1 + 1)

/* global static data
 */
#define	OBJ_QUEUE_LEN	128
static Elf32_Shdr	shdr_queue[OBJ_QUEUE_LEN];
static elf_section *	sec_queue[OBJ_QUEUE_LEN];
static unsigned int	old_to_new_shdr_map[OBJ_QUEUE_LEN];
static int		s_queue_ptr;

/*** IMPLEMENTATION */

int
obj_write (char *filename, elf_base *base,
	ia32_function **flist, unsigned int flist_count, obfuscation_param *obf)
{
	FILE *		fp;
	Elf32_Ehdr	ehdr;

	int		sw;	/* section header walker */
	int		strtab_idx = - 1;

	Elf32_Shdr *	sh;
	unsigned char *	shs_data = NULL;
	unsigned int	shs_len = 0;

	Elf32_Word *	symtab_idx_stack[OBJ_QUEUE_LEN];
	unsigned int	st_sp = 0,
			st_wlk;
	int		symtab_idx;
	elf_section *	cur = NULL;	/* section walker */
	elf_section *	wlk;	/* section walker */


	fp = fopen (filename, "w+");
	if (fp == NULL)
		return (1);

	memset (&ehdr, 0x00, sizeof (ehdr));
	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;

	ehdr.e_ident[EI_CLASS] = ELFCLASS32;
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
	ehdr.e_ident[EI_ABIVERSION] = 0;

	ehdr.e_type = ET_REL;
	ehdr.e_machine = EM_386;
	ehdr.e_version = EV_CURRENT;

	ehdr.e_entry = 0x0;
	ehdr.e_phoff = 0;
	/* ehdr.e_shoff is patched in later */
	ehdr.e_flags = 0;
	ehdr.e_ehsize = sizeof (Elf32_Ehdr);
	ehdr.e_phentsize = ehdr.e_phnum = 0;
	ehdr.e_shentsize = sizeof (Elf32_Shdr);
	/* ehdr.e_shnum and ehdr.e_shstrndx are patched in later */

	if (fwrite (&ehdr, sizeof (Elf32_Ehdr), 1, fp) != 1) {
		perror ("fwrite Ehdr");
		goto bail;
	}

	/* initialize global data
	 */
	memset (shdr_queue, 0x00, sizeof (shdr_queue));
	memset (sec_queue, 0x00, sizeof (sec_queue));
	memset (old_to_new_shdr_map, 0x00, sizeof (old_to_new_shdr_map));
	s_queue_ptr = 1;

	/* 1. write out all functions
	 */
	obj_calculate_bblock_mem (flist, flist_count);

	assert (base->seclist != NULL);
	for (sw = 0 ; sw < base->seclist->elem_count ; ++sw) {
		unsigned int	sh_fpos;	/* file position of codesec */

		cur = base->seclist->list[sw];

		/* only process code sections
		 */
		if ((cur->Shdr.sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) !=
			(SHF_ALLOC | SHF_EXECINSTR))
			continue;

		old_to_new_shdr_map[sw] = s_queue_ptr;

		/* setup section header and position
		 */
		fnote ("%s: writing out code section\n", cur->name);

		sec_queue[s_queue_ptr] = cur;
		memcpy (&shdr_queue[s_queue_ptr], &cur->Shdr,
			sizeof (Elf32_Shdr));
		sh_fpos = file_advance_roundup (fp, cur->Shdr.sh_addralign);
		shdr_queue[s_queue_ptr].sh_offset = sh_fpos;

		obj_write_funclist (fp, base, flist, flist_count, sh_fpos, obf);

		shdr_queue[s_queue_ptr].sh_size = file_advance_roundup (fp, 0) -
			shdr_queue[s_queue_ptr].sh_offset;

		s_queue_ptr += 1;

		/* and just append the appropiate relocation section
		 */
		cur = sec_queue[s_queue_ptr] = obj_build_relocation_section
			(s_queue_ptr, cur, flist, flist_count);

		if (cur == NULL || cur->data_len == 0)
			continue;

		memcpy (&shdr_queue[s_queue_ptr], &cur->Shdr,
			sizeof (Elf32_Shdr));

		wlk = elf_section_list_find_type (base->seclist, SHT_REL, NULL);
		while (wlk != NULL) {
			if (wlk->Shdr.sh_info == sw)
				break;

			wlk = elf_section_list_find_type (base->seclist,
				SHT_REL, wlk);
		}
		old_to_new_shdr_map[wlk->sh_idx] = s_queue_ptr;

		/* add the symtab sh_link index element of the relocation
		 * section header to a write stack. before the section headers
		 * are written out, all locations in this stack are fixed.
		 */
		symtab_idx_stack[st_sp++] = &shdr_queue[s_queue_ptr].sh_link;

		shdr_queue[s_queue_ptr].sh_offset =
			file_advance_roundup (fp, cur->Shdr.sh_addralign);

		if (fwrite (cur->data, cur->data_len, 1, fp) != 1) {
			perror ("fwrite relocation section data");
			goto bail;
		}

		shdr_queue[s_queue_ptr].sh_size = file_advance_roundup (fp, 0) -
			shdr_queue[s_queue_ptr].sh_offset;

		s_queue_ptr += 1;
	}

	/* 2. write out all data sections
	 */
	for (sw = 0 ; sw < base->seclist->elem_count ; ++sw) {
		cur = base->seclist->list[sw];
		if (((cur->Shdr.sh_flags & (SHF_ALLOC | SHF_EXECINSTR)) !=
			SHF_ALLOC) &&
			cur->Shdr.sh_type != SHT_STRTAB)
			continue;

		/* do not write out the section header string table yet
		 */
		if (cur->Shdr.sh_type == SHT_STRTAB) {
			if (strcmp (cur->name, ".shstrtab") == 0)
				continue;

			if (strcmp (cur->name, ".strtab") == 0)
				strtab_idx = s_queue_ptr;
		}

		obj_write_section (fp, cur);
	}

	/* 3. write the relocation sections of data sections written so far.
	 */
	for (sw = 0 ; sw < base->seclist->elem_count ; ++sw) {
		Elf32_Shdr *	refer;	/* the section the rel refers to */

		cur = base->seclist->list[sw];
		if (cur->Shdr.sh_type != SHT_REL)
			continue;

		/* process only relocation sections which refer to data,
		 * non-code sections
		 */
		refer = &shdr_queue[old_to_new_shdr_map[cur->Shdr.sh_info]];
		if (refer->sh_type != SHT_PROGBITS ||
			(refer->sh_flags & SHF_EXECINSTR) != 0)
			continue;

		symtab_idx_stack[st_sp++] = &shdr_queue[s_queue_ptr].sh_link;
		obj_write_section (fp, cur);
	}

	/* 4. write modified symbol table
	 */
	for (sw = 0 ; sw < base->seclist->elem_count ; ++sw) {
		elf_section *	strw;

		cur = base->seclist->list[sw];

		if (cur->Shdr.sh_type != SHT_SYMTAB)
			continue;

		old_to_new_shdr_map[cur->sh_idx] = s_queue_ptr;

		/* also update the new section header index of ".shstrtab"
		 * section.
		 */
		strw = NULL;
		do {
			strw = elf_section_list_find_type (base->seclist,
				SHT_STRTAB, strw);

			if (strw == NULL)
				break;

			if (strcmp (strw->name, ".shstrtab") == 0) {
				old_to_new_shdr_map[strw->sh_idx] =
					s_queue_ptr + 1;
				break;
			}
		}  while (1);

		/* now update all section indexes
		 */
		obj_symtab_correct_sections (cur);
		break;
	}
	assert (cur != NULL);
	obj_write_section (fp, cur);

	/* 5. create .shstrtab section, skipping the zero section header.
	 */
	shs_len += 1;
	shs_data = xrealloc (shs_data, shs_len);
	shs_data[0] = '\0';

	for (sw = 1 ; sw < s_queue_ptr ; ++sw) {
		unsigned int	name_len;

		assert (sec_queue[sw]->name != NULL);
		name_len = strlen (sec_queue[sw]->name) + 1;

		shs_data = xrealloc (shs_data, shs_len + name_len);
		memcpy (&shs_data[shs_len], sec_queue[sw]->name, name_len);
		shdr_queue[sw].sh_name = shs_len;
		shs_len += name_len;
	}

	sec_queue[s_queue_ptr] = NULL;
	sh = &shdr_queue[s_queue_ptr];
	shs_data = xrealloc (shs_data, shs_len + strlen (".shstrtab") + 1);
	memcpy (&shs_data[shs_len], ".shstrtab", strlen (".shstrtab") + 1);
	sh->sh_name = shs_len;
	shs_len += strlen (".shstrtab") + 1;

	sh->sh_type = SHT_STRTAB;
	sh->sh_flags = 0;
	sh->sh_addr = 0x0;
	sh->sh_offset = file_advance_roundup (fp, 0x1);
	sh->sh_size = shs_len;
	sh->sh_link = sh->sh_info = 0;
	sh->sh_addralign = 1;
	sh->sh_entsize = 0;

	ehdr.e_shstrndx = s_queue_ptr;
	s_queue_ptr += 1;

	if (fwrite (shs_data, shs_len, 1, fp) != 1) {
		perror ("fwrite shstrtab data");
		goto bail;
	}

	/* 6. write section header table to file, after doing:
	 *    - fixup of .symtab sh_link element
	 */
	ehdr.e_shoff = file_advance_roundup (fp, 0x10);
	ehdr.e_shnum = s_queue_ptr;

	assert (strtab_idx >= 0);

	symtab_idx = -1;
	for (sw = 0 ; sw < s_queue_ptr ; ++sw) {
		if (shdr_queue[sw].sh_type == SHT_SYMTAB) {
			symtab_idx = sw;
			shdr_queue[sw].sh_link = strtab_idx;
			break;
		}
	}
	assert (symtab_idx >= 0);

	for (st_wlk = 0 ; st_wlk < st_sp ; ++st_wlk)
		*symtab_idx_stack[st_wlk] = symtab_idx;

	for (sw = 0 ; sw < s_queue_ptr ; ++sw) {
		if (shdr_queue[sw].sh_type == SHT_SYMTAB)
			shdr_queue[sw].sh_link = strtab_idx;

		if (fwrite (&shdr_queue[sw], sizeof (Elf32_Shdr), 1, fp) != 1) {
			perror ("fwrite section header");
			goto bail;
		}
	}

	/* 7. overwrite ELF header */
	fseek (fp, 0, SEEK_SET);
	if (fwrite (&ehdr, sizeof (Elf32_Ehdr), 1, fp) != 1) {
		perror ("fwrite 2nd pass elf header");
		goto bail;
	}

	fclose (fp);
	return (0);
bail:
	fclose (fp);
	return (1);
}


/* obj_write_section
 *
 * central section spill function, writing the section `sec' to the file `fp',
 * taking care of alignment and global section stack.
 *
 * return in any case (or bail on failure)
 */

static void
obj_write_section (FILE *fp, elf_section *sec)
{
	fnote ("%s: writing out section\n", sec->name);

	sec_queue[s_queue_ptr] = sec;
	memcpy (&shdr_queue[s_queue_ptr], &sec->Shdr, sizeof (Elf32_Shdr));

	old_to_new_shdr_map[sec->sh_idx] = s_queue_ptr;

	if (sec->Shdr.sh_type == SHT_REL)
		shdr_queue[s_queue_ptr].sh_info =
			old_to_new_shdr_map[sec->Shdr.sh_info];

	shdr_queue[s_queue_ptr].sh_offset =
		file_advance_roundup (fp, sec->Shdr.sh_addralign);

	if (sec->data_len > 0) {
		if (fwrite (sec->data, sec->data_len, 1, fp) != 1) {
			perror ("fwrite relocation section data");

			exit (EXIT_FAILURE);
		}
	}

	shdr_queue[s_queue_ptr].sh_size = file_advance_roundup (fp, 0) -
		shdr_queue[s_queue_ptr].sh_offset;

	/* TODO: correct global symbol table for sections */

	s_queue_ptr += 1;
}


/* obj_build_relocation_section
 *
 * build one relocation section for a code section `codesec'. the code section
 * must have the section index `this_idx'-1, and the relocation section takes
 * up `this_idx'. all functions within `flist' that are within the code
 * section are processed. `flist' is `flist_count' items long.
 *
 * return the new elf relocation section created on success
 * return NULL on failure or if there are no relocation entries
 */

static elf_section *
obj_build_relocation_section (unsigned int this_idx, elf_section *codesec,
	ia32_function **flist, unsigned int flist_count)
{
	unsigned int	fn;
	elf_section *	sec;

	unsigned int	rel_count = 0;
	Elf32_Rel *	rel_data = NULL;
	Elf32_Rel	rel;


	sec = elf_section_create ();
	assert (codesec->name != NULL);
	sec->name = xcalloc (1, strlen (".rel") + strlen (codesec->name) + 1);
	strcat (sec->name, ".rel");
	strcat (sec->name, codesec->name);

	sec->sh_idx = this_idx;

	/* sec->Shdr.sh_name is filled in later */
	sec->Shdr.sh_type = SHT_REL;
	sec->Shdr.sh_flags = 0;
	sec->Shdr.sh_addr = 0x0;
	/* sec->Shdr.sh_offset and .sh_size are filled in later */
	sec->Shdr.sh_info = this_idx - 1;
	sec->Shdr.sh_addralign = 0x04;
	sec->Shdr.sh_entsize = sizeof (Elf32_Rel);


	for (fn = 0 ; fn < flist_count ; ++fn) {
		ia32_bblock **	all;	/* list of all basic blocks in func */
		unsigned int	all_count,	/* number of blocks in list */
				alw,	/* basic block walker */
				ow;	/* other xref walker */
		ia32_xref **	xrarr;

		all = ia32_br_get_all (flist[fn]->br_root, &all_count);

		for (alw = 0 ; alw < all_count ; ++alw) {
			xrarr = (ia32_xref **) all[alw]->other_xref;

			memset (&rel, 0x00, sizeof (rel));

			/* walk all cross references and create relocations
			 * for each one
			 */
			for (ow = 0 ; ow < all[alw]->other_xref_count ; ++ow) {
				fnote ("rel: 0x%04x:0x%04x + %d = 0x%04x\n",
					all[alw]->start, xrarr[ow]->from,
					xrarr[ow]->addend,
					all[alw]->start + xrarr[ow]->from +
						xrarr[ow]->addend);

				switch (xrarr[ow]->to_type) {
				case (IA32_XREF_FUNCTION):
				case (IA32_XREF_FUNCEXTERN):
				case (IA32_XREF_OTHER):
					rel.r_offset = all[alw]->start +
						xrarr[ow]->from +
						xrarr[ow]->addend;
					rel.r_info = xrarr[ow]->orig.r_info;
					break;
				default:
					assert (0);
					break;
				}

				rel_count += 1;
				rel_data = xrealloc (rel_data,
					rel_count * sizeof (Elf32_Rel));
				memcpy (&rel_data[rel_count - 1], &rel,
					sizeof (rel));
			}
		}

		if (all != NULL)
			free (all);
	}

	sec->data = (unsigned char *) rel_data;
	sec->data_len = rel_count * sizeof (Elf32_Rel);

	if (sec->data_len > 0)
		return (sec);

	free (sec);

	return (NULL);
}


/* obj_symtab_correct_sections
 *
 * correct the section indexes within the symbol table. as we spill the
 * sections in different order from the original, we have to update the
 * section indexes within the symbol table to match the new order. the symbol
 * table section `symtab' is changed.
 *
 * return in any case.
 */

static void
obj_symtab_correct_sections (elf_section *symtab)
{
	unsigned int	sent_count,	/* count of symbols */
			sidx;	/* symbol index walker */
	Elf32_Sym *	sw;	/* symbol table walker */


	assert (symtab != NULL);
	sent_count = symtab->data_len / sizeof (Elf32_Sym);

	for (sw = (Elf32_Sym *) symtab->data, sidx = 0 ;
		sidx < sent_count ; ++sidx, ++sw)
	{
/*		if (ELF32_ST_TYPE (sw->st_info) != STT_SECTION)
			continue;
*/
		if (sw->st_shndx == 0 || sw->st_shndx >= OBJ_QUEUE_LEN)
			continue;

		if (old_to_new_shdr_map[sw->st_shndx] != 0)
			sw->st_shndx = old_to_new_shdr_map[sw->st_shndx];
	}

#if 0
	Elf32_Sym *	stab_backup;
	unsigned int	oidx;	/* old symbol table index */

	/* this seems to be a GNU toolchain convention (insanity?):
	 * the section header index must be the same as the symbol table
	 * position for STT_SECTION objects.
	 * first order the entries and finally null'ifying out all unused
	 * positions (as we do not copy over sections such as .comment)
	 */
	stab_backup = xcalloc (sent_count, sizeof (Elf32_Sym));
	memcpy (stab_backup, symtab->data, sent_count * sizeof (Elf32_Sym));

	for (sw = (Elf32_Sym *) symtab->data, sidx = 0 ;
		sidx < sent_count ; ++sidx, ++sw)
	{
		if (ELF32_ST_TYPE (sw->st_info) != STT_SECTION)
			continue;

		for (oidx = 0 ; oidx < (sizeof (old_to_new_shdr_map) /
			sizeof (old_to_new_shdr_map[0])) ; ++oidx)
		{
			if (old_to_new_shdr_map[oidx] == sidx)
				break;
		}

		if ((ELF32_ST_TYPE (((Elf32_Sym *) symtab->data)[oidx].st_info)) != STT_SECTION)
			continue;

		/* unused section in symbol table, copy over NULL section
		 */
		if (oidx == (sizeof (old_to_new_shdr_map) /
			sizeof (old_to_new_shdr_map[0])))
		{
			oidx = 0;
		}

		memcpy (sw, &stab_backup[oidx], sizeof (Elf32_Sym));
	}

	free (stab_backup);
#endif

	/* find the first global symbol and write its index into st_info.
	 * (this is os specific behaviour, GNU toolchain)
	 */
	for (sw = (Elf32_Sym *) symtab->data, sidx = 0 ;
		sidx < sent_count ; ++sidx, ++sw)
	{
		if (ELF32_ST_BIND (sw->st_info) == STB_GLOBAL) {
			symtab->Shdr.sh_info = sidx;
			break;
		}
	}
}


/* obj_sec_find_syment
 *
 * find the STT_SECTION symbol table entry of the section that had the index
 * `old_secidx'. the search is carried out within `base'.
 *
 * return NULL on failure (no appropiate symbol entry found)
 * return pointer to Elf32_Sym element within section on success
 */

static Elf32_Sym *
obj_sec_find_syment (elf_base *base, unsigned int old_secidx)
{
	unsigned int	sent_count,	/* count of symbols */
			sidx;	/* symbol index walker */
	Elf32_Sym *	sw;	/* symbol table walker */


	assert (base != NULL && base->symtab != NULL && base->seclist != NULL);
	sent_count = base->symtab->data_len / sizeof (Elf32_Sym);

	for (sw = (Elf32_Sym *) base->symtab->data, sidx = 0 ;
		sidx < sent_count ; ++sidx, ++sw)
	{
		if (ELF32_ST_TYPE (sw->st_info) == STT_SECTION &&
			sw->st_shndx == old_secidx)
			return (sw);
	}

	return (NULL);
}


Elf32_Sym *
obj_func_find_syment (elf_base *base, ia32_function *func)
{
	unsigned int	sent_count,	/* count of symbols */
			sidx;	/* symbol index walker */
	Elf32_Sym *	sw;	/* symbol table walker */
	elf_section *	strtab;	/* string table to resolve function names */

	assert (base != NULL && base->symtab != NULL && base->seclist != NULL);
	strtab = elf_section_list_find_name (base->seclist, ".strtab");
	assert (strtab != NULL); 

	sent_count = base->symtab->data_len / sizeof (Elf32_Sym);
	for (sw = (Elf32_Sym *) base->symtab->data, sidx = 0 ;
		sidx < sent_count ; ++sidx, ++sw)
	{
		if (sw->st_shndx != func->section_idx ||
			ELF32_ST_TYPE (sw->st_info) != STT_FUNC)
			continue;

		assert (sw->st_name < strtab->data_len);
		if (strcmp (func->name, &strtab->data[sw->st_name]) != 0)
			continue;

		return (sw);
	}

	return (NULL);
}


void
obj_flist_memlift (ia32_function **flist, unsigned int flist_count)
{
	ia32_bblock **	all;
	unsigned int	all_count,
			bn;

	all = obj_bblist_build (flist, flist_count, &all_count);
	assert (all != NULL && all_count > 0);

	for (bn = 0 ; bn < all_count ; ++bn)
		obj_bblock_memlift (all[bn]);

	free (all);
}


int
obj_write_funclist (FILE *fp, elf_base *base, ia32_function **flist,
	unsigned int flist_count, unsigned int code_sec_start,
	obfuscation_param *obf)
{
	ia32_bblock **	all;
	unsigned int	all_count,
			fn,	/* function list walker */
			addr;
	unsigned char *	dest = NULL;
	unsigned int	dest_len;
	int		rval = 0;


	all = obj_bblist_build (flist, flist_count, &all_count);
	assert (all != NULL && all_count > 0);

	if (obf->entangle_basic)
		obj_bblist_randomize (all, all_count);

	/* write basic blocks to file, being non-"nice". this is impossible
	 * when writing multiple functions (as there are multiple ret blocks).
	 */
	addr = file_advance_roundup (fp, 0x4) - code_sec_start;
	obj_func_linearize (addr, all, all_count, &dest, &dest_len, 0);
	free (all);

	if (fwrite (dest, dest_len, 1, fp) != 1) {
		perror ("fwrite function list");
		rval = 1;

		goto bail;
	}

	/* now fixup all function symbols
	 */
	for (fn = 0 ; fn < flist_count ; ++fn) {
		Elf32_Sym *	func_sym;	/* function symtab entry */

		/* fix start and end of each function
		 */
		flist[fn]->start = flist[fn]->br_root->start;
		/* FIXME: correct? flist[fn]->end = flist[fn]->start;*/

		/* find the correct symbol table entry and update both
		 * the position. zero out the size, as there is no obvious
		 * meaningful definition of an entangled function's size.
		 */
		func_sym = obj_func_find_syment (base, flist[fn]);
		assert (func_sym != NULL);

		func_sym->st_value = flist[fn]->start;
		func_sym->st_size = 0x0;
	}

bail:
	if (dest != NULL)
		free (dest);

	return (rval);
}


/* obj_bblist_randomize
 *
 * randomize the order of the basic blocks in `all', which is `all_count'
 * items long.
 *
 * return in any case
 */

static void
obj_bblist_randomize (ia32_bblock **all, unsigned int all_count)
{
	unsigned int	scw;	/* storing crosswalker */
	int		idx;	/* countdown index */
	ia32_bblock **	new;

	new = xcalloc (all_count, sizeof (ia32_bblock *));
	for (idx = all_count - 1 ; idx >= 0 ; --idx) {
		scw = be_random (all_count);
		while (new[scw] != NULL)
			scw = (scw + 1) % all_count;

		new[scw] = all[idx];
	}

	memcpy (all, new, all_count * sizeof (ia32_bblock *));
	free (new);
}


ia32_bblock **
obj_bblist_build (ia32_function **flist, unsigned int flist_count,
	unsigned int *count)
{
	ia32_bblock **	this_list;
	unsigned int	this_count,
			fn;	/* function list walker */
	ia32_bblock **	all = NULL;
	unsigned int	all_count = 0;


	/* for each function in the list, create a list of basic blocks and
	 * append it to the main list.
	 */
	for (fn = 0 ; fn < flist_count ; ++fn) {
		if (flist[fn]->is_copy)
			continue;

		this_list = ia32_br_get_all (flist[fn]->br_root, &this_count);
		if (this_list == NULL || this_count == 0)
			continue;
 
		all = xrealloc (all, (all_count + this_count) *
			sizeof (ia32_bblock *));
		memcpy (&all[all_count], this_list,
			this_count * sizeof (ia32_bblock *));

		all_count += this_count;
		free (this_list);
	}

	*count = all_count;
	return (all);
}


int
obj_write_func (FILE *fp, elf_base *base, ia32_function *func,
	unsigned int code_sec_start)
{
	ia32_bblock **	all;
	unsigned int	all_count,
			addr;	/* current in-section address */
	unsigned char *	dest = NULL;
	unsigned int	dest_len;

	/* do not write out dupe functions
	 */
	if (func->is_copy)
		return (0);

	addr = func->start = file_advance_roundup (fp, 0x4) - code_sec_start;
	func->end = 0x0;

	all = ia32_br_get_all (func->br_root, &all_count);
	obj_func_linearize (func->start, all, all_count, &dest, &dest_len, 1);
	free (all);

	if (fwrite (dest, dest_len, 1, fp) != 1) {
		perror ("fwrite function");
		if (dest != NULL)
			free (dest);

		return (1);
	}

	func->end = func->start + dest_len;

	if (dest != NULL)
		free (dest);

	return (0);
}


/* obj_bblock_memlift
 *
 * move the static referenced basic block memory in `bb->mem' to a unique
 * allocation.
 *
 * return in any case
 */

static void
obj_bblock_memlift (ia32_bblock *bb)
{
	unsigned char *	mem_new;
	unsigned int	mem_len;

	if (bb->mem_allocated)
		return;

	mem_len = bb->end - bb->start;
	if (mem_len == 0)
		mem_len = 1;

	mem_new = xcalloc (1, mem_len);
	memcpy (mem_new, bb->mem, bb->end - bb->start);
	bb->mem = mem_new;
	bb->mem_allocated = 1;
}


/* obj_bblock_fold
 *
 * for a memlifted basic block `bb', insert all opaque instructions inbetween.
 *
 * return in any case
 */

static void
obj_bblock_fold (ia32_bblock *bb)
{
	ia32_bb_user *		bb_user;
	instr_array *		ia;
	unsigned int		i_ptr,	/* bb instruction pointer */
				iic;	/* instruction insert counter */
	unsigned char *		bbm;	/* basic block memory pointer */
	ia32_instruction *	inst,
				inst_s;
	unsigned int		bbm_rel,
				new_inst_len,
				move_length;
	unsigned char		new_inst[16+1];


	bb_user = (ia32_bb_user *) bb->user;
	if (bb_user == NULL)
		return;
	ia = (instr_array *) bb_user->instr_insert;
	if (ia == NULL)
		return;

	assert (bb->mem_allocated);
	bbm = bb->mem;

	for (i_ptr = 0 ; i_ptr < ia->in_count ; ++i_ptr) {
		for (iic = 0 ; iic < ia->in_points_icount[i_ptr] ; ++iic) {
			new_inst_len = ia32_encode_instruction
				(ia->in_points_opcode[i_ptr][iic],
				&ia->in_points[i_ptr][iic], new_inst);
			assert (new_inst_len > 0);

			if (obf.junk_debug) {
				memmove (&new_inst[1], &new_inst[0],
					sizeof (new_inst) - 1);
				new_inst[0] = IA32_OPCODE_NOP;
				new_inst_len += 1;
			}

			bbm_rel = bbm - bb->mem;
#if 0
			printf ("bb length: 0x%x, bbm_rel: 0x%x\n",
				bb->end - bb->start, bbm_rel);
#endif
			bb->mem = xrealloc (bb->mem, bb->end - bb->start +
				new_inst_len);
			bbm = bb->mem + bbm_rel;

			move_length = (bb->end - bb->start) - (bbm - bb->mem);
#if 0
			printf ("memmove (0x%08x, 0x%08x, %d) (new_inst_len = %d)\n",
				(unsigned int) (bbm + new_inst_len),
				(unsigned int) bbm, move_length, new_inst_len);
#endif
			memmove (bbm + new_inst_len, bbm, move_length);
			memcpy (bbm, new_inst, new_inst_len);

			obj_bblock_fold_reloc (bb, bbm - bb->mem, new_inst_len);

			bbm += new_inst_len;
			bb->end += new_inst_len;
		}

		inst = ia32_decode_instruction (bbm, &inst_s);
		assert (inst != NULL);
		bbm += inst->length;
	}
}


/* obj_bblock_fold_reloc
 *
 * shift all relocations in `bb' by `add_len' bytes, if they lie after
 * `bb_rel_start'.
 *
 * return in any case
 */

static void
obj_bblock_fold_reloc (ia32_bblock *bb, unsigned int bb_rel_start,
	unsigned int add_len)
{
	unsigned int	xn;
	ia32_xref **	xrarr = (ia32_xref **) bb->other_xref;

	for (xn = 0 ; xn < bb->other_xref_count ; ++xn) {
		if (xrarr[xn]->from >= bb_rel_start)
			xrarr[xn]->from += add_len;
	}
}


void
obj_bblock_move_reloc (ia32_bblock *bb, unsigned int i_start,
	unsigned int i_len, int move_offset, int *dont_touch)
{
	ia32_xref **	xrarr = (ia32_xref **) bb->other_xref;
	ia32_xref *	cur;
	unsigned int	xn;


	for (xn = 0 ; xn < bb->other_xref_count ; ++xn) {
		cur = (ia32_xref *) xrarr[xn];
#if 0
		printf ("i_start = 0x%x, i_len = %d, cur->from = 0x%x(+%d)\n",
			i_start, i_len, cur->from, cur->addend);
#endif

		if (dont_touch != NULL && dont_touch[xn])
			continue;

		if (cur->from < i_start ||
			(cur->from + cur->addend) >= (i_start + i_len))
			continue;

#if 0
		printf ("   move reloc at 0x%x(+%d) by %d\n",
			cur->from, cur->addend, move_offset);
#endif
		cur->from += move_offset;

		if (dont_touch != NULL)
			dont_touch[xn] = 1;
	}
}


ia32_xref **
obj_bblock_copy_reloc (ia32_bblock *bb)
{
	ia32_xref **	xnew;
	ia32_xref **	xrarr = (ia32_xref **) bb->other_xref;
	unsigned int	xn;

	if (bb->other_xref_count == 0)
		return (NULL);

	xnew = xcalloc (bb->other_xref_count, sizeof (ia32_xref *));

	for (xn = 0 ; xn < bb->other_xref_count ; ++xn) {
		xnew[xn] = xcalloc (1, sizeof (ia32_xref));
		memcpy (xnew[xn], xrarr[xn], sizeof (ia32_xref));
	}

	return (xnew);
}


void
obj_bblock_split_reloc (ia32_bblock *bb1, ia32_bblock *bb2)
{
	unsigned int	xn,
			bb1_size,
			bb1_xcount,
			bb2_xcount;
	ia32_xref **	bb1_xrarr = (ia32_xref **) bb1->other_xref;
	ia32_xref **	bb2_xrarr;

	bb1_size = bb1->end - bb1->start;
	bb2_xrarr = xcalloc (bb1->other_xref_count, sizeof (ia32_xref *));
	memcpy (bb2_xrarr, bb1_xrarr,
		bb1->other_xref_count * sizeof (ia32_xref *));

	/* 1. distribute disjunct sets among the two blocks
	 */
	for (xn = 0 ; xn < bb1->other_xref_count ; ++xn) {
#if 0
		printf ("reloc at rel %d (bb1_size = %d)\n", bb1_xrarr[xn]->from,
			bb1_size);
#endif
		if (bb1_xrarr[xn]->from < bb1_size) {
			bb2_xrarr[xn] = NULL;
		} else {
			bb1_xrarr[xn] = NULL;
			bb2_xrarr[xn]->from -= bb1_size;
		}
	}

	/* 2. compaction
	 */
	bb1_xcount = array_compaction (bb1_xrarr, bb1->other_xref_count);
	bb2_xcount = array_compaction (bb2_xrarr, bb1->other_xref_count);

	/* 3. reallocation and block update
	 */
	bb1_xrarr = xrealloc (bb1_xrarr, bb1_xcount * sizeof (ia32_xref *));
	bb1->other_xref_count = bb1_xcount;
	bb1->other_xref = bb1_xrarr;

	bb2_xrarr = xrealloc (bb2_xrarr, bb2_xcount * sizeof (ia32_xref *));
	bb2->other_xref_count = bb2_xcount;
	bb2->other_xref = bb2_xrarr;
}

/* obj_func_linearize
 *
 * linearize all basic blocks in list `bbl' of a function into a sequential
 * order. the memory used is dynamically allocated to `dest', which is at the
 * end of the processing `dest_len' bytes long. the function which is
 * linearized starts at virtual address `start' within the current section.
 * note that the basic blocks of the function can be changed by this function
 * (in rare case of conditional near jump translation). if `nice' is set to
 * non-zero, we try to spill the function nicely according to compiler
 * conventinos, else we allow/encourage hostile ordering.
 *
 * return in any case
 */

static void
obj_func_linearize (unsigned int start, ia32_bblock **bbl,
	unsigned int bbl_count, unsigned char **dest, unsigned int *dest_len,
	int nice)
{
	unsigned char *	mem = NULL;
	unsigned int	mem_len = 0,
			blw,
			bblock_len,
			addr = 0;
	int		ret_bblock_idx = -1;
	int		changed = 0;


	for (blw = 0 ; blw < bbl_count ; ++blw) {
		obj_bblock_memlift (bbl[blw]);

		obj_bblock_fold (bbl[blw]);
	}

	for (blw = 0 ; blw < bbl_count ; ++blw) {
		/* comply with some implicit compiler assumptions that the
		 * "ret" block must be the last in linear form. save the index
		 * and dump it as last, later.
		 */
		if (nice && bbl[blw]->endtype == BR_END_RET) {
			ret_bblock_idx = blw;
			continue;
		}

		bblock_len = bbl[blw]->end - bbl[blw]->start;
		bbl[blw]->start = start + addr;
		bbl[blw]->end = start + addr + bblock_len;

		mem_len += bblock_len;
		mem = xrealloc (mem, mem_len);
		memcpy (&mem[addr], bbl[blw]->mem, bblock_len);

		addr += bblock_len;
	}

	/* do the special end basic block
	 */
	if (ret_bblock_idx != -1) {
		bblock_len = bbl[ret_bblock_idx]->end -
			bbl[ret_bblock_idx]->start;
		bbl[ret_bblock_idx]->start = start + addr;
		bbl[ret_bblock_idx]->end = start + addr + bblock_len;

		mem_len += bblock_len;
		mem = xrealloc (mem, mem_len);
		memcpy (&mem[addr], bbl[ret_bblock_idx]->mem, bblock_len);

		addr += bblock_len;
	}

	/* now that all blocks are linearized in memory, try to fixup all
	 * ends. use simple go-to-start backtracking when a change may require
	 * changes in other basic blocks.
	 */
	do {
		/* additional length required to do the fixup
		 */
		unsigned int	add_len;

		changed = 0;

		for (blw = 0 ; changed == 0 && blw < bbl_count ; ++blw) {
			add_len = bblock_fixup_end (mem, start, bbl[blw]);

			/* no size change required, hence other basic blocks
			 * are unaffected by fixup.
			 */
			if (add_len == 0)
				continue;

			fnote ("  bblock at 0x%04x-0x%04x requests %d byte "
				"enlargement\n", bbl[blw]->start, bbl[blw]->end,
				add_len);
			bblock_grow (&mem, &mem_len, start, bbl[blw], add_len,
				bbl, bbl_count);
			changed = 1;

			break;
		}
	} while (changed == 1);

	*dest = mem;
	*dest_len = mem_len;
}


/* bblock_grow
 *
 * grow the basic block `bb' at the end by `grow_size' bytes. `mem' starts at
 * the virtual address `mem_start'. the basic block list `bbl' of the current
 * function has to be given, and is `bbl_count' items long.
 *
 * return in any case
 */

static void
bblock_grow (unsigned char **mem, unsigned int *mem_len, unsigned int mem_start,
	ia32_bblock *bb, unsigned int grow_size,
	ia32_bblock **bbl, unsigned int bbl_count)
{
	unsigned char *	src;
	unsigned int	len,
			bn;

	fnote ("bblow_grow: bb 0x%04x-0x%04x by %d\n",
		bb->start, bb->end, grow_size);

	assert (bb->mem_allocated);
	*mem_len += grow_size;
	*mem = xrealloc (*mem, *mem_len);

	src = *mem - mem_start + bb->end;
	len = *mem_len - (bb->end - mem_start + grow_size);
	memmove (src + grow_size, src, len);
	memset (src, IA32_OPCODE_INT3, grow_size);

	/*bb->last_ilen += grow_size;*/

	for (bn = 0 ; bn < bbl_count ; ++bn) {
		assert (bbl[bn]->last_ilen <= (bbl[bn]->end - bbl[bn]->start));
		assert (bbl[bn]->mem_allocated);

		/* blocks that lie in front of the grown one can be skipped,
		 * as their relative position has not changed. also, the
		 * special case of this block has to be considered, as we can
		 * have a zero size pass block which would be moved behind
		 * itself then.
		 */
		if (bbl[bn] == bb || bbl[bn]->start < bb->end)
			continue;

		bbl[bn]->start += grow_size;
		bbl[bn]->end += grow_size;
	}

	bb->end += grow_size;
	bb->last_unused += grow_size;
}


/* bblock_fixup_up
 *
 * fix the last instruction of the basic block `bb' to point correctly within
 * memory. to do this, we translate the symbolic reference in endbr[] to a
 * displacement or offset (depending on the instruction). the change will be
 * done in memory, to `mem', which starts at virtual address `mem_start'.
 * hence, the basic block starts in memory at (mem - mem_start + bb->start).
 *
 * TODO: merge with morph_br_fix_inst
 *
 * return number of extra bytes necessary to fixup this block on failure
 * return zero in case the block was/is properly fixed up
 */

static unsigned int
bblock_fixup_end (unsigned char *mem, unsigned int mem_start, ia32_bblock *bb)
{
	int			grow,
				conv;
	unsigned int		bn;	/* branch end walker */
	unsigned int		i_vaddr;
	unsigned char *		i_mem;
	ia32_instruction *	inst,
				inst_s;
	ia32_switchtable *	stab;	/* for use with BR_END_SWITCH */
	unsigned int		swlk;	/* switch table walker */


	fnote ("bblock_fixup_end: 0x%04x-0x%04x, last_ilen = %d, "
		"last_unused = %d, endtype = %d\n", bb->start, bb->end,
		bb->last_ilen, bb->last_unused, bb->endtype);

	switch (bb->endtype) {
		/* we also have to deal with _PASS blocks, as we may change
		 * the order and have to spill a jmp
		 */
	case (BR_END_PASS):
	case (BR_END_TRANSFER):
	case (BR_END_IF):
	case (BR_END_CALL):
	case (BR_END_CALL_EXTERN):
		break;

	case (BR_END_SWITCH):
		stab = (ia32_switchtable *) bb->switchtab;

		/* rather quick solution, using the assumption of the .text
		 * section symbol having a value of zero. as the value to be
		 * put is S + A, where S is zero, we just put the
		 * addend = address, which should work for any GCC generated
		 * object file.
		 */
		for (swlk = 0 ; swlk < stab->entries ; ++swlk) {
			/*printf ("storing case %2d: 0x%08x\n",
				swlk, bb->endbr[swlk]->start);*/
			stab->mem_start[swlk] = bb->endbr[swlk]->start;
		}

		return (0);
		/* any other we ignore */
	default:
		return (0);
	}

	/* ignore references to inter-function objects
	 */
	for (bn = 0 ; bb->endbr_external != NULL && bn < bb->endbr_count ; ++bn) {
		if (bb->endtype != BR_END_CALL && bb->endbr_external[bn]) {
			/* FIXME: what to do? */
			assert (0);
			return (0);
		}
	}

	i_vaddr = bb->end - bb->last_ilen - bb->last_unused;
	i_mem = mem - mem_start + i_vaddr;

	if (bb->endtype == BR_END_IF) {
		/* first fix the original "jump-away" case. this should be
		 * possible in any case (or notify us to make more room).
		 */
		grow = bblock_fixup_end_single (bb, i_vaddr, i_mem, 1);
		if (grow < 0)
			return (-grow);

		/* now that this case is fixed, we are worried by the original
		 * "fall-through" case. as we shuffle the basic blocks, it
		 * could be that we have to introduce a new transfer jump.
		 * first, the easy case: no fixup needed, as the fallthrough
		 * is still correct.
		 */
		if (bb->end == bb->endbr[0]->start)
			return (0);

		/* get length of this instruction
		 */
		inst = ia32_decode_instruction (i_mem, &inst_s);
		assert (inst != NULL);

		/* advance to instruction after the jcc
		 */
		i_vaddr += inst->length;
		i_mem += inst->length;

		/* if there is already a second instruction (ie we ran through
		 * this code already), then handle it directly. else request
		 * enough bytes to write an initial unconditional near jump.
		 */
		if (inst->length < bb->last_ilen) {
			int	jmp_length;

			jmp_length = bb->last_ilen - inst->length;
			if (jmp_length == OBJ_BB_IF_FIXUP_SIZE)
				i_mem[0] = IA32_OPCODE_JMPN;
			else
				i_mem[0] = IA32_OPCODE_JMPF;

			goto handle_case0;
		}

		if (bb->last_unused < OBJ_BB_IF_FIXUP_SIZE)
			return (OBJ_BB_IF_FIXUP_SIZE - bb->last_unused);

		/* advance to the fixup-instruction and write a jmp there
		 */
		bb->last_unused -= OBJ_BB_IF_FIXUP_SIZE;
		bb->last_ilen += OBJ_BB_IF_FIXUP_SIZE;

		i_mem[0] = IA32_OPCODE_JMPN;

		/* fall through to transfer handling. this works, as the fixup
		 * is done on the instruction only, not on the endtype.
		 */
	} else if (bb->endtype == BR_END_CALL) {
		unsigned int	xn;	/* cross reference walk index */
		ia32_xref *	xr;	/* .. walk pointer */

		/* object-local calls have to be adjusted and the pass'ing to
		 * the next basic block has to be corrected in case the
		 * original block order is changed.
		 */
#if 0
		printf ("** 0x%04x %s: 0x%02x 0x%02x 0x%02x 0x%02x 0x%02x\n",
			i_vaddr, bb->endtype == BR_END_CALL ? "BR_END_CALL" :
			"BR_END_CALL_EXTERN", i_mem[0], i_mem[1], i_mem[2],
			i_mem[3], i_mem[4]);
		printf ("   target: 0x%04x, last_ilen = %d, last_unused = %d\n",
			bb->endbr[1]->start, bb->last_ilen, bb->last_unused);
#endif
		for (xn = 0 ; xn < bb->other_xref_count ; ++xn) {
			xr = ((ia32_xref **) bb->other_xref)[xn];
#if 0
			if (xr->from == (i_vaddr - bb->start)) {
				printf ("   other xref, %s\n",
					xr->original_relocation ?
					"original relocation" : "made up");
			}
#endif
			if (xr->from == (i_vaddr - bb->start) &&
				xr->original_relocation)
			{
				bb->endtype = BR_END_CALL_EXTERN;

				goto call_reloc_handled;
			}
		}

		assert (bb->endbr_external != NULL && bb->endbr_external[1]);

		grow = bblock_fixup_end_single (bb, i_vaddr, i_mem, 1);
		assert (grow == 0);

		if (bb->end == bb->endbr[0]->start)
			return (0);

		inst = ia32_decode_instruction (i_mem, &inst_s);
		assert (inst != NULL);
		i_vaddr += inst->length;
		i_mem += inst->length;

		/* already did the conversion: just fixup the jump.
		 */
		if (inst->length < bb->last_ilen)
			goto handle_case0;

		/* otherwise, try conversion to TRANSFER block by appending a
		 * jump, but set the endtype to BR_END_CALL still (we might
		 * have to fixup the call displacement on later passes).
		 */
		conv = obj_ia32_bbconv_pass_to_transfer (bb, i_mem, bb->endbr[0]);
		if (conv < 0)
			return (-conv);

		bb->endtype = BR_END_CALL;

		 /* fallthrough, the transfer will be handled at 'handle_case0'
		 */
	}

call_reloc_handled:

	if (bb->endtype == BR_END_CALL_EXTERN) {
		assert (i_mem[1] == 0xfc && i_mem[2] == 0xff &&
			i_mem[3] == 0xff && i_mem[4] == 0xff);

		/* object-external calls can be ignored, we don't have to
		 * fixup anything at instruction level as the relocation does
		 * it at link time. hence, convert to a PASS branch, which
		 * will be converted to TRANSFER right below.
		 */
		i_vaddr += bb->last_ilen;
		bb->last_ilen = 0;
		bb->endtype = BR_END_PASS;
		bb->endbr_count = 1;
	}

	if (bb->endtype == BR_END_PASS) {
		/* extra pass handling: when it falls down to the wrong bblock, we
		 * have to spill a jump instruction.
		 */
		if (bb->end == bb->endbr[0]->start)
			return (0);

		assert (bb->last_ilen == 0);
		/* FIXME: maybe not needed, as bb->last_ilen is zero? */
		i_vaddr = bb->end - bb->last_unused;
		i_mem = mem - mem_start + i_vaddr;

		conv = obj_ia32_bbconv_pass_to_transfer (bb, i_mem, bb->endbr[0]);
		if (conv < 0)
			return (-conv);

		/* fall through to transfer handling */
	}

handle_case0:
	/* handling of transfer type basic blocks.
	 */
	grow = bblock_fixup_end_single (bb, i_vaddr, i_mem, 0);
	if (grow < 0)
		return (-grow);

	assert (bb->last_unused == 0);

	return (0);
}


/* bblock_fixup_end_single
 *
 * handle one fixup of basic block `bb' to ìts end block `br_idx'. the fixup
 * has to be done at `i_vaddr' which lies in memory at `i_mem'.
 *
 * return negative the number of extra bytes needed if the fixup cannot be
 *    done right now.
 * return zero when the fixup has been done
 */

static int
bblock_fixup_end_single (ia32_bblock *bb, unsigned int i_vaddr,
	unsigned char *i_mem, int br_idx)
{
	ia32_instruction *	inst,
				inst_s;
	ia32_bblock *		target;
	unsigned int		daddr_current,
				daddr_correct,
				displ_relofs,
				displ_size;
	int			displ_new;


	fnote ("bblock_fixup_single: 0x%04x-0x%04x idx %d\n",
		bb->start, bb->end, br_idx);
	target = bb->endbr[br_idx];

	inst = ia32_decode_instruction (i_mem, &inst_s);
	assert (inst != NULL);

	displ_relofs = ia32_has_displacement (inst, &displ_size);
	assert (displ_relofs != 0);

	/* check whether the real and the desired destination addresses match.
	 * if so, there no work to do for us.
	 */
	daddr_current = ia32_trace_control (inst, i_mem, i_vaddr, NULL, NULL);
	daddr_correct = target->start;
	if (daddr_current == daddr_correct) {
		if (bb->last_unused > 0)
			fnote ("  bb->last_unused = %d\n", bb->last_unused);

		if (bb->endtype != BR_END_IF && bb->endtype != BR_END_CALL) {
			assert (bb->last_unused == 0);
		}

		return (0);
	}

	displ_new = daddr_correct - (i_vaddr + inst->length);

	/* case: displacement does not fit into currents basic block limits.
	 *       in case we already freed up space for a larger displacement,
	 * use it. otherwise, just signal back the amount of extra bytes we
	 * need to properly modify this block.
	 */
	if (morph_displ_boundcheck (displ_new, displ_size) != 0) {
		int	grow;

		assert (displ_size == 8);

		/* use the previously unused bytes to extend the displacement
		 */
		grow = obj_ia32_instruction_expand (bb, i_mem, displ_new);
		if (grow < 0)
			return (grow);

		bb->last_unused -= grow;
		assert (bb->last_unused == 0);

		return (0);
	}

	/* other case: no need to mod anything size-wise, just store the new
	 * displacement :)
	 */
	ia32_encode_value (i_mem + displ_relofs, displ_size, displ_new);

	return (0);
}


/* obj_ia32_bbconv_pass_to_transfer
 *
 * convert a the endtype of a basic block `source' from pass to transfer by
 * extending it with a jump instruction leading to `target'. `i_mem' refers to
 * the place in memory the jump instruction will be stored.
 *
 * return negative the number of extra bytes needed if there is not enough
 *   room
 * return zero on success
 */

static int
obj_ia32_bbconv_pass_to_transfer (ia32_bblock *source, unsigned char *i_mem,
	ia32_bblock *target)
{
	fnote ("obj_ia32_bbconv_pass_to_transfer: 0x%04x-0x%04x, "
		"target 0x%04x\n", source->start, source->end, target->start);

	/*assert (source->endtype == BR_END_PASS);*/
#if 0
	/* not needed, as we take care of displacement-extension in
	 * bblock_fixup_end
	 */

	int		displ_new,
			displ_new_8,
			displ_new_32;
	unsigned int	displ_size,
			needed;

	/* calculate displacement for both cases, as the instruction itself
	 * influences the displacement for backward jumps
	 */
	displ_new_8 = target->start - (source->end - source->last_unused +
		OBJ_BBCONV_PASS_TO_TRANSFER_8);
	displ_new_32 = target->start - (source->end - source->last_unused +
		OBJ_BBCONV_PASS_TO_TRANSFER_32);

	/* now pick the optimal displacement and instruction
	 */
	displ_new = displ_new_8;
	displ_size = IA32_WIDTH_8;
	if (morph_displ_boundcheck (displ_new, displ_size)) {
		displ_new = displ_new_32;
		displ_size = IA32_WIDTH_32;
	}

	/* calculate the number of extra bytes we need. note that we cannot
	 * just return two or five, because a request of two bytes can move
	 * the target basic block further away so that we need five bytes next
	 * time, but then two bytes are already free. using this method, we
	 * can return the necessary request of three extra bytes then.
	 */
	needed = 1 + ia32_bit_to_byte (displ_size);
	if (source->last_unused < needed)
		return (-(needed - source->last_unused));

	assert (needed == source->last_unused);
	assert (needed == source->last_ilen);

	/* convert the end and just write the instruction. the displacement is
	 * taken care of by bblock_fix_end.
	 */
	source->endtype = BR_END_TRANSFER;
	i_mem[0] = displ_size == IA32_WIDTH_8 ?
		IA32_OPCODE_JMPN : IA32_OPCODE_JMPF;
#endif
	if (source->last_unused < OBJ_BBCONV_PASS_TO_TRANSFER_8)
		return (-(OBJ_BBCONV_PASS_TO_TRANSFER_8 - source->last_unused));

	i_mem[0] = IA32_OPCODE_JMPN;
	source->endtype = BR_END_TRANSFER;

	source->last_ilen += OBJ_BBCONV_PASS_TO_TRANSFER_8;
	source->last_unused -= OBJ_BBCONV_PASS_TO_TRANSFER_8;

	return (0);
}


int
obj_ia32_instruction_expand (ia32_bblock *bb, unsigned char *mem,
	int displ_new)
{
	/* jcc   outreach   ==>    jcc    outreach32
	 */
	if ((mem[0] & ~IA32_COND_MASK) == IA32_OPCODE_JCC) {
		unsigned int	cond;

		if (bb->last_unused < 4)
			return (-(4 - bb->last_unused));

		cond = mem[0] & IA32_COND_MASK;
		mem[0] = 0x0f;
		mem[1] = 0x80 | cond;

		ia32_encode_value (&mem[2], IA32_WIDTH_32, displ_new - (1 + 3));
		bb->last_ilen += 4;

		return (1 + 3);
	}

	/* jecxz   outreach ==>     jecxz  l1
	 *                          jmp    l2
	 *                      l1: jmp    outreach32
	 *                      l2:
	 *
	 * note that we cannot translate it straight with something like "or
	 * ecx, ecx; jz outreach", because jecxz does not touch any status
	 * flags, while or does.
	 */
	if (mem[0] == IA32_OPCODE_JECXZ) {
		if (bb->last_unused < 7)
			return (-(7 - bb->last_unused));

		mem[0] = IA32_OPCODE_JECXZ;
		mem[1] = 0x02;

		mem[2] = IA32_OPCODE_JMPN;
		mem[3] = 0x05;

		mem[4] = IA32_OPCODE_JMPF;
		ia32_encode_value (&mem[5], IA32_WIDTH_32, displ_new - (2 + 5));

		bb->last_ilen = 5;

		return (2 + 5);
	}

	/* jmpn   outreach  ==>     jmpf  outreach32
	 */
	if (mem[0] == IA32_OPCODE_JMPN) {
		if (bb->last_unused < 3)
			return (-(3 - bb->last_unused));

		mem[0] = IA32_OPCODE_JMPF;

		ia32_encode_value (&mem[1], IA32_WIDTH_32, displ_new - (3));

		bb->last_ilen += 3;

		return (3);
	}

	/* loop*  outreach  ==>     loop  l1
	 *                          jmpn  l2
	 *                      l1: jmpf  outreach32
	 *                      l2:
	 */
	if (mem[0] == IA32_OPCODE_LOOP || mem[0] == IA32_OPCODE_LOOPZ ||
		mem[0] == IA32_OPCODE_LOOPNZ)
	{
		if (bb->last_unused < 7)
			return (-(7 - bb->last_unused));

		/* leave mem[0] untouched */
		mem[1] = 0x02;

		mem[2] = IA32_OPCODE_JMPN;
		mem[3] = 0x05;

		mem[4] = IA32_OPCODE_JMPF;
		ia32_encode_value (&mem[5], IA32_WIDTH_32, displ_new - (2 + 5));

		bb->last_ilen = 5;

		return (2 + 5);
	}

	/* should not happen */
	assert (0);
	return (0);
}


void
obj_calculate_bblock_mem (ia32_function **flist, unsigned int flist_count)
{
	unsigned int	fn,
			bbn,
			all_count;
	ia32_bblock **	all;

	for (fn = 0 ; fn < flist_count ; ++fn) {
		all = ia32_br_get_all (flist[fn]->br_root, &all_count);
		if (all == NULL)
			continue;

		if (all_count == 0) {
			free (all);
			continue;
		}

		for (bbn = 0 ; bbn < all_count ; ++bbn) {
			if (all[bbn]->mem_allocated)
				continue;

			all[bbn]->mem = flist[fn]->mem -
				flist[fn]->start + all[bbn]->start;
		}

		free (all);
	}
}


static long
file_advance_roundup (FILE *fp, unsigned int padding)
{
	unsigned int	pos,
			diff;
	unsigned char	tbuf[padding];

	pos = ftell (fp);
	if (padding == 0 || pos % padding == 0)
		return (ftell (fp));

	diff = pos;
	diff %= padding;
	diff = padding - diff;

	assert (diff > 0);
	memset (tbuf, 0x00, padding);
	fwrite (tbuf, diff, 1, fp);

	/* fseek (fp, pos, SEEK_CUR); */
	return (ftell (fp));
}


