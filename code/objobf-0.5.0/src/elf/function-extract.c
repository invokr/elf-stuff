/* donkey-fix, be an associal nerd
 */

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <common.h>
#include <elf_base.h>
#include <elf_file.h>
#include <elf_reloc.h>
#include <elf_section.h>
#include <elf_symbol.h>
#include <elf_dump.h>
#include <ia32-glue.h>
#include <ia32-debug.h>


extern dump_header	dh_Shdr_short[];
extern dump_header	dh_Shdr[];


extern int ia32_verbosity;
extern int ia32_graphviz_align_undefined;


void
function_dump (FILE *fp, ia32_function *func);


int	dump_asm = 1;
char *	progname;
char *	binary;


void
usage (char *name)
{
	fprintf (stderr, "usage: %s [options] <binary>\n\n",
		progname);

	fprintf (stderr, "options\n"
		"\t-D\tprint DEBUG output from ia32_ module\n"
		"\t-d\tdump all functions in object as .asm and .bin\n"
		"\t-p name\tpalmers mode, print only calltree leading to function\n"
		"\t\t`name'\n"
		"\t-x\tabort when external references are found\n"
		"\t-v\toutput the generated graph instantly\n"
		"\t-A\talign \"undefined\"/external references seperatly in graph\n\n");

	exit (EXIT_FAILURE);
}


int	dump_func = 0;
int	visual = 0;
int	warn_extern = 0;
char *	fname = NULL;


int
main (int argc, char *argv[])
{
	unsigned int		n;
	char			c;
	unsigned int		flist_count;	/* number of items */
	ia32_function **	flist;	/* function list */
	elf_base *		elf;	/* entire ELF object */
	FILE *			fp;
	elf_rel_list *		rel_list;
	elf_reloc_list *	reloc_text;
	elf_reloc_list *	reloc_rodata;
	unsigned int		xref_count;


	progname = argv[0];

	if (argc < 2)
		usage (progname);

	ia32_verbosity = IA32_FATAL;

	while ((c = getopt (argc, argv, "Ddp:xvA")) != EOF) {
		switch (c) {
		case ('D'):
			ia32_verbosity = IA32_DEBUG;
			break;
		case ('d'):
			dump_func = 1;
			break;
		case ('p'):
			fname = optarg;
			break;
		case ('x'):
			warn_extern = 1;
			break;
		case ('v'):
			visual = 1;
			break;
		case ('A'):
			ia32_graphviz_align_undefined = 1;
			break;
		default:
			usage (progname);
			break;
		}
	}

	binary = argv[argc - 1];
	if (binary[0] == '-')
		usage (progname);

	elf = elf_base_load (binary);
	if (elf == NULL) {
		fprintf (stderr, "elf_base_load: failed\n");
		exit (EXIT_FAILURE);
	}


	/* create and load section list
	 */
	flist = elf_function_list_create (elf->elf, elf->seclist,
		&flist_count);
	if (flist == NULL) {
		fprintf (stderr, "failed to obtain list of functions, exit\n");

		exit (EXIT_FAILURE);
	}

	/* create relocation list
	 */
	rel_list = elf_rel_list_create (elf);
	reloc_text = elf_reloc_list_create (elf,
		elf_rel_list_find_byname (rel_list, ".rel.text"),
		flist, flist_count);
	reloc_rodata = elf_reloc_list_create (elf,
		elf_rel_list_find_byname (rel_list, ".rel.rodata"),
		NULL, 0);

	printf ("analysing... ");
	fflush (stdout);

	/* FIXME: add rel_rodata */
	ia32_func_treeplain (&flist, &flist_count, reloc_text, reloc_rodata);
	printf ("done.\n");

	xref_count = ia32_func_xref_count (flist, flist_count,
		IA32_XREF_FUNCEXTERN);
	if (warn_extern && xref_count != 0) {
		fprintf (stderr, "%u extern function references, aborting\n",
			xref_count);

		exit (EXIT_FAILURE);
	}

	fp = fopen ("debug.dot", "w");
	if (fname == NULL) {
		ia32_graphviz_func_out (fp, flist, flist_count, reloc_text);
	} else {
		ia32_function *	func;

		func = ia32_func_list_find_byname (flist, flist_count,
			fname);
		if (func == NULL) {
			fprintf (stderr, "no such function: \"%s\"\n",
				fname);

			exit (EXIT_FAILURE);
		}

		ia32_graphviz_func_out_calltree (fp, flist, flist_count,
			func);
	}
	fclose (fp);

	if (visual) {
		system ("dot -Tps -o debug.ps debug.dot");
		system ("gv debug.ps");
	}


	for (n = 0 ; dump_func && n < flist_count ; ++n) {
		char	outname[128];

		snprintf (outname, sizeof (outname), "%s.bin", flist[n]->name);
		outname[sizeof (outname) - 1] = '\0';

		fp = fopen (outname, "wb");
		fwrite (flist[n]->mem, 1, flist[n]->end - flist[n]->start, fp);
		fclose (fp);

		snprintf (outname, sizeof (outname), "%s.asm", flist[n]->name);
		outname[sizeof (outname) - 1] = '\0';

		fp = fopen (outname, "w");
		function_dump (fp, flist[n]);
		fclose (fp);
	}

	elf_base_destroy (elf);

	exit (EXIT_SUCCESS);
}


void
function_dump (FILE *fp, ia32_function *func)
{
	ia32_instruction *	inst,
				inst_s;
	char			inst_str[128];
	unsigned int		i,
				destaddr;
	int			resume;


	i = 0;

	while ((i + func->start) < func->end) {
		fprintf (fp, "0x%08x(0x%08x)", func->start + i, i);
		inst = ia32_decode_instruction (&func->mem[i], &inst_s);

		if (inst == NULL) {
			fprintf (fp, "INVALID\n");

			return;
		}

		ia32_sprint (inst, inst_str, sizeof (inst_str));
		fprintf (fp, "\t%s\n", inst_str);

		if (OD_TEST (inst->opc.used, OP_CONTROL)) {
			destaddr = ia32_trace_control (inst, &func->mem[i],
				func->start + i, &resume, NULL);

			fprintf (fp, "\tTRANSFER: 0x%08x, %s, %s, %s\n", destaddr,
				(ia32_trace_range (func->start, func->end,
					destaddr) == 1) ? "INTRA" : "INTER",
				OD_TEST (inst->opc.used, OP_COND) ? "COND" : "UNCOND",
				resume == 1 ? "RESUME" : "PASS");
		}

		i += inst->length;
	}

	return;
}


#if 0
void
function_dump (elf_file *elf, elf_section_list *slist, char *func_name,
	char *section_name, unsigned int relofs, unsigned int relsize)
{
	int		i;
	elf_section *	sect = NULL;
	FILE *		fp;
	char		outname[128];


	for (i = 0 ; i < elf->Ehdr.e_shnum ; ++i) {
		if (strcmp (&elf->sh_str[slist->list[i]->Shdr.sh_name],
			section_name) != 0)
			continue;

		sect = slist->list[i];

#if 0
		fprintf (stderr, "%2d (%2lu): ", i, slist->list[i]->sh_idx);
		elf_dump_desc (elf, dh_Shdr_short,
			(void *) &slist->list[i]->Shdr.sh_name,
			elf->Ehdr.e_shentsize);
		fprintf (stderr, "| %s\n",
			&elf->sh_str[slist->list[i]->Shdr.sh_name]);
#endif
	}

	if (sect == NULL)
		return;

	relofs -= sect->Shdr.sh_addr;
	if (sect->Shdr.sh_type != SHT_PROGBITS)
		return;

	if (sect == NULL) {
		fprintf (stderr, "unable to find %s\n", section_name);

		return;
	}

	i = 0;

	snprintf (outname, sizeof (outname), "%s.bin", func_name);
	outname[sizeof (outname) - 1] = '\0';

	fp = fopen (outname, "wb");
	fwrite (sect->data + relofs, 1, relsize, fp);
	fclose (fp);

	snprintf (outname, sizeof (outname), "%s.asm", func_name);
	outname[sizeof (outname) - 1] = '\0';

	fp = fopen (outname, "w");

	while (i < relsize && (i + relofs) < sect->data_len) {
		ia32_instruction *	inst,
					inst_s;
		char			inst_str[128];
		unsigned int		destaddr;
		int			resume;


		fprintf (fp, "0x%08x(0x%08x)", sect->Shdr.sh_addr + i + relofs,
			i);
		inst = ia32_decode_instruction (&sect->data[i + relofs], &inst_s);

		if (inst == NULL) {
			fprintf (fp, "INVALID\n");

			return;
		}

		ia32_sprint (inst, inst_str, sizeof (inst_str));
		fprintf (fp, "\t%s\n", inst_str);

		if (OD_TEST (inst->opc.used, OP_CONTROL)) {
			destaddr = ia32_trace_control (inst, &sect->data[i + relofs],
				sect->Shdr.sh_addr + i + relofs, &resume);

			fprintf (fp, "\tTRANSFER: 0x%08x, %s, %s, %s\n", destaddr,
				(ia32_trace_range (sect->Shdr.sh_addr + relofs,
					sect->Shdr.sh_addr + relofs + relsize,
					destaddr) == 1) ? "INTRA" : "INTER",
				OD_TEST (inst->opc.used, OP_COND) ? "COND" : "UNCOND",
				resume == 1 ? "RESUME" : "PASS");
		}

		i += inst->length;
	}

	fprintf (fp, "\n");
	fclose (fp);
}

#endif

