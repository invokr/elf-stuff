/* reducebind.c - dynamic to static binary conversion utility
 *
 * by scut
 *
 * BETA SOFTWARE, USE ON YOUR OWN RISK
 *
 * x86/linux only so far. some binaries segfault deep in their code, but this
 * does not seem to relate to the binary size. some binaries that have a 19mb
 * size statically linked (qt designer for example ;) work, some small
 * binaries, such as bash do not work.
 */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>

#define	VERSION "0.1.0"

/*** local prototypes */
static void elf_dump_new (pid_t pid, const char *pathname_new,
	const char *pathname_old);
static void file_advance_roundup (FILE *fp, unsigned int padding);
static Elf32_Addr elf_get_entrypoint (const char *pathname);


int
main (int argc, char *argv[], char *envp[])
{
	char *		pathname;
	char *		f_argv[2];
	pid_t		fpid;	/* child pid, gets ptraced */
	struct user	regs;	/* PTRACE pulled registers */
	Elf32_Addr	entry;
	char *		output = "output";

	fprintf (stderr, "reducebind version "VERSION"\n\n");

	if (argc < 2) {
		fprintf (stderr, "usage: %s <binary> [output]\n\n", argv[0]);

		exit (EXIT_FAILURE);
	}
	pathname = argv[1];
	if (argc >= 3)
		output = argv[2];

	entry = elf_get_entrypoint (pathname);

	fpid = fork ();
	if (fpid < 0) {
		perror ("fork");
		exit (EXIT_FAILURE);
	}

	/* child process.
	 */
	if (fpid == 0) {
		if (ptrace (PTRACE_TRACEME, 0, NULL, NULL) != 0) {
			perror ("ptrace PTRACE_TRACEME");
			exit (EXIT_FAILURE);
		}
		fprintf (stderr, "  child: TRACEME set\n");

		fprintf (stderr, "  child: executing: %s\n", pathname);
		close (1);
		dup2 (2, 1);

		/* prepare arguments and environment.
		 */
		f_argv[0] = pathname;
		f_argv[1] = NULL;

		putenv ("LD_BIND_NOW=1");
		execve (f_argv[0], f_argv, envp);

		/* failed ? */
		perror ("execve");
		exit (EXIT_FAILURE);
	}

	wait (NULL);

	memset (&regs, 0, sizeof (regs));

	if (ptrace (PTRACE_GETREGS, fpid, NULL, &regs) < 0) {
		perror ("ptrace PTRACE_GETREGS");
		exit (EXIT_FAILURE);
	}
	fprintf (stderr, "(%d) [0x%08lx] first stop\n", fpid, regs.regs.eip);
	fprintf (stderr, "(%d) tracing until entry point is reached (0x%08x)\n",
		fpid, entry);

	while (regs.regs.eip != entry) {
		if (ptrace (PTRACE_SINGLESTEP, fpid, NULL, NULL) < 0) {
			perror ("ptrace PTRACE_SINGLESTEP");
			exit (EXIT_FAILURE);
		}
		wait (NULL);

		memset (&regs, 0, sizeof (regs));
		if (ptrace (PTRACE_GETREGS, fpid, NULL, &regs) < 0) {
			perror ("ptrace PTRACE_GETREGS");
			exit (EXIT_FAILURE);
		}
		fprintf (stderr, "\r(%d) [0x%08lx]", fpid, regs.regs.eip);
	}

	fprintf (stderr, "\n(%d) entry point reached\n", fpid);
	fprintf (stderr, "(%d) dumping process memory to new ELF ET_EXEC file\n",
		fpid);

	elf_dump_new (fpid, output, pathname);

	exit (EXIT_SUCCESS);
}


static void
elf_dump_new (pid_t pid, const char *pathname_new, const char *pathname_old)
{
	FILE *		fpn;
	FILE *		fpo;
	FILE *		mapsfp;
	char		maps_pathname[32];
	char		map_line[256];
	Elf32_Ehdr	eh;
	Elf32_Phdr	phdr[128];
	unsigned int	pn;		/* program header table index */


	fpn = fopen (pathname_new, "wb");
	fpo = fopen (pathname_old, "rb");
	if (fpn == NULL || fpo == NULL) {
		perror ("fopen output ELF file creation");
		exit (EXIT_FAILURE);
	}

	if (fread (&eh, sizeof (eh), 1, fpo) != 1) {
		perror ("fread ELF header");
		exit (EXIT_FAILURE);
	}
	fclose (fpo);

	/* kill header values */
	eh.e_shoff = 0x0;	/* we do not need any sections for loading */
	eh.e_shnum = 0;
	eh.e_shstrndx = 0;

	/* the program header table will be fixed later */
	eh.e_phoff = 0;
	eh.e_phnum = 0;

	fwrite (&eh, sizeof (eh), 1, fpn);

	snprintf (maps_pathname, sizeof (maps_pathname) - 1,
		"/proc/%d/maps", pid);
	maps_pathname[sizeof (maps_pathname) - 1] = '\0';
	mapsfp = fopen (maps_pathname, "r");
	if (mapsfp == NULL) {
		perror ("fopen map file");
		exit (EXIT_FAILURE);
	}

	while (1) {
		Elf32_Phdr *	ph;
		unsigned int	addr_start,
				addr_end,
				addr_walker;
		char		map_perm[8];
		unsigned char	data_saved[sizeof (unsigned long int)];


		memset (map_line, '\0', sizeof (map_line));
		if (fgets (map_line, sizeof (map_line) - 1, mapsfp) == NULL)
			break;
		map_line[sizeof (map_line) - 1] = '\0';

		fprintf (stderr, "%s", map_line);
		if (sscanf (map_line, "%08x-%08x %7[rwxp-] ",
			&addr_start, &addr_end, map_perm) != 3) 
		{
			perror ("invalid map-line");

			exit (EXIT_FAILURE);
		}

		/* we do not need the stack in here.
		 */
		if (addr_end == 0xc0000000)
			continue;

		file_advance_roundup (fpn, PAGE_SIZE);

		ph = &phdr[eh.e_phnum];
		eh.e_phnum += 1;
		memset (ph, 0x00, sizeof (Elf32_Phdr));

		ph->p_type = PT_LOAD;
		ph->p_offset = ftell (fpn);
		ph->p_vaddr = addr_start;
		ph->p_paddr = 0x0;
		ph->p_filesz = ph->p_memsz = addr_end - addr_start;
		ph->p_flags = 0;
		if (map_perm[0] == 'r')
			ph->p_flags |= PF_R;
		if (map_perm[1] == 'w')
			ph->p_flags |= PF_W;
		if (map_perm[2] == 'x')
			ph->p_flags |= PF_X;
		ph->p_align = PAGE_SIZE;

		/* save segment data, assuming addr is page aligned
		 */
		for (addr_walker = 0 ; addr_walker < (addr_end - addr_start);
			addr_walker += sizeof (data_saved))
		{
			errno = 0;

			*((unsigned long int *) &data_saved[0]) =
				ptrace (PTRACE_PEEKDATA, pid,
					addr_start + addr_walker, NULL);

			if (errno == 0 && fwrite (&data_saved[0],
				sizeof (data_saved), 1, fpn) != 1)
			{
				perror ("fwrite segment");

				exit (EXIT_FAILURE);
			} else if (errno != 0) {
				fprintf (stderr,
					"[0x%08x] invalid PTRACE_PEEKDATA\n",
					addr_start + addr_walker);

				exit (EXIT_FAILURE);
			}
		}
	}

	fclose (mapsfp);

	/* now write program header table
	 */
	file_advance_roundup (fpn, PAGE_SIZE);
	eh.e_phoff = ftell (fpn);

	for (pn = 0 ; pn < eh.e_phnum ; ++pn) {
		if (fwrite (&phdr[pn], sizeof (Elf32_Phdr), 1, fpn) != 1) {
			perror ("fwrite program header");
			exit (EXIT_FAILURE);
		}
	}

	fseek (fpn, 0, SEEK_SET);
	if (fwrite (&eh, sizeof (Elf32_Ehdr), 1, fpn) != 1) {
		perror ("fwrite final ELF header");
		exit (EXIT_FAILURE);
	}

	fclose (fpn);
	chmod (pathname_new, 0700);
}


static void
file_advance_roundup (FILE *fp, unsigned int padding)
{
	unsigned int	pos;

	pos = ftell (fp);
	if (pos % padding == 0)
		return;

	pos %= padding;
	pos = padding - pos;

	fseek (fp, pos, SEEK_CUR);
}


static Elf32_Addr
elf_get_entrypoint (const char *pathname)
{
	FILE *		fp;
	Elf32_Ehdr	eh;


	fp = fopen (pathname, "rb");
	if (fp == NULL) {
		perror ("fopen input ELF file");
		exit (EXIT_FAILURE);
	}

	if (fread (&eh, sizeof (eh), 1, fp) != 1) {
		perror ("fread");
		exit (EXIT_FAILURE);
	}

	fclose (fp);

	return (eh.e_entry);
}


