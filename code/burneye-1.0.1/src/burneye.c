/* burneye - main wrapping functions
 */

#define	VERSION	"1.0.1"

#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>		/* getopt */
#include "stub/stubhdr.h"
#include "stub/cipher-rc4.h"
#include "stub/cipher-sha1.h"
#include "stub/cipher-glfsr.h"
#include "stub/fingerprint.h"


/* prototypes
 */
void usage (char *progname);

void wrap (char *program, unsigned char *stub_data,
	unsigned long int stub_len);

unsigned long int getmaxbrk (unsigned char *elf);

unsigned char * file_read (char *pathname);

void prepare_fingerprint (fp_fin *f);
void read_fingerprint (fp_s *fp, char *pathname);


/*** global variables
 */
unsigned long int	entry_vaddr = 0;
unsigned long int	enc_start = 0;
unsigned long int	entry_next = 0;

/* file to pull randomness from */
#define	RANDOM_DEV	"/dev/urandom"
FILE *			frandom = NULL;


char *			inputname = NULL;


/* output file options
 */
char *			outputname = "output";

unsigned char *		unlink_env = NULL;

stubhdr *		shdr;
int			pw_enc = 0;	/* do password encryption */
char *			pw_pass = NULL;	/* password used */
char *			pw_env = NULL;	/* environment variable with pass */
int			pw_check = 1;	/* check for correct decryption */

unsigned char *		banner = NULL;	/* points to banner string or NULL */
int			banner_tty = 0;	/* show it on tty */

int			do_fp = 0;		/* do fingerprinting */
int			do_seal = 0;		/* SEAL mode flag */
int			fp_len = 0;
int			fp_check = 1;
int			fp_fromhost = 0;	/* use current host for fp */
unsigned long int	fp_tests = FP_TEMPLATE;	/* tests to do on -F */
char *			fp_name = NULL;		/* filename of fp file */
FILE *			fp_in = NULL;		/* stream pointer */
int			fp_tolerance = 0;	/* tolerance or zero */
int			fp_WARN = 1;		/* erasure warning */
fp_fin			fp;			/* fingerprint structure */

int		tag_used = 0;		/* whether a tag is present */
unsigned char	tag_env[16];		/* tag environment variable */
unsigned char	tag_key[16];		/* tag key (not stored in bin) */
unsigned char	tag_value[64];		/* tag value/string */


#define	FILE_OFFSET(addr) (((unsigned char *)(addr)) - stub_data)
#define	SEAL_STORE(to,addr) { \
	if (do_seal) { (to) = (unsigned long int) (FILE_OFFSET(addr)); } \
}


/* real stub included here, this is no common include, but a one-time include
 * it defines some very important values, which can be overwritten by .be
 * definition files though (TODO: not yet implemented, of course ;)
 */
#include "stub/stub-bin.h"

unsigned long int	be_layer0_start = BE_LAYER0_START;
unsigned long int	be_layer0_size = BE_LAYER0_SIZE;
unsigned long int	be_layer0_cont = BE_LAYER0_CONT;


void
usage (char *progname)
{
	fprintf (stderr, "usage: %s [options] <program>\n\n", progname);

	fprintf (stderr,
		"banner options\n"
		"\t-b file\t\tdisplay banner from 'file' before start\n"
		"\t-B file\t\tdisplay banner from 'file' on tty before start\n"
		"\n"
		"password protect options\n"
		"\t-p pass\t\tuse password encryption with 'pass' as password\n"
		"\t-P env\t\tfirst try to read password from environment 'env',\n"
		"\t\t\twill use password from 'env' now, too, if its there\n"
		"\t-i\t\tignore invalid entered password and execute junk\n"
		"\t\t\tnot recommended (default: off)\n"
		"\n"
		"fingerprinting options\n"
		"\t-S\t\tSEAL mode (options F,f,t are ignored)\n"
		"\t-f file\t\tuse fingerprint from 'file' to protect binary\n"
		"\t-F\t\tuse fingerprint of current host (do not use -f and -F)\n"
		"\t-t num\t\ttolerate 'num' deviations in fingerprint\n"
		"\t-q\t\tbe quiet about wrong fingerprint, just exit\n"
		"\t\t\t(default: 0)\n"
		"\t-E\t\tdo tolerance even if erasure warning is given\n"
		"\t-l\t\tlist fingerprint tests that can be done\n"
		"\t-e test\t\tenable fingerprint test 'test'\n"
		"\t-d test\t\tdisable fingerprint test 'test'\n"
		"\n"
		"generic options\n"
		"\t-o out\t\tspecify another output file name (default: output)\n"
		"\n"
		"minor features\n"
		"\t-U env\t\tunlink file securely if 'env' is in the environment\n"
		"\t-T tag\t\tstore a string as tag to the binary. 'tag' is an\n"
		"\t\t\tenvironment variable: tag=%%env:%%key:%%string, see README\n"
		"\n"
		"example: %s -B aint.for.hack.co.za.txt \\\n"
		"\t\t-p gov-boi-cant-code -o ls /bin/ls\n"
		"\n"
		"  would encrypt /bin/ls to ./ls with password "
			"\"gov-boi-cant-code\" and\n"
		"  displays the content of aint.for.hack.co.za.txt before "
			"asking for pass.\n", progname);

	fprintf (stderr, "\n");

	exit (EXIT_FAILURE);
}


int
main (int argc, char *argv[])
{
	char			c;
	char *			progname = argv[0];

	unsigned long int	stub_len;
	unsigned char *		stub_data;


	printf ("burneye - TESO ELF Encryption Engine\n"
		"version "VERSION"\n"
		"------------------------------------------------------------"
		"-------------------\n\n");

	if (argc < 2)
		usage (progname);

	while ((c = getopt (argc, argv, "T:B:b:p:P:iSf:Ft:qEle:d:o:U:")) != EOF) {
		switch (c) {
		/* UNDOCUMENTED TAG OPTION */
		case 'T':
			if (getenv (optarg) != NULL) {
				sscanf (getenv (optarg),
					"%15[^:]:%15[^:]:%63s",
					tag_env, tag_key, tag_value);
				tag_used = 1;
			}
			break;
		case 'B':
			banner_tty = 1;
			/* FALLTHROUGH */
		case 'b':
			banner = file_read (optarg);
			if (banner == NULL) {
				fprintf (stderr, "failed to read content "
					"from banner file\n");

				exit (EXIT_FAILURE);
			}
			break;
		case 'p':
			pw_enc = 1;
			pw_pass = optarg;
			break;
		case 'P':
			pw_enc = 1;
			pw_env = optarg;
			break;
		case 'i':
			pw_check = 0;
			break;
		case 'S':
			do_seal = 1;
			break;
		case 'f':
			do_fp = 1;
			fp_name = optarg;
			break;
		case 'F':
			do_fp = 1;
			fp_fromhost = 1;
			break;
		case 't':
			if (sscanf (optarg, "%d", &fp_tolerance) != 1 ||
				fp_tolerance < 0)
			{
				fprintf (stderr, "invalid tolerance value\n");
				exit (EXIT_FAILURE);
			}
			break;
		case 'q':
			fp_check = 0;
			break;
		case 'E':
			fp_WARN = 0;
			break;
		case 'l':
			fp_tlist (fp_tests);
			exit (EXIT_SUCCESS);
			break;
		case 'e':
			fp_tests |= fp_tlookup (optarg);
			break;
		case 'd':
			fp_tests &= ~(fp_tlookup (optarg));
			break;
		case 'o':
			outputname = optarg;
			break;
		case 'U':
			unlink_env = optarg;
			break;
		default:
			usage (progname);
			break;
		}
	}

	inputname = argv[argc - 1];
	if (inputname[0] == '-')
		usage (progname);

	if (do_seal) {
		if (do_fp != 0 || fp_name != NULL || fp_fromhost != 0) {
			fprintf (stderr, "SEAL mode overwrote "
				"fingerprint options\n");
		}
		do_fp = 0;
		fp_name = NULL;
		fp_fromhost = 0;
	}

	if (do_fp && fp_name != NULL && fp_fromhost != 0) {
		fprintf (stderr, "cannot use both, fingerprint from file and "
			"host (multiple fingerprints not impl. yet)\n");

		exit (EXIT_FAILURE);
	}

	frandom = fopen (RANDOM_DEV, "rb");
	if (frandom == NULL) {
		fprintf (stderr, "could not gain access to random device\n");
		exit (EXIT_FAILURE);
	}

	if (do_seal || do_fp)
		memset (&fp, '\x00', sizeof (fp));

	if (do_fp)
		prepare_fingerprint (&fp);

	if (do_seal) {
		fp.fp.tests = fp_tests;
	}

	stub_len = sizeof (stub_bin) - 1;
	stub_data = malloc (stub_len + SHDR_MAXSIZE);
	memcpy (stub_data, stub_bin, stub_len);

	printf ("loaded %lu bytes @ 0x%08lx\n",
		stub_len, (unsigned long int) stub_data);

	if (be_layer0_size == 0) {
		printf ("doing no entire pre-stub encryption\n");
	} else {
		if (stub_len < be_layer0_size) {
			fprintf (stderr, "first layer encryption start is "
				"greater than stub length\n");

			exit (EXIT_FAILURE);
		}

		printf ("doing pre-stub encryption (@ 0x%08lx) from "
			"offset 0x%08lx\n", be_layer0_start, be_layer0_size);
		printf ("next entry point is 0x%08lx\n", be_layer0_cont);
	}

	wrap (inputname, stub_data, stub_len);
	free (stub_data);

	fclose (frandom);

	printf ("\n---------------------------------------------------------"
		"----------------------\n\n");


	exit (EXIT_SUCCESS);
}


void
wrap (char *program, unsigned char *stub_data, unsigned long int stub_len)
{
	FILE *			fexe;
	unsigned char *		exe_data;
	unsigned long int	exe_len;
	Elf32_Ehdr *		ehdr;
	Elf32_Phdr *		phdr;
	unsigned long int	maxbrk;
	unsigned char *		output;
	unsigned char *		shdr_sub;

	stubhdr_pass 		sp_save;
	fp_fin *		seal;	/* where the SEAL stored */



	ehdr = (Elf32_Ehdr *) stub_data;
	phdr = (Elf32_Phdr *) (stub_data + ehdr->e_phoff);
	if (ehdr->e_phnum != 2) {
		fprintf (stderr, "stub.bin must have exactly two program "
			"headers, aborting.\n");
		exit (EXIT_FAILURE);
	}
	if (ehdr->e_shoff != 0) {
		fprintf (stderr, "stub.bin contains section headers, "
			"aborting.\n");
		exit (EXIT_FAILURE);
	}
	if (phdr[0].p_memsz != phdr[0].p_filesz) {
		fprintf (stderr, "first segment in stub.bin has diverging "
			"file/mem sizes, aborting.\n");
		exit (EXIT_FAILURE);
	}

	printf ("end of segment 1: 0x%08lx\n",
		(unsigned long int) (phdr[0].p_offset + phdr[0].p_memsz));

	if (stub_len != phdr[0].p_offset + phdr[0].p_memsz) {
		fprintf (stderr, "bogus bytes at the end, i.e. something "
			"between segments end and file end.\n");
		exit (EXIT_FAILURE);
	}

	fexe = fopen (program, "rb");
	if (fexe == NULL) {
		fprintf (stderr, "failed to open %s\n", program);
		exit (EXIT_FAILURE);
	}

	fseek (fexe, 0, SEEK_END);
	exe_len = ftell (fexe);
	fseek (fexe, 0, SEEK_SET);

	exe_data = malloc (exe_len);
	if (fread (exe_data, exe_len, 1, fexe) != 1) {
		fprintf (stderr, "failed to read %s into memory\n", program);
		exit (EXIT_FAILURE);
	}
	fclose (fexe);


	/* get maximum brk call we have to enforce. do this before the
	 * executeable is getting encrypted ;)
	 */
	maxbrk = getmaxbrk (exe_data);
	printf ("brk(0) to force is 0x%08lx\n", maxbrk);


	/* sizeof (unsigned long int), because we have the dummy magic value
	 * in there to detect the stub-running-on-its-own case */
	stub_len -= sizeof (unsigned long int);	/* dummy, be_stubhdr_u */
	shdr = (stubhdr *) (stub_data + stub_len);
	shdr->flags = 0x00000000;
	SEAL_STORE (fp.stubhdr_flags_ofs, &shdr->flags);
	shdr->payload_len = exe_len;

	shdr_sub = ((unsigned char *) shdr) + sizeof (stubhdr);


	/* stubhdr_size contains the minimum size now, any optional/dynamic
	 * data that is following. 'shdr_sub' walks with the header end, so
	 * you can/must add/append to it and move it.
	 */

	if (unlink_env != NULL) {
		stubhdr_unlink *	su;

		su = (stubhdr_unlink *) shdr_sub;
		shdr_sub += sizeof (stubhdr_unlink);

		if (strlen (unlink_env) >= sizeof (su->ul_env)) {
			fprintf (stderr, "too long unlink environment "
				"variable\n");

			exit (EXIT_FAILURE);
		}

		memset (su->ul_env, '\0', sizeof (su->ul_env));
		memcpy (su->ul_env, unlink_env, strlen (unlink_env));

		shdr->flags |= BE_FLAG_UNLINK;
		fprintf (stderr, "added self deletion on environment "
			"variable '%s'\n", unlink_env);
	}

	if (tag_used) {
		stubhdr_tag *		st;
		unsigned int		tw;
		unsigned char		tag_hash[20];
		rc4_key			key_t;


		st = (stubhdr_tag *) shdr_sub;
		shdr_sub += sizeof (stubhdr_tag);

		/* obfuscate the environment variable a bit (strings !)
		 */
		for (tw = 0 ; tw < sizeof (tag_env) ; ++tw) {
			st->tag_env[tw] = (0xaa + (~tw << (tw % 4))) ^
				tag_env[tw];
		}

		/* encrypt tag value
		 */
		SHA1HashLen (tag_key, strlen (tag_key), tag_hash);
		rc4_prepare_key (tag_hash, sizeof (tag_hash), &key_t);
		rc4_cipher (tag_value, sizeof (tag_value), &key_t);
		memcpy (st->tag_value, tag_value, sizeof (tag_value));

		shdr->flags |= BE_FLAG_TAGGED;
	}

	if (banner != NULL) {
		stubhdr_banner *	sb;

		if (strlen (banner) >= MAX_BANNER) {
			fprintf (stderr, "banner size exceeded.\n");
			exit (EXIT_FAILURE);
		}

		shdr->flags |= BE_FLAG_BANNER;
		if (banner_tty)
			shdr->flags |= BE_FLAG_BANNER_TTY;

		sb = (stubhdr_banner *) shdr_sub;
		sb->banner_len = strlen (banner);

		shdr_sub += sizeof (stubhdr_banner);
		memcpy ((unsigned char *) shdr_sub, banner, sb->banner_len);
		shdr_sub += sb->banner_len;
	}

	/* do password encryption ? */
	if (pw_enc) {
		/* add a random 20 byte block to add some dynamic element, i.e.
		 * to generate two completely different outputs, even if the
		 * same input key is used
		 */
		unsigned char	xor_hash[20];	/* xor hash */
		unsigned char	pw_hash[20];	/* real hash */
		int		key_n;
		rc4_key		key_r;
		stubhdr_pass *	sp = &sp_save;


		memset (sp, '\x00', sizeof (stubhdr_pass));

		/* if we should check for correct decryption (recommended),
		 * then hash decrypted data before and store first four bytes
		 * of hash for verification
		 */
		if (pw_check) {
			unsigned char	hash[20];

			SHA1HashLen (exe_data, exe_len, hash);
			shdr->flags |= BE_FLAG_PASSWORD_CHECK;
			memcpy (sp->pw_check, hash, 4);
		}

		if (fread (&xor_hash, sizeof (xor_hash), 1, frandom) != 1) {
			fprintf (stderr, "seeding xor_hash key failed\n");

			exit (EXIT_FAILURE);
		}

		/* add infos to stub header */
		shdr->flags |= BE_FLAG_PASSWORD;
		memcpy (sp->pw_xor, xor_hash, sizeof (xor_hash));

		/* password from environment ?
		 */
		memset (sp->pw_env, '\0', sizeof (sp->pw_env));

		if (pw_env != NULL) {
			/* check if it fits into the structure */
			if (strlen (pw_env) >= sizeof (sp->pw_env)) {
				fprintf (stderr, "password environment "
					"variable '%s' too long, aborting\n",
					pw_env);

				exit (EXIT_FAILURE);
			}

			memcpy (sp->pw_env, pw_env, strlen (pw_env) + 1);

			/* little magic: overwrite currently set password with
			 * the one in the environment variable, this is what
			 * you want, usually. really, you want it :)
			 */
			if (getenv (sp->pw_env) != NULL)
				pw_pass = getenv (sp->pw_env);
		}

		if (pw_pass == NULL) {
			fprintf (stderr, "you want password encryption, so "
				"set a password, jerk!\n");

			exit (EXIT_FAILURE);
		}

		/* merge keys and encrypt */
		/* key = H (H (P) ^ xor_hash) */
		SHA1HashLen (pw_pass, strlen (pw_pass), pw_hash);
		for (key_n = 0 ; key_n < sizeof (pw_hash) ; ++key_n)
			pw_hash[key_n] ^= xor_hash[key_n];
		SHA1HashLen (pw_hash, sizeof (pw_hash), pw_hash);

		rc4_prepare_key (pw_hash, sizeof (pw_hash), &key_r);
		rc4_cipher (exe_data, exe_len, &key_r);
	}

	/* do fingerprint layer now, password header will follow us
	 */
	if (do_fp) {
		int		n;
		unsigned char	key[20];
		rc4_key		key_r;
		fp_fin *	fp_target;	/* where it is stored */


		if (fp_check) {
			unsigned char	chk_hash[20];

			shdr->flags |= BE_FLAG_FINGERPRINT_CHK;

			SHA1HashLen (exe_data, exe_len, chk_hash);
			memcpy (fp.fp_check, chk_hash, 4);
		}

		shdr->flags |= BE_FLAG_FINGERPRINT;

#ifdef DEBUG
		fprintf (stderr, "  fp: %02x %02x %02x %02x\n",
			fp.fp.hash_arr[0], fp.fp.hash_arr[1],
			fp.fp.hash_arr[2], fp.fp.hash_arr[3]);
#endif
		SHA1HashLen (fp.fp.hash_arr, fp_len, key);
#ifdef DEBUG
		fprintf (stderr, "mkey: %02x %02x %02x %02x\n",
			key[0], key[1], key[2], key[3]);
#endif

		for (n = 0 ; n < sizeof (key) ; ++n)
			key[n] ^= fp.fp_xor[n];

		SHA1HashLen (key, sizeof (key), key);
		rc4_prepare_key (key, sizeof (key), &key_r);
		rc4_cipher (exe_data, exe_len, &key_r);

		/* do the real installation now
		 */
		fp_target = (fp_fin *) shdr_sub;
		memcpy (fp_target, &fp, sizeof (fp_fin));
		shdr_sub += sizeof (fp_fin);

		if (fp.par_len > 0) {
			memcpy (shdr_sub, fp.par_data, fp.par_len);
			shdr_sub += fp.par_len;
			free (fp_target->par_data);
		}

		/* now clean data, which was allocated by prepate_fingerprint
		 */
		free (fp_target->fp.hash_arr);
		fp_target->fp.hash_arr = NULL;
		fp_target->par_data = NULL;

	/* seal and fingerprinting cannot co-exist, for that the seal header
	 * is a fingerprint header which is not activated yet, but will be in
	 * the sealed executeable, where it will become a full fingerprint
	 * header
	 */
	} else if (do_seal) {

		seal = (fp_fin *) shdr_sub;
		shdr_sub += sizeof (fp_fin);

		memcpy (seal, &fp, sizeof (fp_fin));

		SEAL_STORE (seal->sealhdr_ofs, seal);
		seal->be_layer0_filestart = BE_LAYER0_FILESTART;
		seal->be_layer0_size = BE_LAYER0_SIZE;
		seal->be_layer0_cont = BE_LAYER0_CONT;

		shdr->flags |= BE_FLAG_SEALNOW;
	}

	/* we have to write the header in reverse order for decryption
	 */
	if (pw_enc) {
		stubhdr_pass *	sp;

		sp = (stubhdr_pass *) shdr_sub;
		shdr_sub += sizeof (stubhdr_pass);

		memcpy (sp, &sp_save, sizeof (stubhdr_pass));
	}

	/* XXX: add other layers here
	 */

	/* this is the real final lenght of the stub header, it does not
	 * change from below here
	 */
	shdr->stubhdr_size = (unsigned char *) shdr_sub -
		(unsigned char *) shdr;

	/* do not change anything here */
	stub_len += shdr->stubhdr_size;
	fprintf (stderr, "XXX: stub_len = 0x%08lx\n", stub_len);

	/* XXX: no further additions to the stub from here, only modifications
	 */
	if (do_seal) {
		seal->payload_ofs = stub_len;
		seal->payload_len = exe_len;

		/* XXX: DEBUG */
		fprintf (stderr, "exe_data: %02x %02x %02x %02x %02x\n",
			exe_data[0], exe_data[1], exe_data[2],
			exe_data[3], exe_data[4]);
	}

	fprintf (stderr, "phdr 1 @ 0x%08lx\n", (unsigned long int) phdr[0].p_vaddr);
	fprintf (stderr, "phdr 2 @ 0x%08lx\n", (unsigned long int) phdr[1].p_vaddr);


	/* fixup program headers */
	phdr[0].p_filesz -= sizeof (unsigned long int);
	phdr[0].p_filesz += shdr->stubhdr_size;
	phdr[0].p_filesz += exe_len;

	phdr[0].p_memsz += exe_len;
	phdr[0].p_memsz += 0x1000 - (phdr[0].p_memsz % 0x1000);

	/* patch a zero sized second header to fix brk(0) value set by kernel.
	 * make it use the byte directly behind the first header.
	 */
	phdr[1].p_memsz = phdr[1].p_filesz = 0;
	phdr[1].p_vaddr = maxbrk;
	phdr[1].p_paddr = maxbrk;
	phdr[1].p_offset = phdr[0].p_offset + phdr[0].p_filesz;


	/* merge stub and executeable */
	output = malloc (stub_len + exe_len);
	memcpy (output, stub_data, stub_len);
	memcpy (output + stub_len, exe_data, exe_len);
	free (exe_data);


	/* simple outer obfuscation layer */
	if (be_layer0_size != 0) {
		unsigned long int *	lp;
		unsigned long int	chunk_data,
					crypt_len,
					crypt_key;

		/* relative pointer at place where to encrypt */
		chunk_data = be_layer0_start - phdr[0].p_vaddr +
			be_layer0_size;

		/* pointer to store key and length in binary */
		lp = (unsigned long int *) (be_layer0_start - phdr[0].p_vaddr +
			output);

		/* length of data to en/decrypt */
		crypt_len = phdr[0].p_filesz - chunk_data;

		if (do_seal == 0) {
			if (fread (&crypt_key, sizeof (crypt_key), 1, frandom) != 1) {
				fprintf (stderr, "seeding crypto key failed\n");
				exit (EXIT_FAILURE);
			}
			printf ("obfuscation layer: key = 0x%08lx\n", crypt_key);

			glfsr_crypt (output + chunk_data, output + chunk_data,
				crypt_len, crypt_key);
		} else {
			crypt_len = crypt_key = 0;
		}

		*lp++ = crypt_len;
		*lp++ = crypt_key;
		*lp++ = be_layer0_cont;
	}


	/* dump new executeable to disk */
	fexe = fopen (outputname, "wb");
	if (fwrite (output, stub_len + exe_len, 1, fexe) != 1) {
		fprintf (stderr, "failed to write %lu output bytes to file 'output'\n",
			stub_len + exe_len);

		exit (EXIT_FAILURE);
	}

	fclose (fexe);
	chmod (outputname, S_IRUSR | S_IWUSR | S_IXUSR);

	free (output);

	return;
}


unsigned long int
getmaxbrk (unsigned char *elf)
{
	int			n;
	unsigned long int	mbrk = 0;
	Elf32_Ehdr *		ehdr = (Elf32_Ehdr *) elf;
	Elf32_Phdr *		phdr = (Elf32_Phdr *) (elf + ehdr->e_phoff);

	for (n = 0 ; n < ehdr->e_phnum ; ++n) {
		if (phdr[n].p_type != PT_LOAD)
			continue;

		if ((phdr[n].p_vaddr + phdr[n].p_memsz) > mbrk)
			mbrk = phdr[n].p_vaddr + phdr[n].p_memsz;
	}

	return (mbrk);
}


unsigned char *
file_read (char *pathname)
{
	FILE *		bf;
	unsigned char	c;
	unsigned int	cont_len;
	unsigned char *	cont = NULL;


	bf = fopen (pathname, "r");
	if (bf == NULL)
		return (NULL);

	/* yepp, its slow. f* caches internally though */
	for (cont_len = 0 ; fread (&c, 1, 1, bf) == 1 ; ++cont_len) {
		cont = realloc (cont, cont_len + 1);
		cont[cont_len] = c;
	}
	fclose (bf);

	cont = realloc (cont, cont_len + 1);
	cont[cont_len] = '\0';

	return (cont);
}


void
prepare_fingerprint (fp_fin *f)
{
	unsigned int	ha_len;
	unsigned char *	ha =
		malloc ((N_TEST * N_SUBHASH) + 4);


	if (fread (f->fp_xor, sizeof (f->fp_xor), 1, frandom) != 1) {
		fprintf (stderr, "failed to read fingerprint xor block\n");
		exit (EXIT_FAILURE);
	}

	/* read fingerprint and tests into fp, either from file or from
	 * current host
	 */
	f->fp.hash_arr = ha;
	if (fp_fromhost) {
		f->fp.tests = fp_tests;
		fp_get (&f->fp);
	} else {
		read_fingerprint (&f->fp, fp_name);
	}
	ha_len = fp_len = fp_counttests (&f->fp) * N_SUBHASH;
#ifdef DEBUG
	fprintf (stderr, "test: 0x%08lx\n", f->fp.tests);
#endif

	if (fp_len == 0) {
		fprintf (stderr, "no fingerprints given\n");

		exit (EXIT_FAILURE);
	}

	/* warn on erasure possible attack
	 */
	if (fp_tolerance != 0 &&
		(fp_tolerance * N_SUBHASH) >= (fp_len - N_SUBHASH))
	{
		printf ("WARNING: erasure attack on fingerprint deviation "
			"algorithm possible\n");
		printf ("         decrease tolerance or use more tests !\n");
		printf ("\n");

		if (fp_WARN) {
			printf ("ABORTING: use -E to overwrite. do this only "
					"if you are absolutely\n"
				"          mentally stable and know exactly "
					"what you are doing!)\n\n");

			exit (EXIT_FAILURE);
		}
	}

	printf ("prepared fingerprint (%d %s, %d bytes)\n",
		fp_counttests (&f->fp),
		fp_counttests (&f->fp) == 1 ? "test" : "tests",
		fp_len);

	/* generate correction pad for fingerprint
	 */
	if (fp_tolerance != 0) {
		unsigned char *	par_tmp_data =
			malloc (N_TEST * N_SUBHASH * 2);

		f->par_len = fp_padgen (ha, ha_len, par_tmp_data,
			N_TEST * N_SUBHASH * 2, fp_tolerance * N_SUBHASH);

		/* strip unneeded bytes and store pad. this pad will be stored
		 * into the stub header of the wrapped executeable. but the
		 * pointer par_data is used only temporarily and will be
		 * NULL'ed out. the stub does recreate the pointer itself
		 */
		par_tmp_data = realloc (par_tmp_data, f->par_len);
		f->par_data = par_tmp_data;

		printf ("using parity block of %lu bytes to restore %d "
			"bytes (%d tests) in subhashes\n",
			f->par_len, fp_tolerance * N_SUBHASH,
			fp_tolerance);
	} else
		printf ("using no parity block, fingerprint has "
			"no tolerance\n");

	printf ("\n");


	return;
}


/* yah, you're right, it looks a bit messy, originally i wanted to put a
 * small .y parse in, will come at some time, if the complexity of the
 * possible configuration options exceed commandline/file freedom. ;-)
 */

void
read_fingerprint (fp_s *fp, char *pathname)
{
	int		in_fp = 0;
	FILE *		inf;
	unsigned char	line[128];
	unsigned char	keyword[64];
	unsigned char *	ha_p;
	unsigned char *	ha_p_end;


	inf = fopen (pathname, "r");
	if (inf == NULL) {
		fprintf (stderr, "failed to open fingerprint file \"%s\"\n",
			pathname);
		exit (EXIT_FAILURE);
	}

	fp->tests = 0;	/* file is going to tell us what to enable */

	/* read in test values and fingerprint raw data
	 * all the enable statements must preceed the fingerprint data !
	 */
	ha_p = fp->hash_arr;
	ha_p_end = ha_p + (N_TEST * N_SUBHASH);

	while (fgets (line, sizeof (line), inf) != NULL) {
		if (in_fp && strcmp (line, "end\n") == 0) {
			if ((ha_p - fp->hash_arr) !=
				(fp_counttests (fp) * N_SUBHASH))
			{
				fprintf (stderr, "test count and fingerprint "
					"do not match (%d to file: %d) !\n",
					fp_counttests (fp) * N_SUBHASH,
					ha_p - fp->hash_arr);

				exit (EXIT_FAILURE);
			}

			fclose (inf);
			return;
		}
		if (in_fp) {
			unsigned char *	lp;

#define	HEXCHECK(c) { if (strchr(hexarr,(c)) == NULL) {\
	fprintf(stderr, "invalid character \\x%02x in fingerprint data\n", (c));\
	exit (EXIT_FAILURE);}}
#define	HEXTRANS(c) ((unsigned int)(strchr(hexarr,(c)) - hexarr))

			for (lp = line ; strlen (lp) > 2 && ha_p < ha_p_end ; lp += 2) {
				char	hexarr[] = "0123456789abcdef";

				HEXCHECK(lp[0]); HEXCHECK(lp[1]);
				ha_p[0] = (HEXTRANS(lp[0]) << 4) |
					HEXTRANS(lp[1]);
				ha_p += 1;
			}
		} else if (strcmp (line, "begin\n") == 0) {
			in_fp = 1;
		} else if (sscanf (line, "enable %64s\n", keyword) == 1) {
			keyword[sizeof (keyword) - 1] = '\0';
			fp_tenable (fp, keyword);
		} else if (sscanf (line, "disable %64s\n", keyword) == 1) {
			keyword[sizeof (keyword) - 1] = '\0';
			fp_tdisable (fp, keyword);
		} else if (strlen (line) != 1 && line[0] != '#') {
			goto bail;
		}
	}

bail:
	fprintf (stderr, "syntax error in fingerprint file\n");

	exit (EXIT_FAILURE);
}


