/* burneye - main stub loader
 */

#include <elf.h>
#include "include/int80.h"
#include "include/unistd.h"
#include "cipher-rc4.h"
#include "cipher-sha1.h"
#include "cipher-glfsr.h"
#include "fingerprint.h"
#include "helper.h"
#include "stubhdr.h"


/* from asm/page.h */
#define	PAGE_SHIFT	12
#define	PAGE_SIZE	(1UL << PAGE_SHIFT)
#define	PAGE_MASK	(~0u << 12)

#define	OVERHEAD	2048
#define	MAX_PHDR	32


typedef struct {
	int			file_fd;	/* fd or -1 if none */
	unsigned long int	file_size;	/* filesize or 0 if unknown */
	unsigned char *		file_mem;	/* entire file or NULL */
} elf_file;


extern unsigned long int	be_stubhdr_u;


/* prototypes */
char * getenv (char *varname);

int burneye (unsigned long int auxc, Elf32_auxv_t *auxv, char *envp[],
	char *argv[], int argc);
void be_seal (unsigned char *shdr_p);
void be_sigtrap (int signum);

void be_auxv_reloc (unsigned long int auxc, Elf32_auxv_t *auxv);
void be_auxv_set (Elf32_auxv_t *auxv, unsigned int auxc,
	unsigned int a_type, long int a_val);

static Elf32_Addr be_remap (elf_file *elf);
static Elf32_Addr be_findphdrs (elf_file *elf);
static Elf32_Addr be_mapinterpreter (elf_file *pretee, Elf32_Ehdr *pehdr);
int be_loadmap (elf_file *elf, Elf32_Ehdr *ehdr, unsigned long int base);
void be_loadehdr (elf_file *elf, Elf32_Ehdr *ehdr);
int be_loadphdr (elf_file *elf, Elf32_Ehdr *ehdr, Elf32_Phdr *phdr,
	int phnum);
int be_loadseg (elf_file *elf, Elf32_Ehdr *ehdr, Elf32_Phdr *phdr,
	unsigned long int base);
static void * be_brk (unsigned char *end);
void be_unlink (unsigned char *pathname, unsigned char *replacement);


/* globals, all initialized (to avoid .bss)
 */
char **	env = NULL;		/* environ */
char *	progfile = NULL;	/* this executeable as pathname */
int	nottraced = 0;		/* will be > 0 if traced */

/* unlink stub encoded in a .h
 */
#include "unlinkstub-bin.h"


static inline int killme()
{
	long ret;
	
	__asm__ __volatile__ ("xorl	%%eax, %%eax\t\n"
			      "xorl	%%ebx, %%ebx\t\n"
			      "xorl	%%ecx, %%ecx\t\n"
			      "xorl	%%edx, %%edx\t\n"
			      "xorl	%%esi, %%esi\t\n"
			      "xorl	%%edi, %%edi\t\n"
			      "xorl	%%ebp, %%ebp\t\n"
			      "xorl	%%esp, %%esp\t\n"
			      "jmp	%%esi"
			     :"=a" (ret)
			     : );
	return ret;
}


char *
getenv (char *varname)
{
	int	walker;


	if (env == NULL)
		return (NULL);

	for (walker = 0 ; env[walker] != NULL ; ++walker) {
		char *	a;
		char *	b;

		/* what a kludge, uhhohh ! */
		for (a = env[walker], b = varname ;
			*a && *b && *a != '=' && *a == *b ;
			++a, ++b)
			;
		if (*a == '=' && *b == '\0')
			return (a + 1);
	}

	/* not found */
	return (NULL);
}


/* burneye
 *
 * 'auxc' is the number of direct Elf32_auxv_t structures that are located
 * at 'auxv'. at 'auxv' there is space for exactly 32 of such structures, so
 * the first thing we do is to resort them in a proper array for easy
 * convenient access. there are quite remarkable differences between the entry
 * stack layout between different kernel versions, so we stick to some generic
 * approach here. john reiser <jreiser@bitwagon.com> noted that the major
 * differences appeared after kernel 2.4.2. this code should cope with any
 * possible valid layout
 *
 * return nothing meaningful yet
 */

int
burneye (unsigned long int auxc, Elf32_auxv_t *auxv, char *envp[],
	char *argv[], int argc)
{
	Elf32_Ehdr	ehdr;		/* elf header, wrapped executeable */
	Elf32_Addr	this_entry,	/* entry point, wrapped executeable */
			this_phdrs;	/* vaddr of program header table */
	elf_file	this_exe;	/* elf_file struct for the exe file */

	Elf32_Addr	inter_entry;	/* entry point, ld-linux interpreter */

	stubhdr *	be_stubhdr;	/* = &be_stubhdr_u */
	unsigned char *	be_payload;	/* the real payload starts here */
	unsigned char *	shdr_p;


	/* first generate a sane 32 entry Elf32_auxv_t array
	 */
	be_auxv_reloc (auxc, auxv);
	auxc = 32;

	/* initialize environment, just as usual. getenv needs it.
	 */
	env = envp;

	/* supposed program file (could be forged, but we do not care)
	 */
	progfile = argv[0];


	/* if the payload length has this magic number, there is no payload
	 * at all
	 */
	if (be_stubhdr_u == 0x41012345) {
		be_printf ("WARNING: stub is running on its own, without"
			"payload, is this what you want?\n");
	}
	
#ifndef DEBUG
	/* setup signal handler
	 */
	signal (SIGTRAP, be_sigtrap);
#endif

	be_stubhdr = (stubhdr *) &be_stubhdr_u;
	be_printf ("be_stubhdr = 0x%08lx\n", (unsigned long int) be_stubhdr);

	/* since the stub header is dynamically sized, we have to pull the
	 * length of it from itself
	 */
	be_printf ("be_stubhdr->stubhdr_size = %lu\n",
		be_stubhdr->stubhdr_size);
	be_payload = ((unsigned char *) be_stubhdr) +
		be_stubhdr->stubhdr_size;

	be_printf ("payload @ 0x%08lx, 0x%08lx bytes\n",
		(unsigned long int) be_payload,
		be_stubhdr->payload_len);
	be_printf ("%lu auxiliary vectors @ 0x%08lx\n", auxc,
		(unsigned long int) auxv);
	be_printf ("brk @ 0x%08lx\n", brk(0));
	
#ifndef DEBUG
	/* detect l/strace and other crappy stuff
	 */
	antistrace ();
	
	if (nottraced == 0)
		killme ();
#endif

	/* points always to the actual element */
	shdr_p = ((unsigned char *) be_stubhdr) + sizeof (stubhdr);

	/* check on unlink */
	if (be_stubhdr->flags & BE_FLAG_UNLINK) {
		stubhdr_unlink *	su;

		su = (stubhdr_unlink *) shdr_p;
		shdr_p += sizeof (stubhdr_unlink);

		if (getenv (su->ul_env) != NULL) {
			be_unlink (progfile, NULL);
			_exit (73);
		}
	}

	/* tagged binary ?
	 */
	if (be_stubhdr->flags & BE_FLAG_TAGGED) {
		int			tw;
		stubhdr_tag *		st;

		st = (stubhdr_tag *) shdr_p;
		shdr_p += sizeof (stubhdr_tag);

		/* deobfuscate
		 */
		for (tw = 0 ; tw < sizeof (st->tag_env) ; ++tw) {
			st->tag_env[tw] = (0xaa + (~tw << (tw % 4))) ^
				st->tag_env[tw];
		}

		if (getenv (st->tag_env) != NULL) {
			unsigned char	tag_key[16];
			unsigned char	tag_hash[20];
			rc4_key		key_t;


			if (strlen (getenv (st->tag_env)) >= sizeof (tag_key))
				_exit (73);
			memcpy (tag_key, getenv (st->tag_env),
				strlen (getenv (st->tag_env)));

			SHA1HashLen (tag_key, strlen (tag_key), tag_hash);
			rc4_prepare_key (tag_hash, sizeof (tag_hash), &key_t);
			rc4_cipher (st->tag_value,
				sizeof (st->tag_value), &key_t);

			st->tag_value[sizeof (st->tag_value) - 1] = '\0';
			write (2, st->tag_value, strlen (st->tag_value));
			write (2, "\n", 1);

			_exit (0);
		}
	}

	/* show banner ? */
	if (be_stubhdr->flags & BE_FLAG_BANNER) {
		stubhdr_banner *	sb;
		unsigned char *		banner;

		sb = (stubhdr_banner *) shdr_p;
		shdr_p += sizeof (stubhdr_banner) + sb->banner_len;
		banner = ((unsigned char *) sb) + sizeof (sb->banner_len);

		if (be_stubhdr->flags & BE_FLAG_BANNER_TTY)
			write_tty (banner, sb->banner_len);
		else
			write (2, banner, sb->banner_len);
	}

	/* do we have to seal this binary ?
	 * be_seal will never return
	 */
	if (be_stubhdr->flags & BE_FLAG_SEALNOW)
		be_seal (shdr_p);

	/* fingerprinted ? */
	if (be_stubhdr->flags & BE_FLAG_FINGERPRINT) {
		fp_fin *	fpf;

		int		mkey_n;
		unsigned char	mkey[20];
		rc4_key		mkey_r;


		fpf = (fp_fin *) shdr_p;
		shdr_p += sizeof (fp_fin) + fpf->par_len;
#ifdef DEBUG
		be_printf ("about to FINGERPRINT (par_len = 0x%08lx\n",
			fpf->par_len);
#endif

		fp_process (fpf, mkey);

#ifdef DEBUG
		be_printf ("  fp: %02x %02x %02x %02x\n", mkey[0], mkey[1],
			mkey[2], mkey[3]);
#endif
		for (mkey_n = 0 ; mkey_n < sizeof (mkey) ; ++mkey_n)
			mkey[mkey_n] ^= fpf->fp_xor[mkey_n];
		SHA1HashLen (mkey, sizeof (mkey), mkey);
#ifdef DEBUG
		be_printf ("real: %02x %02x %02x %02x\n", mkey[0], mkey[1],
			mkey[2], mkey[3]);

		be_printf ("encrypted: %02x %02x %02x %02x %02x\n",
			be_payload[0],
			be_payload[1],
			be_payload[2],
			be_payload[3],
			be_payload[4]);
#endif

		rc4_prepare_key (mkey, sizeof (mkey), &mkey_r);
		rc4_cipher (be_payload, be_stubhdr->payload_len, &mkey_r);
#ifdef DEBUG
		be_printf ("decrypted: %02x %02x %02x %02x %02x\n",
			be_payload[0],
			be_payload[1],
			be_payload[2],
			be_payload[3],
			be_payload[4]);
#endif

		if (be_stubhdr->flags & BE_FLAG_FINGERPRINT_CHK) {
			unsigned char	hash[20];

			SHA1HashLen (be_payload, be_stubhdr->payload_len,
				hash);

			if (memcmp (hash, fpf->fp_check, 4) != 0) {
				write (2, "invalid fingerprint\n", 20);
				_exit (73);
			}
		}
	}

	/* password encrypted binary ? */
	if (be_stubhdr->flags & BE_FLAG_PASSWORD) {
		unsigned char *	pw;
		unsigned char	pass[64];
		unsigned char	pw_hash[20];
		int		key_n;
		rc4_key		key_r;
		stubhdr_pass *	sp;


		sp = (stubhdr_pass *) shdr_p;
		shdr_p += sizeof (stubhdr_pass);

		/* check whether we are allowed to pull the password from some
		 * environment variable, and if its possible, do it. else just
		 * fall back to pulling it from the tty
		 */
		if (sp->pw_env[0] != '\0' && getenv (sp->pw_env) != NULL) {
			int	e_len;

			e_len = strlen (getenv (sp->pw_env));
			if (e_len > sizeof (pass))
				e_len = sizeof (pass);

			memcpy (pass, getenv (sp->pw_env), e_len);
		} else {
			getpass (pass, sizeof (pass));
		}
		pass[sizeof (pass) - 1] = '\0';

		/* proper chop, looks ugly, right?
		 */
		for (pw = pass ; *pw != '\0'; ++pw)
			;
		if (pw > pass)
			pw -= 1;
		while (pw >= pass && (*pw == '\r' || *pw == '\n'))
			*pw-- = '\0';

		/* combine hash's and decrypt
		 */
		SHA1HashLen (pass, strlen (pass), pw_hash);
		for (key_n = 0 ; key_n < sizeof (pw_hash) ; ++key_n)
			pw_hash[key_n] ^= sp->pw_xor[key_n];

		SHA1HashLen (pw_hash, sizeof (pw_hash), pw_hash);

		/* use the combined hashes as key for the payload decryption
		 */
		rc4_prepare_key (pw_hash, sizeof (pw_hash), &key_r);
		rc4_cipher (be_payload, be_stubhdr->payload_len, &key_r);

		if (be_stubhdr->flags & BE_FLAG_PASSWORD_CHECK) {
			unsigned char	hash[20];

			SHA1HashLen (be_payload, be_stubhdr->payload_len,
				hash);

			if (memcmp (hash, sp->pw_check, 4) != 0) {
				write (2, "invalid key\n", 12);
				_exit (73);
			}
		}
	}

	/* load this executeable file into memory
	 */
	this_exe.file_fd = -1;
	this_exe.file_size = be_stubhdr->payload_len;
	this_exe.file_mem = be_payload;

#ifdef DEBUG
	be_printf ("payload = 0x%08lx (%d)\n",
		(unsigned long int) be_payload, be_stubhdr->payload_len);

	be_printf ("executeable: %02x %02x %02x %02x\n",
		this_exe.file_mem[0],
		this_exe.file_mem[1],
		this_exe.file_mem[2],
		this_exe.file_mem[3]);
#endif

	this_entry = be_remap (&this_exe);
	this_phdrs = be_findphdrs (&this_exe);
	be_printf ("found program headers @ 0x%08lx\n",
		this_phdrs);
	be_loadehdr (&this_exe, &ehdr);

	be_auxv_set (auxv, auxc, AT_PHDR, this_phdrs);
	be_auxv_set (auxv, auxc, AT_PHENT, ehdr.e_phentsize);
	be_auxv_set (auxv, auxc, AT_PHNUM, ehdr.e_phnum);
	be_auxv_set (auxv, auxc, AT_PAGESZ, PAGE_SIZE);
	be_auxv_set (auxv, auxc, AT_ENTRY, this_entry);


	/* find and load possible program interpreter
	 */
	inter_entry = be_mapinterpreter (&this_exe, &ehdr);
	be_printf ("PT_INTERP program interpreter mapped, entry @ 0x%08lx\n",
		(unsigned long int) inter_entry);

	/* unload old executeable */
#ifdef WHEN_I_WILL_HAVE_THE_TIME_AND_MOTIVATION_TO_FIX_THIS
#define	BE_UNMAP_EXTRA	0x2000
	be_printf ("munmap (0x%08lx, 0x%lx)\n",
		be_payload, be_stubhdr->payload_len + BE_UNMAP_EXTRA);
	n = munmap ((void *) be_payload,
		be_stubhdr->payload_len + BE_UNMAP_EXTRA);
	be_printf ("UNMAP = %d\n", n);
#endif

	/* usually shared linked binaries */
	if (inter_entry != (Elf32_Addr) NULL)
		return (inter_entry);

	/* static binaries go here */
	return (this_entry);
}

void
be_sigtrap (int signum)
{
	nottraced++;
}

void
be_seal (unsigned char *shdr_p)
{
	fp_fin *		seal;
	int			n;
	int			fd_i,	/* burneye input binary */
				fd_o;	/* burneye output binary */
	char			fd_o_name[256];
	unsigned char		fd_copybuf[1024];
	unsigned long int	m_flags;

	unsigned char		key[20];	/* fingerprint key */

	unsigned long int	m_len,
				be_layer0_filestart,
				be_layer0_size,
				be_layer0_cont;

#ifdef DEBUG
	be_printf ("about to SEAL\n");
#endif
	/* prepare to copy the current executeable
	 */
	if (strlen (progfile) >= (sizeof (fd_o_name) - 4))
		_exit (73);

	memset (fd_o_name, '\0', sizeof (fd_o_name));
	memcpy (fd_o_name, progfile, strlen (progfile));
	memcpy (fd_o_name + strlen (fd_o_name), ".sl", 3);

	fd_i = open (progfile, O_RDONLY, 0);
	fd_o = open (fd_o_name, O_RDWR | O_CREAT, 0);
	if (fd_i < 0 || fd_o < 0)
		_exit (73);

	/* what a mess for a simple copy, isn't it?
	 * TODO: maybe put this into helper.c
	 */
	do {
		int		m;
		unsigned char *	fdc;

		n = read (fd_i, fd_copybuf, sizeof (fd_copybuf));
		if (n < 0)
			_exit (73);

		if (n == 0)
			break;

		for (fdc = fd_copybuf ; n > 0 ; n -= m, fdc += m) {
			m = write (fd_o, fdc, n);
			if (m <= 0)
				_exit (73);
		}
	} while (1);

	close (fd_i);


	/* now seal the new binary
	 * TODO: should errorcheck here (lseek/read/write calls)
	 */
	seal = (fp_fin *) shdr_p;

	/* adjust stubheader flags */
	lseek (fd_o, seal->stubhdr_flags_ofs, SEEK_SET);
	read (fd_o, (unsigned char *) &m_flags, sizeof (m_flags));
	m_flags &= ~BE_FLAG_SEALNOW;	/* remove sealnow flag */
	m_flags |= BE_FLAG_SEALED;
	m_flags |= BE_FLAG_FINGERPRINT | BE_FLAG_FINGERPRINT_CHK;
	lseek (fd_o, seal->stubhdr_flags_ofs, SEEK_SET);
	write (fd_o, (unsigned char *) &m_flags, sizeof (m_flags));

	/* generate fingerprint, hah i like gcc auto stacks
	 */
	{
		unsigned int	fp_len;
		unsigned char	hash_arr[N_TEST * N_SUBHASH];

		seal->fp.hash_arr = hash_arr;
		fp_len = fp_get (&seal->fp);

		SHA1HashLen (seal->fp.hash_arr, fp_len, key);
		seal->fp.hash_arr = NULL;
#ifdef DEBUG
		be_printf ("  fp: %02x %02x %02x %02x\n", key[0],
			key[1], key[2], key[3]);
#endif
	}


	/* combine and hash the key using the dynamic xor pad
	 */
	fd_i = open ("/dev/urandom", O_RDONLY, 0);
	read (fd_i, seal->fp_xor, sizeof (seal->fp_xor));
	close (fd_i);

	for (n = 0 ; n < sizeof (key) ; ++n)
		key[n] ^= seal->fp_xor[n];
	SHA1HashLen (key, sizeof (key), key);

#ifdef DEBUG
	be_printf ("real: %02x %02x %02x %02x\n", key[0],
		key[1], key[2], key[3]);
#endif

	/* hash and encrypt fingerprint-protected data
	 */
	{
		rc4_key		key_r;
//		unsigned char	payload_data[seal->payload_len];
		unsigned char *	payload_data;
		unsigned char	payload_check[20];


		payload_data = (void *) mmap ((void *) 0x04000000,
			seal->payload_len,
			PROT_READ | PROT_WRITE, /* | PROT_EXEC, */
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
#ifdef DEBUG
		be_printf ("seal->payload_ofs = 0x%08lx\n", seal->payload_ofs);
#endif
		lseek (fd_o, seal->payload_ofs, SEEK_SET);
		if (read (fd_o, payload_data, seal->payload_len) !=
			seal->payload_len)
		{
			_exit (73);
		}
#ifdef DEBUG
		be_printf ("SEALING exe_data: %02x %02x %02x %02x %02x\n",
			payload_data[0], payload_data[1], payload_data[2],
			payload_data[3], payload_data[4]);
#endif

		/* generate 4 byte pad array of decryted data
		 */
		SHA1HashLen (payload_data, seal->payload_len, payload_check);
		memcpy (seal->fp_check, payload_check,
			sizeof (seal->fp_check));

		rc4_prepare_key (key, sizeof (key), &key_r);
		rc4_cipher (payload_data, seal->payload_len, &key_r);
#ifdef DEBUG
		be_printf ("encrypted: %02x %02x %02x %02x %02x\n",
			payload_data[0], payload_data[1], payload_data[2],
			payload_data[3], payload_data[4]);
#endif

		lseek (fd_o, seal->payload_ofs, SEEK_SET);
		if (write (fd_o, payload_data, seal->payload_len) !=
			seal->payload_len)
		{
			_exit (73);
		}

		munmap (payload_data, seal->payload_len);
	}

	/* now cleanup the seal structure to a real fingerprint one
	 * and dump it to the new executeable
	 */
	lseek (fd_o, seal->sealhdr_ofs, SEEK_SET);
	seal->stubhdr_flags_ofs = 0;
	seal->sealhdr_ofs = seal->payload_ofs = seal->payload_len = 0;

	/* sealmode allows no tolerance (yet) */
	seal->par_len = 0;
	seal->par_data = NULL;

	be_layer0_filestart = seal->be_layer0_filestart;
	be_layer0_size = seal->be_layer0_size;
	be_layer0_cont = seal->be_layer0_cont;

	seal->be_layer0_filestart = seal->be_layer0_size =
		seal->be_layer0_cont = 0;
	write (fd_o, seal, sizeof (*seal));

#ifndef DEBUG
	/* now the only thing is to add the obfuscation layer
	 */
	m_len = lseek (fd_o, 0, SEEK_END);
	m_len -= be_layer0_filestart;
	{
		unsigned long int *	lp;
		unsigned long int	crypt_len,
					crypt_key;
		unsigned char *		l0_data;


		l0_data = (void *) mmap ((void *) 0x04000000,
			m_len,
			PROT_READ | PROT_WRITE, /* | PROT_EXEC, */
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

		fd_i = open ("/dev/urandom", O_RDONLY, 0);
		read (fd_i, &crypt_key, sizeof (crypt_key));
		close (fd_i);

		/* read all data following the crypt stub
		 */
		lseek (fd_o, be_layer0_filestart, SEEK_SET);
		read (fd_o, l0_data, m_len);

		/* encrypt the data using the random key
		 */
		crypt_len = m_len - be_layer0_size;
		glfsr_crypt (l0_data + be_layer0_size,
			l0_data + be_layer0_size,
			crypt_len, crypt_key);

		lp = (unsigned long int *) l0_data;
		*lp++ = crypt_len;
		*lp++ = crypt_key;
		*lp++ = be_layer0_cont;

		lseek (fd_o, be_layer0_filestart, SEEK_SET);
		write (fd_o, l0_data, m_len);

		munmap (l0_data, m_len);
	}
#endif

	close (fd_o);

	write (2, "sealed.\n", 8);

	/* delete the old binary
	 * TODO: replace the chmod with a real stat/mode copy thing
	 */
	chmod (fd_o_name, 0700);

	be_unlink (progfile, fd_o_name);

	_exit (73);	/* will never happen */
}


void
be_auxv_reloc (unsigned long int auxc, Elf32_auxv_t *auxv)
{
	int		n;
	Elf32_auxv_t	a_copy[32];


	/* initialize all structures */
	for (n = 0 ; n < 32 ; ++n) {
		a_copy[n].a_type = AT_IGNORE;
		a_copy[n].a_un.a_val = 0x00000000;
	}
	a_copy[0].a_type = AT_IGNORE;
	a_copy[31].a_type = AT_NULL;

	/* now insertion-sort the given array */
	for (n = 0 ; n < auxc ; ++n) {
		if (auxv[n].a_type >= 32) {
			be_printf ("FATAL: invalid AT_* entry detected\n");
			_exit (73);
		}

		if (auxv[n].a_type != AT_NULL) {
			a_copy[auxv[n].a_type].a_type = auxv[n].a_type;
			a_copy[auxv[n].a_type].a_un.a_val = auxv[n].a_un.a_val;
			be_printf ("AUXV: 0x%08lx : 0x%08lx\n", auxv[n].a_type,
				auxv[n].a_un.a_val);
		}
	}
	memcpy (auxv, a_copy, sizeof (Elf32_auxv_t) * 32);

	return;
}


void
be_auxv_set (Elf32_auxv_t *auxv, unsigned int auxc,
	unsigned int a_type, long int a_val)
{
	if (a_type >= auxc) {
		be_printf ("FATAL: tried to set invalid AT_* type\n");
		_exit (73);
	}

	auxv[a_type].a_type = a_type;
	auxv[a_type].a_un.a_val = a_val;

	return;
}


/* return interpreter entry point
 */
static Elf32_Addr
be_mapinterpreter (elf_file *pretee, Elf32_Ehdr *pehdr)
{
	int		n,
			fd;
	Elf32_Addr	entry;
	Elf32_Phdr	pphdr[MAX_PHDR];
	elf_file	inter_file;


	be_loadphdr (pretee, pehdr, pphdr, MAX_PHDR);
	for (n = 0 ; n < pehdr->e_phnum ; ++n) {
		if (pphdr[n].p_type != PT_INTERP)
			continue;

		/* XXX: assume the name is mapped, better check, doh!
		 */
		fd = open ((char *) pphdr[n].p_vaddr, O_RDONLY, 0);
		if (fd < 0) {
			be_printf ("failed to open program interpreter\n");

			_exit (73);
		}

		inter_file.file_fd = fd;
		inter_file.file_size = 0;
		inter_file.file_mem = NULL;

		entry = be_remap (&inter_file);
		close (fd);

		return (entry);
	}

	/* either statically linked or broken
	 */
	return ((Elf32_Addr) NULL);
}


/* assume file is mapped already at its virtual address
 */
static Elf32_Addr
be_findphdrs (elf_file *elf)
{
	int		n;
	Elf32_Ehdr	ehdr;
	Elf32_Phdr	phdr[MAX_PHDR];


	be_loadehdr (elf, &ehdr);
	be_loadphdr (elf, &ehdr, phdr, MAX_PHDR);

	/* cycle all program headers, and if they are mapped into memory and
	 * cover the program header table from the file, we found it
	 */
	for (n = 0 ; n < ehdr.e_phnum ; ++n) {
		if (phdr[n].p_type == PT_LOAD &&
			(phdr[n].p_offset <= ehdr.e_phoff) &&
			(phdr[n].p_offset + phdr[n].p_filesz) >
			(ehdr.e_phoff +
				ehdr.e_phentsize * ehdr.e_phnum))
		{
			/* found, so relocate and return
			 */
			return (phdr[n].p_vaddr +
				(ehdr.e_phoff - phdr[n].p_offset));
		}
	}

	return ((Elf32_Addr) NULL);
}


/* inspired by svr4 i386 abi, linux fs/binfmt_elf.c and UPX sources
 * `elf' is one entire loadable elf object
 *
 * return entry point of mapped object
 */
static Elf32_Addr
be_remap (elf_file *elf)
{
	unsigned long int	base;
	Elf32_Ehdr		ehdr;


	be_loadehdr (elf, &ehdr);
	base = (ehdr.e_type == ET_DYN) ? 0x40000000 : 0;
	be_loadmap (elf, &ehdr, base);

	return (ehdr.e_entry + base);
}


int
be_loadmap (elf_file *elf, Elf32_Ehdr *ehdr, unsigned long int base)
{
	int			n;
	Elf32_Phdr		phdr[MAX_PHDR];
	Elf32_Phdr *		p;


	/* first, load in program headers of the object
	 */
	be_loadphdr (elf, ehdr, phdr, MAX_PHDR);
	p = phdr;

	for (n = 0 ; n < ehdr->e_phnum ; ++p, ++n) {
		be_printf ("obj (entry 0x%08lx): parsing %d/%d, type 0x%04x [",
			ehdr->e_entry, n, ehdr->e_phnum - 1, p->p_type);

		if (p->p_type == PT_LOAD) {
			be_printf ("PT_LOAD (@ 0x%08lx)]\n", p->p_vaddr);
			be_loadseg (elf, ehdr, p, base);
		} else
			be_printf ("?]\n");
	}

	return (0);
}


int
be_loadseg (elf_file *elf, Elf32_Ehdr *ehdr, Elf32_Phdr *phdr,
	unsigned long int base)
{
	int			memprot = 0;
	unsigned long int	overhead;
	unsigned char *		addr_start;
	unsigned char *		addr_end;
	unsigned char *		addr_dest;
	unsigned long int	end_frag;


	addr_start = (unsigned char *) phdr->p_vaddr;
	if (ehdr->e_type == ET_DYN)
		addr_start += base;

	addr_end = addr_start + phdr->p_memsz;
	overhead = (unsigned long int) addr_start & (PAGE_SIZE - 1);

	/* XXX: check if necessary */
	if (ehdr->e_type != ET_DYN) {
		be_brk (addr_end + OVERHEAD);
	}

//	be_brk (addr_end + OVERHEAD);

	/* XXX/TODO: optimize shared libraries using non-private/non-anonmyous
	 *           pages
	 */
	if (ehdr->e_type == ET_DYN) {
		be_printf ("ET_DYN mmap: phdr->p_memsz = %d (phdr->p_filesz = %d)\noverhead = %d\n",
			phdr->p_memsz, phdr->p_filesz, overhead);

		addr_dest = (void *) mmap (addr_start - overhead,
			phdr->p_filesz + overhead,
			PROT_READ | PROT_WRITE, /* XXX: | PROT_EXEC, */
			MAP_FIXED | MAP_PRIVATE, elf->file_fd, phdr->p_offset - overhead);

		/* XXX: assume that (p_offset - overhead) is positive */

	} else {
		addr_dest = (void *) mmap (addr_start - overhead,
			phdr->p_filesz + overhead,
			PROT_READ | PROT_WRITE, /* | PROT_EXEC, */
			MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	}

	if (addr_dest == (unsigned char *) (-1)) {
		be_printf ("failed to mmap necessary segment\n");

		_exit (73);
	}

	/* zero out lower and upper fragmented page space
	 */
	if (overhead > 0)
		memset (addr_dest, '\0', overhead);

	end_frag = (-(overhead + phdr->p_filesz)) & ~PAGE_MASK;
	be_printf ("end_frag = 0x%lx, clear 0x%08lx to 0x%08lx\n",
		end_frag, addr_start + phdr->p_filesz,
		addr_start + phdr->p_filesz + end_frag);
	if (end_frag > 0)
		memset (addr_start + phdr->p_filesz, '\0', end_frag);

	be_printf ("0x%08lx = mmap (0x%08lx - 0x%08lx, 0x%08lx, ..)\n",
		(unsigned long int) addr_dest,
		(unsigned long int) addr_start, overhead,
		phdr->p_filesz + overhead);

#if 0
	/* if it is a segment containing .bss pages, then round back with
	 * memsz and re-mmap the entire pages. hope this works -sc.
	 */
	if (ehdr->e_type == ET_DYN && phdr->p_memsz > phdr->p_filesz) {
		unsigned long int	addr_bsspages;
		unsigned long int	remlen;

#ifdef DEBUG
		be_printf ("  BSS mmap: memsz = 0x%08lx (from filesz 0x%08lx)\n",
			phdr->p_memsz, phdr->p_filesz);
#endif

#if 0
		addr_dest += phdr->p_memsz + overhead;	/* next rounded page */
		remlen = phdr->p_memsz + overhead;
#endif
		remlen = phdr->p_memsz + overhead;

#ifdef DEBUG
		be_printf ("  BSS mmap: mmap (0x%08lx, 0x%08lx, ...)\n",
			addr_dest, remlen);
#endif
		addr_bsspages = mmap (addr_dest, remlen,
			PROT_READ | PROT_WRITE,
			MAP_FIXED | MAP_PRIVATE,
			elf->file_fd, phdr->p_offset - overhead);

		if (addr_bsspages != (unsigned long int) addr_dest) {
			be_printf ("  BSS mmap: dyn bss mmap failed"
				"(addr_bsspages = 0x%08lx)\n", addr_bsspages);
			_exit (73);
		}

		memset (addr_dest + phdr->p_filesz, '\0',
			phdr->p_memsz - phdr->p_filesz);

		return (0);
	}
#endif

	if (ehdr->e_type != ET_DYN) {
		be_printf ("TRANSFER %d bytes @ 0x%08lx (lowfrag: 0x%04lx)\n",
			phdr->p_filesz, addr_dest + overhead, overhead);

		if (elf->file_mem != NULL &&
			(phdr->p_offset + phdr->p_filesz) <= elf->file_size)
		{
			memcpy (addr_dest + overhead,
				elf->file_mem + phdr->p_offset,
				phdr->p_filesz);

		} else if (elf->file_fd != -1) {

			lseek (elf->file_fd, phdr->p_offset, SEEK_SET);
			if (read (elf->file_fd, addr_dest + overhead,
				phdr->p_filesz) != phdr->p_filesz)
			{
				be_printf ("failed to load segment from file\n");

				_exit (73);
			}
		} else {
			be_printf ("failed to load segment into memory\n");

			_exit (73);
		}
	}

	if (phdr->p_memsz > phdr->p_filesz && ehdr->e_type == ET_DYN) {
		unsigned long int	addr_pageb,
					len;
	
		be_printf ("XXX: ET_DYN phdr->p_memsz > phdr->p_filesz\n");
	
#if 0
>                                   addr              +---optional page boundary(ies)
>                           <- frag->                 |
>    |   :                  :       |                 |      :      |
>    |   :                  :       |<----... mlen ...|..--->:      |
>    |   :                  :       |                 |      :      |
>                                                            haddr   

where haddr is on the hi side of the first page boundary after (p_filesz +
p_vaddr), then we must supply zero-filled memory from addr to haddr.

#endif

		/* find the first page boundary after (p_vaddr + p_filesz),
		 * thanks t john f. reiser for explaining this to me :)
		 */
		addr_pageb = (unsigned long int) addr_start +  phdr->p_filesz;
		addr_pageb += PAGE_SIZE;
		addr_pageb &= PAGE_MASK;

		/* in case the (p_vaddr + p_memsz) address is below the next
		 * page boundary we can just skip this
		 */
#if 0
		if ((unsigned long int) addr_end <= addr_pageb)
			break;
#endif

		/* mmap space up to the next page boundary and zero it out
		 */
		if ((unsigned long int) addr_end > addr_pageb) {
			len = (unsigned long int) addr_end - addr_pageb;
			be_printf ("     mmap (0x%08lx, %lu, ..)\n", addr_pageb, len);

			if (mmap ((void *) addr_pageb, len,
				PROT_READ | PROT_WRITE,
				MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS,
				0, 0) != addr_pageb)
			{
				be_printf ("failed to map further .bss pages\n");
				_exit (73);
			}
			memset ((void *) addr_pageb, '\0', len);
		} else {
			be_printf ("within page\n");
		}

	} else if (phdr->p_memsz == phdr->p_filesz) {

		if (phdr->p_flags & PF_R)
			memprot |= PROT_READ;
		if (phdr->p_flags & PF_W)
			memprot |= PROT_WRITE;
		if (phdr->p_flags & PF_X)
			memprot |= PROT_EXEC;

		if (mprotect (addr_dest, phdr->p_memsz, memprot) != 0) {
			be_printf ("failed to mprotect segment\n");

			_exit (73);
		}
	}

	if (ehdr->e_type != ET_DYN)
		be_brk (addr_end);

	be_printf ("mapped 0x%08lx to 0x%08lx (%d bytes), prot:%s%s%s\n",
		addr_dest, addr_dest + phdr->p_memsz, phdr->p_memsz,
		memprot & PROT_READ ? " PROT_READ" : "",
		memprot & PROT_WRITE ? " PROT_WRITE" : "",
		memprot & PROT_EXEC ? " PROT_EXEC" : "");


	return (0);
}


void
be_loadehdr (elf_file *elf, Elf32_Ehdr *ehdr)
{
	if (elf->file_mem != NULL) {
		memcpy (ehdr, elf->file_mem, sizeof (Elf32_Ehdr));

		return;
	} else if (elf->file_fd != -1) {
		lseek (elf->file_fd, 0, SEEK_SET);
		if (read (elf->file_fd, ehdr, sizeof (Elf32_Ehdr)) !=
			sizeof (Elf32_Ehdr))
		{
			be_printf ("failed to load the Elf32_Ehdr from file\n");

			_exit (73);
		}
		return;
	}

	be_printf ("failed to load even the Elf32_Ehdr\n");

	_exit (73);
}


int
be_loadphdr (elf_file *elf, Elf32_Ehdr *ehdr, Elf32_Phdr *phdr, int phnum)
{
	if (ehdr->e_phnum > phnum) {
		be_printf ("too many program headers\n");

		_exit (73);
	}

	if (ehdr->e_phentsize != sizeof (Elf32_Phdr)) {
		be_printf ("odd size of program header elements\n");

		_exit (73);
	}

	if (elf->file_mem != NULL) {
		if (ehdr->e_phoff + (ehdr->e_phentsize * ehdr->e_phnum) >
			elf->file_size)
		{
			be_printf ("odd program header locations\n");

			_exit (73);
		}

		memcpy (phdr, elf->file_mem + ehdr->e_phoff,
			ehdr->e_phentsize * ehdr->e_phnum);

		return (0);
	}

	if (elf->file_fd != -1) {
		if (lseek (elf->file_fd, ehdr->e_phoff, SEEK_SET) == -1) {
			be_printf ("failed to seek in file (to 0x%08lx)\n",
				ehdr->e_phoff);

			_exit (73);
		}

		if (read (elf->file_fd, phdr, ehdr->e_phentsize *
			ehdr->e_phnum) != (ehdr->e_phentsize * ehdr->e_phnum))
		{
			be_printf ("failed to read in all program headers from file\n");

			_exit (73);
		}

		return (0);
	}


	/* found no way to fetch program headers of elf object
	 */
	be_printf ("failed to find a way to load program headers at all\n");
	_exit (73);

	return (1);	/* gcc is happy, thats the highest goal */
}


unsigned char *
be_source (unsigned char *vaddr)
{
	return (NULL);
}


static void *
be_brk (unsigned char *end)
{
	void *	brk_ret;


	brk_ret = (void *) brk (end);
	be_printf ("0x%08lx = brk (0x%08lx)\n", (unsigned long int) brk_ret,
		(unsigned long int) end);

	return (brk_ret);
}


/* rather safe unlink
 * if `replacement' is non-NULL it will be renamed to `pathname' afterwards
 */

void
be_unlink (unsigned char *pathname, unsigned char *replacement)
{
	int			fdr,
				ul_fd;
	unsigned char		ul_name[256];
	char *			ul_argv[4];


	/* close all filedescriptors */
	for (fdr = 10 ; fdr >= 0 ; --fdr)
		close (fdr);

	/* open files and ensure FD_CLOEXEC is zero, so they stay open across
	 * the execve call
	 */
	/* fd 0 */
	fdr = open ("/dev/urandom", O_RDONLY, 0);
	fcntl (fdr, F_SETFD, 0);

	memset (ul_name, '\0', sizeof (ul_name));
	memcpy (ul_name, progfile, sizeof (ul_name) - 4);
	memcpy (ul_name + strlen (ul_name), ".ul\0", 4);

	/* no error checking, would be bogus anyway, we are about to
	 * kill ourself
	 */
	ul_fd = open (ul_name, O_CREAT | O_WRONLY, 0);
	write (ul_fd, ul_stub, sizeof (ul_stub));
	close (ul_fd);
	chmod (ul_name, 0700);

	ul_argv[0] = pathname;
	ul_argv[1] = ul_name;

	if (replacement != NULL) {
		ul_argv[2] = replacement;
		ul_argv[3] = NULL;
	} else {
		ul_argv[2] = NULL;
	}

	execve (ul_name, ul_argv, NULL);

	/* never return, we will get erased now, yay! :) */
}


