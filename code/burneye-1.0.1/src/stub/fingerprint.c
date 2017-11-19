/* fingerprinting functions
 *
 * we use 18 byte subhashes (first 144 bit of sha1 160 bit hash) here, to
 * better line up with the pre reed solomon transformation. then finally,
 * the key is a real 20 byte sha1 hash of the subhash array
 */

#ifndef	IN_STUB
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#else
#include "include/int80.h"
#include "include/unistd.h"
#include "helper.h"
#endif

#include "fingerprint.h"
#include "cipher-sha1.h"
#include "rs.h"

/* externals */
extern unsigned int	KK;

/* prototypes */
static unsigned int
fp_sgrep (char *pathname, char *seq, unsigned char *buf,
	unsigned int buf_len);
void strlcat (unsigned char *tgt, unsigned int len, unsigned char *str);


#ifndef	IN_STUB
int	test_sysbase = 1;	/* fixed information */
int	test_sysinstall = 1;	/* information that varies each installation */
int	test_procpci = 1;	/* /proc/pci | grep "bridge:" output */
int	test_proccpu = 1;	/* /proc/cpuinfo, certain characteristics */
int	test_procmem = 1;	/* /proc/meminfo, total system memory */
int	test_procroute = 1;	/* /proc/net/route, system routing table */
int	test_procpartitions = 1;/* /proc/partitions, harddisk partitions */


/* option table */
typedef struct {
	char *			name;
	unsigned long int	c_num;
} elem;

/* the order is important, low bits come first */
elem	e_list[] = {
	{ "sysbase", FP_SYSBASE },
	{ "sysinstall", FP_SYSINSTALL },
	{ "procpci", FP_PROCPCI },
	{ "proccpu", FP_PROCCPU },
	{ "procmem", FP_PROCMEM },
	{ "procroute", FP_PROCROUTE },
	{ "procpartitions", FP_PROCPARTITIONS },
	{ NULL, 0 },
};


void
fp_tenable (fp_s *fp, char *arg)
{
	fp->tests |= fp_tlookup (arg);
}


void
fp_tdisable (fp_s *fp, char *arg)
{
	fp->tests &= ~(fp_tlookup (arg));
}


int
fp_counttests (fp_s *fp)
{
	int	n,
		count = 0;

	for (n = 0 ; n < 32 ; ++n) {
		if (fp->tests & (1 << n))
			count += 1;
	}

	return (count);
}


unsigned long int
fp_tlookup (char *arg)
{
	int	n;

	for (n = 0 ; e_list[n].name != NULL ; ++n)
		if (strcmp (e_list[n].name, arg) == 0)
			return (e_list[n].c_num);

	fprintf (stderr, "invalid symbol\n");

	exit (EXIT_FAILURE);
}


void
fp_tlist (unsigned long int tests)
{
	int	n;

	printf ("%-17s     value\n", "name of test");
	printf ("----------------+----------\n");
	for (n = 0 ; e_list[n].name != NULL ; ++n)
		printf ("%-17s0x%08lx (default: %s)\n", e_list[n].name,
			e_list[n].c_num,
			tests & fp_tlookup (e_list[n].name) ?
			"enabled" : "disabled");
	printf ("----------------+----------\n");
}


#endif


#ifdef	STANDALONE
static void usage (char *progname);

void
hexdump_s (FILE *outf, unsigned char *data, unsigned int amount);

void
hexdump (unsigned char *data, unsigned int amount);


fp_s	template = {
	NULL,	/* hash array pointer */

	/* default fingerprints to take */
	FP_TEMPLATE,
};

char *	outname = NULL;
FILE *	outf = NULL;



static void
usage (char *progname)
{
	fprintf (stderr, "usage: %s [options]\n\n"
		"\t-h\tthis help\n"
		"\t-e opt\tenable fingerprint option\n"
		"\t-d opt\tdisable fingerprint option\n"
		"\t-l\tlist fingerprint options\n"
		"\t-f name\tset output file name (default: stdout)\n\n",
		progname);

	exit (EXIT_FAILURE);
}


int
main (int argc, char *argv[])
{
	int		n;
	char		c;
	char *		progname = argv[0];
	int		out_c;
	unsigned char	hash_arr[N_TEST * N_SUBHASH];


	if (argc == 1)
		fprintf (stderr, "run %s -h for options\n\n", progname);

	template.hash_arr = hash_arr;

	while ((c = getopt (argc, argv, "he:d:lf:")) != EOF) {
		switch (c) {
		case 'h':
			usage (progname);
			break;
		case 'e':
			fp_tenable (&template, optarg);
			break;
		case 'd':
			fp_tdisable (&template, optarg);
			break;
		case 'l':
			fp_tlist (template.tests);
			exit (EXIT_SUCCESS);
			break;
		case 'f':
			outname = optarg;
			break;
		default:
			usage (progname);
			break;
		}
	}

	if (outname != NULL) {
		outf = fopen (outname, "w");
		if (outf == NULL) {
			perror ("fopen output file");
			exit (EXIT_FAILURE);
		}
	} else
		outf = stdout;

	out_c = fp_get (&template);

	for (n = 0 ; e_list[n].name != NULL ; ++n)
		if (template.tests & e_list[n].c_num)
			fprintf (outf, "enable %s\n", e_list[n].name);

	fprintf (outf, "begin\n");
	hexdump_s (outf, template.hash_arr, out_c);
	fprintf (outf, "end\n");

	exit (EXIT_SUCCESS);
}
#endif


unsigned int
fp_get (fp_s *fs)
{
	struct utsname	un;
	unsigned char *	ha;
	unsigned char	tmpstr[1024];


	memset (fs->hash_arr, '\0', N_TEST * N_SUBHASH);
	ha = fs->hash_arr;


	if ((fs->tests & FP_SYSBASE) || (fs->tests & FP_SYSINSTALL))
		uname (&un);

	/* (fs->tests & FP_sysbase: sysname, nodename, machine */
	if (fs->tests & FP_SYSBASE) {
		memset (tmpstr, '\0', sizeof (tmpstr));
		strlcat (tmpstr, sizeof (tmpstr), un.sysname);
		strlcat (tmpstr, sizeof (tmpstr), un.nodename);
		strlcat (tmpstr, sizeof (tmpstr), un.machine);
		tmpstr[sizeof (tmpstr) - 1] = '\0';
		SHA1Hash (tmpstr, ha);
		ha += N_SUBHASH;
	}

	/* (fs->tests & FP_sysinstall: release, version XXX: more strict than sysbase */
	if (fs->tests & FP_SYSINSTALL) {
		memset (tmpstr, '\0', sizeof (tmpstr));
		strlcat (tmpstr, sizeof (tmpstr), un.release);
		strlcat (tmpstr, sizeof (tmpstr), un.version);
		tmpstr[sizeof (tmpstr) - 1] = '\0';
		SHA1Hash (tmpstr, ha);
		ha += N_SUBHASH;
	}

	/* (fs->tests & FP_procpci: pci registered bridges */
	if (fs->tests & FP_PROCPCI) {
		memset (tmpstr, '\0', sizeof (tmpstr));
		fp_sgrep ("/proc/pci", "bridge:", tmpstr, sizeof (tmpstr));
		tmpstr[sizeof (tmpstr) - 1] = '\0';
		SHA1Hash (tmpstr, ha);
		ha += N_SUBHASH;
	}

	/* (fs->tests & FP_proccpu: generic cpu fingerprint */
	if (fs->tests & FP_PROCCPU) {
		memset (tmpstr, '\0', sizeof (tmpstr));
		fp_sgrep ("/proc/cpuinfo", "vendor_id",
			tmpstr, sizeof (tmpstr));
		tmpstr[sizeof (tmpstr) - 1] = '\0';
		fp_sgrep ("/proc/cpuinfo", "model",
			tmpstr + strlen (tmpstr),
			sizeof (tmpstr) - strlen (tmpstr));
		tmpstr[sizeof (tmpstr) - 1] = '\0';
		fp_sgrep ("/proc/cpuinfo", "flags",
			tmpstr + strlen (tmpstr),
			sizeof (tmpstr) - strlen (tmpstr));
		tmpstr[sizeof (tmpstr) - 1] = '\0';

		SHA1Hash (tmpstr, ha);
		ha += N_SUBHASH;
	}

	/* (fs->tests & FP_procmem: total system memory size */
	if (fs->tests & FP_PROCMEM) {
		memset (tmpstr, '\0', sizeof (tmpstr));
		fp_sgrep ("/proc/meminfo", "MemTotal:",
			tmpstr, sizeof (tmpstr));
		tmpstr[sizeof (tmpstr) - 1] = '\0';

		SHA1Hash (tmpstr, ha);
		ha += N_SUBHASH;
	}

	/* (fs->tests & FP_procroute: routing table */
	if (fs->tests & FP_PROCROUTE) {
		memset (tmpstr, '\0', sizeof (tmpstr));
		fp_sgrep ("/proc/net/route", NULL, tmpstr, sizeof (tmpstr));
		tmpstr[sizeof (tmpstr) - 1] = '\0';

		SHA1Hash (tmpstr, ha);
		ha += N_SUBHASH;
	}

	/* (fs->tests & FP_procpartitions: partition tables */
	if (fs->tests & FP_PROCPARTITIONS) {
		memset (tmpstr, '\0', sizeof (tmpstr));
		fp_sgrep ("/proc/partitions", NULL, tmpstr, sizeof (tmpstr));
		tmpstr[sizeof (tmpstr) - 1] = '\0';

		SHA1Hash (tmpstr, ha);
		ha += N_SUBHASH;
	}


	return (ha - fs->hash_arr);
}


/* fp_sgrep
 *
 * simple single sequence grep with only syscalls. read from file with
 * pathname 'pathname' only lines that contain the sequence 'seq' (or every
 * line, when NULL), appending all lines (including '\n') to buffer 'buf',
 * which is 'buf_len' bytes long.
 *
 * return number of bytes in buffer
 */

static unsigned int
fp_sgrep (char *pathname, char *seq, unsigned char *buf, unsigned int buf_len)
{
	int		fd,
			n;
	unsigned char *	lp;
	unsigned char *	sp;
	unsigned char	line[256];
	unsigned int	ret = 0;


	fd = open (pathname, O_RDONLY, 0);
	if (fd < 0) {
#ifndef	IN_STUB
		perror ("fp_sgrep:open");
		exit (EXIT_FAILURE);
#else
		_exit (73);
#endif
	}

	/* uhh yes, i know it looks like a kludge, but i cannot rely on any
	 * library function, for that the same code runs from within the stub,
	 * syscall wise too. :(
	 */
	do {
		lp = line;
		do {
			n = read (fd, lp, 1);
		} while (n == 1 && *lp != '\0' && *lp != '\n' &&
			lp++ <= (line + sizeof (line)));

		if (n <= 0) {
			close (fd);

			return (ret);
		}

		if (seq == NULL) {
			memcpy (buf, line, lp - line + 1);
			buf += (lp - line) + 1;
			ret += (lp - line) + 1;
		} else {
			for (sp = line ; sp < (lp - strlen (seq)) ; ++sp) {
				if (memcmp (sp, seq, strlen (seq)) == 0 &&
					(lp - line) < buf_len)
				{
					memcpy (buf, line, lp - line + 1);
					buf += (lp - line) + 1;
					ret += (lp - line) + 1;
					sp = lp;	/* one time is enough */
				}
			}
		}
	} while (1);
}


#ifdef STANDALONE
void
hexdump_s (FILE *outf, unsigned char *data, unsigned int amount)
{
	unsigned int	dp;	/* data pointer */

	for (dp = 1 ; dp <= amount ; ++dp) {
		fprintf (outf, "%02x", data[dp-1]);
		if (dp % 16 == 0)
			fprintf (outf, "\n");
	}
	if ((dp - 1) % 16 != 0)
		fprintf (outf, "\n");

	return;
}


void
hexdump (unsigned char *data, unsigned int amount)
{
	unsigned int	dp, p;	/* data pointer */
	const char	trans[] =
		"................................ !\"#$%&'()*+,-./0123456789"
		":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
		"nopqrstuvwxyz{|}~...................................."
		"....................................................."
		"........................................";

	for (dp = 1; dp <= amount; dp++) {
		printf ("%02x ", data[dp-1]);
		if ((dp % 8) == 0)
			printf (" ");
		if ((dp % 16) == 0) {
			printf ("| ");
			p = dp;
			for (dp -= 16; dp < p; dp++)
				printf ("%c", trans[data[dp]]);
			printf ("\n");
		}
	}
	if ((amount % 16) != 0) {
		p = dp = 16 - (amount % 16);
		for (dp = p; dp > 0; dp--) {
			printf ("   ");
			if (((dp % 8) == 0) && (p != 8))
				printf (" ");
		}
		printf (" | ");
		for (dp = (amount - (16 - p)); dp < amount; dp++)
			printf ("%c", trans[data[dp]]);
	}
	printf ("\n");

	return;
}
#endif


void
strlcat (unsigned char *tgt, unsigned int len, unsigned char *str)
{
	len -= strlen (tgt);
	tgt += strlen (tgt);
	memcpy (tgt, str, (strlen (str) + 1) > len ? len : (strlen (str) + 1));
}


unsigned long int
fp_padgen (unsigned char *data, unsigned int data_len, unsigned char *pad,
	unsigned int pad_len, unsigned int data_recover)
{
	unsigned int	tr_arr[NN];


	/* assume a good (n * 8/12 < NN) length here, rs_* will check
	 */
	memset (tr_arr, '\0', sizeof (tr_arr));
	rs_trans (data, data_len, &tr_arr[0], NN);

	/* computing the number of data symbols */
	data_len *= 8;
	data_len /= 12;
	data_recover *= 8;
	data_recover /= 12;

	/* the following line is the pure essence of the entire fingerprint
	 * deviation mathematics we do here
	 */
	KK = NN - (2 * data_recover);

	/* generate error correction block
	 */
	rs_encode (&tr_arr[0], &tr_arr[KK]);

	/* now we have the following layout of the tr_arr array:
	 *
	 * 0                  data_len         KK
	 * [data_len symbols] | [zero padding] | [error correction symbols]
	 *
	 * package the error correction symbols back into a byte array
	 */
	rs_detrans (pad, pad_len, &tr_arr[KK], NN - KK);

	/* number of parity bytes. always fits.
	 */
	return ((12 * 2 * data_recover) / 8);
}


int
fp_padfix (unsigned char *data, unsigned int data_len,
	unsigned char *pad, unsigned int pad_len)
{
	int		n;
	unsigned int	tr_arr[NN];


	/* again, transform 8 to 12 bits */
	memset (tr_arr, '\0', sizeof (tr_arr));
	rs_trans (data, data_len, tr_arr, NN);

	data_len *= 8;
	data_len /= 12;

	/* calculate KK accordingly to the pad length
	 */
	KK = NN - ((pad_len * 8) / 12);
	rs_trans (pad, pad_len, &tr_arr[KK], NN - KK);

	/* now, we try to fixup any errors. since the knowledge about possible
	 * erasures (i.e. known places of errors) can double the number of
	 * corrected symbols there may be a way to shortcut brute force attacks
	 * by giving the sha1 subhash boundaries through erasures, much like
	 * the reed solomon features at correcting burst errors. this is bad.
	 */
	n = rs_eras_dec (tr_arr, NULL, 0);

	rs_detrans (data, ((data_len * 12) / 8), &tr_arr[0], data_len);

	return (n != -1 ? 0 : 1);
}


#ifdef IN_STUB

void
fp_process (fp_fin *fpf, unsigned char *key)
{
#ifdef FP_DEBUG
	int		pad_res;
#endif
	unsigned int	ha_len;
	unsigned char	hash_arr[N_TEST * N_SUBHASH];

#ifdef DEBUG
	be_printf ("test: 0x%08lx\n", fpf->fp.tests);
#endif

	fpf->fp.hash_arr = hash_arr;
	ha_len = fp_get (&fpf->fp);

#ifdef DEBUG
	be_printf ("  fp: %02x %02x %02x %02x\n",
		hash_arr[0], hash_arr[1], hash_arr[2], hash_arr[3]);
#endif

	/* if there is a rescue pad to fix deviation with, apply it.
	 */
	if (fpf->par_len != 0) {
		fpf->par_data = ((unsigned char *) &fpf->par_data) +
			sizeof (fpf->par_data);
#ifdef FP_DEBUG
		pad_res =
#endif
		fp_padfix (hash_arr, ha_len, fpf->par_data, fpf->par_len);
#ifdef FP_DEBUG
		if (pad_res == 0) {
			be_printf ("valid fingerprint\n");
		} else {
			be_printf ("invalid fingerprint\n");
		}
#endif
	}

	/* generate final 160 bit sha1 hash out of (possibly corrected) host
	 * characteristics
	 */
	SHA1HashLen (hash_arr, ha_len, key);

	return;
}


#endif


