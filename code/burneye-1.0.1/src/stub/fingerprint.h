
#ifndef	FINGERPRINT_H
#define	FINGERPRINT_H


#define	N_TEST		7	/* number of overall available tests */
#define	N_SUBHASH	18	/* size in bytes of subhash */

/* yes, i wish bitfields would support pointer-wise addressing, too,
 * so shut up */
#define	FP_SYSBASE		0x00000001
#define	FP_SYSINSTALL		0x00000002
#define	FP_PROCPCI		0x00000004
#define	FP_PROCCPU		0x00000008
#define	FP_PROCMEM		0x00000010
#define	FP_PROCROUTE		0x00000020
#define	FP_PROCPARTITIONS	0x00000040

#define	FP_TEMPLATE	(FP_SYSBASE | \
	FP_PROCPCI | FP_PROCCPU | \
	FP_PROCROUTE)

typedef struct {
	unsigned char *		hash_arr;
	unsigned long int	tests;
} fp_s;


typedef struct {
	/* only used when SEALNOW is set */
	unsigned long int	stubhdr_flags_ofs;
	unsigned long int	sealhdr_ofs;	/* this headers offset */

	unsigned long int	payload_ofs;
	unsigned long int	payload_len;

	unsigned long int	be_layer0_filestart;
	unsigned long int	be_layer0_size;
	unsigned long int	be_layer0_cont;

	/* real fingerprint data */
	fp_s			fp;
	unsigned char		fp_xor[20];	/* xor hash */
	unsigned char		fp_check[4];	/* check hash */
	unsigned long int	par_len;	/* parity length */

	/* must be last defined element in structure */
	unsigned char *		par_data;	/* parity data */
	/* par_arr here */
} fp_fin;


#ifndef IN_STUB
/* fp_tenable
 *
 * lookup symbolic test `arg' and enable it in `fp'
 */

void
fp_tenable (fp_s *fp, char *arg);


/* fp_tdisable
 *
 * lookup symbolic test `arg' and disable it in `fp'
 */

void
fp_tdisable (fp_s *fp, char *arg);


/* fp_tlist
 *
 * list available fingerprint tests, defaults are printed ('tests')
 */

void
fp_tlist (unsigned long int tests);


/* fp_counttests
 *
 * count the number of tests used in the fingerprint described by `fp'
 *
 * return the number of tests
 */

int
fp_counttests (fp_s *fp);


/* fp_tlookup
 *
 * convert symbolic test `arg' to a flag value used in fingerprint structures
 *
 * return flag value
 */

unsigned long int
fp_tlookup (char *arg);
#endif


/* fp_get
 *
 * retrieve some host fingerprint into the fingerprint structure pointed to by
 * `fs'. the individual tests are done as specified by the `fs->tests' field.
 *
 * return number of bytes stored into `fs->hash_arr'
 */

unsigned int
fp_get (fp_s *fs);


/* fp_padgen
 *
 * generate a reed solomon rescue pad at `pad', which is `pad_len' bytes long
 * (does not have to be the exact size, but should be large enough), which can
 * recover up to `data_recover' bytes from `data_len' bytes at `data'.
 *
 * return the number of bytes of the pad
 */

unsigned long int
fp_padgen (unsigned char *data, unsigned int data_len, unsigned char *pad,
	unsigned int pad_len, unsigned int data_recover);


/* fp_padfix
 *
 * use the supplied byte based pad `pad', which is `pad_len' bytes long, to
 * correct as much errors as possible in data block `data', which is
 * `data_len' bytes long.
 *
 * return 0 on success
 * return 1 on failure
 */

int
fp_padfix (unsigned char *data, unsigned int data_len,
	unsigned char *pad, unsigned int pad_len);


#ifdef IN_STUB

/* fp_process
 *
 * called to process a fingerprint from within the stub
 */

void
fp_process (fp_fin *fpf, unsigned char *key);

#endif

#endif


