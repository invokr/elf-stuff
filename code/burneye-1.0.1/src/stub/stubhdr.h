/* burneye - stub appended header
 *
 * -scut
 *
 * this is appended to the stub binary. see stub.lds, stub.c and wrap.c
 * for further description
 */

#ifndef	BURNEYE_STUBHDR_H
#define	BURNEYE_STUBHDR_H

#define	BE_FLAG_PASSWORD	0x0001		/* password protected */
#define	BE_FLAG_PASSWORD_CHECK	0x0002		/* check if it was valid */
#define	BE_FLAG_BANNER		0x0004		/* show banner */
#define	BE_FLAG_BANNER_TTY	0x0008		/* .. on tty */
#define	BE_FLAG_FINGERPRINT	0x0010		/* fingeprinted */
#define	BE_FLAG_FINGERPRINT_CHK	0x0020		/* check success */
#define	BE_FLAG_UNLINK		0x0040		/* unlink on env */
#define	BE_FLAG_SEALNOW		0x0080		/* to-be-sealed binary */
#define	BE_FLAG_SEALED		0x0100		/* just a tag-flag */
#define	BE_FLAG_TAGGED		0x0200		/* is binary tagged ? */


typedef struct {
	unsigned char		ul_env[16];	/* variable */
} stubhdr_unlink;


typedef struct {
	unsigned char		tag_env[20];
	unsigned char		tag_value[64];
} stubhdr_tag;


typedef struct {
	unsigned long int	banner_len;	/* length of banner[] bytes */

	/* variable sized banner here */
/*	unsigned char		banner[]; */
} stubhdr_banner;


typedef struct {
	unsigned char		pw_check[4];	/* first 4 bytes of hash */
	unsigned char		pw_xor[20];	/* dynamic xor hash */
	unsigned char		pw_env[16];	/* environment variable */
} stubhdr_pass;


typedef struct {
	unsigned long int	stubhdr_size;	/* length of this header */
	unsigned long int	payload_len;	/* length of payload */
	unsigned long int	flags;		/* generic flags */

	/*** DYNAMIC/OPTIONAL elements come here */

#if 0	/* appended if BE_FLAG_BANNER */
	stubhdr_banner		banner;
#endif

#if 0	/* appended if BE_FLAG_PASSWORD */
	stubhdr_pass		spass;
#endif

	/* ... variable lenght content from here on ... */
} stubhdr;

#define	MAX_BANNER	1024
#define	MAX_FINGERPRINT	4096

#define	SHDR_MAXSIZE	(sizeof (stubhdr) + \
	sizeof (stubhdr_unlink) + sizeof (stubhdr_tag) + \
	sizeof (stubhdr_banner) + MAX_BANNER + \
	sizeof (stubhdr_pass) + MAX_FINGERPRINT)

#endif


