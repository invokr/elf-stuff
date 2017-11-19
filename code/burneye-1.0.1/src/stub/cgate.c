
#include "include/int80.h"
#include "include/unistd.h"
#include "helper.h"


typedef struct {
	unsigned long int	sav0,
				sav4;	/* first 8 saved bytes of function */
	unsigned long int	ra_sav;	/* saved return address */
	unsigned char *		ar_beg;	/* begin address of encrypted area */
	unsigned long int	ar_len;	/* length of function */
	void *			keyptr;	/* key structure pointer */
} callgate;


callgate * cg_find (unsigned long int addr);

void
cg_decrypt (callgate *cg)
{
#ifdef VDEBUG
	be_printf ("cg_decrypt (0x%08lx, 0x%08lx, %lu)\n", cg->keyptr, cg->ar_beg, cg->ar_len);
#endif
}



callgate sample = {
	0x01234567, 0x89abcdef,
	0x00000000,
	(void *) 0x40404040, 0x00001000,
	(void *) 0x80808080,
};


callgate *
cg_find (unsigned long int addr)
{
	return (&sample);
}

