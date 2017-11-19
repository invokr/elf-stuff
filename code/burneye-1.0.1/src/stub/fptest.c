
#include <stdio.h>
#include "fingerprint.h"

int
main (int argc, char *argv[])
{
	fp_s			fp;

	unsigned int		ha_len;
	unsigned char		ha[N_TEST * 18];

	int			pad_res;
	unsigned long int	pad_len;
	unsigned char		pad[256];


	fp.tests = FP_SYSBASE | FP_PROCPCI | FP_PROCMEM;
	fp.hash_arr = ha;
	ha_len = fp_get (&fp);

	pad_len = fp_padgen (ha, ha_len, pad, sizeof (pad), 1 * 18);

	pad_res = fp_padfix (ha, ha_len, pad, pad_len);
}


