

void
glfsr_crypt (unsigned char *dst, unsigned char *src,
	unsigned int len, unsigned int key)
{
	int			n;
	unsigned long int	state = key,
				fillup;

	while (len--) {
		for (n = 0 ; n < 8 ; ++n) {
			fillup = 0;

			if (state & 0x1) {
				state >>= 1;
				fillup |= 0x80000000;
			} else {
				state >>= 1;
				state ^= 0xc0000057;
			}
			fillup >>= 1;
		}
		fillup >>= 24;
		fillup &= 0x000000ff;

		*dst++ = *src++ ^ fillup;
	}

	return;
}


