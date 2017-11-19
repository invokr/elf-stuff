

static int quicksort_verbose = 1;

void
qprint (void)
{
	printf ("calling quicksort\n");
}


void
quicksort (unsigned char *a, int m, int n)
{
	int	i, j, v, x;

	if (n <= m)
		return;

	i = m - 1;
	j = n;
	v = a[n];
	while (1) {
		do
			i = i + 1;
		while (a[i] < v);
		do
			j = j - 1;
		while (a[j] > v);

		if (i >= j)
			break;
		x = a[i];
		a[i] = a[j];
		a[j] = x;
	}
	x = a[i];
	a[i] = a[n];
	a[n] = x;

	qprint ();

	quicksort (a, m, j);
	quicksort (a, i + 1, n);
}

void * quicksort_fptr = (void *) quicksort;

