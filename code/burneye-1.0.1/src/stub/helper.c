/* helper functions
 */

#include <stdarg.h>
#include "include/int80.h"
#include "include/unistd.h"
#include "helper.h"


void
memset (void *dst, unsigned char c, unsigned int len)
{
	unsigned char *	p = (unsigned char *) dst;

	while (len--)
		*p++ = c;
}


int
memcmp (void *dst, void *src, unsigned int len)
{
	unsigned char *	d = (unsigned char *) dst;
	unsigned char *	s = (unsigned char *) src;

	while (len-- > 0) {
		if (*d++ != *s++)
			return (1);
	}

	return (0);
}


void
memcpy (void *dst, void *src, unsigned int len)
{
	unsigned char *	d = (unsigned char *) dst;
	unsigned char * s = (unsigned char *) src;

	while (len--)
		*d++ = *s++;
}


int
strlen (unsigned char *str)
{
	int	n = 0;

	while (*str++)
		n++;

	return (n);
}



#ifdef VDEBUG
void
be_printf (char *str, ...)
{
	int	len;
	va_list	vl;
	char	buf[1024];

	va_start (vl, str);
	len = vsnprintf (buf, sizeof (buf), str, vl);
	va_end (vl);
	buf[sizeof (buf) - 1] = '\0';

	write (1, buf, len);

	return;
}
#endif


/* based on the dietlibc version, which was ripped elsewhere ;) */
void
getpass (unsigned char *buf, unsigned int buf_len)
{
	int		tty_fd;
	unsigned int	buf_just,
			buf_read = 0;
	termios		t_backup,
			t_noecho;


	tty_fd = open ("/dev/tty", O_RDWR, 0);
	if (tty_fd < 0)
		_exit (73);

	/* set terminal to non-echo'ing mode */
	if (ioctl (tty_fd, TCGETS, (unsigned long int) &t_backup) != 0)
		_exit (73);

	memcpy (&t_noecho, &t_backup, sizeof (t_backup));
	t_noecho.c_lflag &= ~(ECHO | ISIG);
	if (ioctl (tty_fd, TCSETSF, (unsigned long int) &t_noecho) != 0)
		_exit (73);

	write (tty_fd, "password: ", 10);

	do {
		buf_just = read (tty_fd, buf + buf_read, buf_len - buf_read);
		if (buf_just < 0)
			_exit (73);

		buf_read += buf_just;
	} while (buf_read < buf_len && buf[buf_read - 1] != '\n');

	buf[buf_read > 0 ? (buf_read - 1) : 0] = '\0';
	buf[buf_len - 1] = '\0';
	write (tty_fd, "\n", 1);

	if (ioctl (tty_fd, TCSETSF, (unsigned long int) &t_backup) != 0)
		_exit (73);
	close (tty_fd);

	return;
}


void
write_tty (unsigned char *buf, unsigned int buf_len)
{
	int	tty_fd;


	tty_fd = open ("/dev/tty", O_RDWR, 0);
	if (tty_fd < 0)
		return;

	write (tty_fd, buf, buf_len);
	close (tty_fd);
}


