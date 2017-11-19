#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


dnl Process this file with autoconf to produce a configure script.
define([svnversion], esyscmd([sh -c "svnversion|tr -d '\n'"]))
AC_INIT([elfcrypt], [0.5.svnversion])
AC_CONFIG_SRCDIR([stub/elf.c])

dnl foreign is least strict
AM_INIT_AUTOMAKE([foreign])

AC_CANONICAL_HOST
AC_MSG_CHECKING([for supported operating system])
case "$host_os" in
linux*)                 AC_DEFINE([LINUX]) ;;
freebsd*)                 AC_DEFINE([FREEBSD]) ;;
*)                      AC_MSG_RESULT([NO!])
                        AC_MSG_ERROR([unsupported operating system: $host_os !!!]) ;;
esac
AC_MSG_RESULT($host_os)

AC_MSG_CHECKING([for supported architecture])
case "$host_cpu" in
i[[3456]]86|pentium)    AC_DEFINE([I386]) ;;
x86_64)			AC_DEFINE([X86_64]) ;;
ia64)			AC_DEFINE([IA64]) ;;
*)                      AC_MSG_RESULT([NO!])
                        AC_MSG_ERROR([unsupported architecture: $host_cpu !!!]) ;;
esac
AC_MSG_RESULT($host_cpu)


# Checks for programs.
AC_PROG_CC

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lm':
#AC_CHECK_LIB([m], [main])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_UINT8_T


AC_CONFIG_FILES([Makefile stub/Makefile wrapper/Makefile])
AC_OUTPUT
