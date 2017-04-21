#  -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([bLsched], [0.1.0], [fisaksen@baylibre.com])
AM_INIT_AUTOMAKE([foreign color-tests subdir-objects dist-xz])
AM_SILENT_RULES([yes])

AC_PREFIX_DEFAULT([/usr])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([errno.h \
	fcntl.h \
	getopt.h \
	limits.h \
	linux/connector.h \
	linux/cn_proc.h \
	linux/netlink.h \
	poll.h \
	sched.h \
	signal.h \
	stdarg.h \
	stddef.h \
	stdint.h \
	stdlib.h \
	string.h \
	sys/param.h \
	sys/socket.h \
	sys/time.h \
	unistd.h \
	], [ ], [AC_MSG_ERROR([required header missing])])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_PID_T
AC_C_RESTRICT
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

# Checks for functions
AC_CHECK_FUNCS([bind \
	gettimeofday \
	getopt \
	kill \
	memset \
	socket \
	strerror \
	strstr \
	sched_setaffinity \
	sched_getaffinity \
	], [ ], [AC_MSG_ERROR([required function missing])])

# Compile flags
AC_ARG_ENABLE([debug], AC_HELP_STRING([--enable-debug], [enable debugging [default=no]]), [
	CFLAGS+=" -g -O0"
])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
