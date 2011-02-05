AC_PREREQ([2.68])
m4_define([E_NSS_VERSION], [m4_translit(m4_esyscmd_s(awk '$ 2 == "NSS_ENG_VERSION" {print $ 3;}' engines/e_nss_int.h),")])

AC_INIT([e_nss], [E_NSS_VERSION])

AC_CONFIG_SRCDIR([engines/e_nss.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.11 foreign dist-bzip2
                  color-tests -Wall -Werror])

AC_CANONICAL_HOST

LT_INIT([shared disable-static win32-dll])
LT_LANG([Windows Resource])


AC_PROG_CC
AC_C_INLINE


AC_ARG_ENABLE([tests],
  [AS_HELP_STRING([--enable-tests],
     [enable experimental regression tests @<:@default=no@:>@])],
  [],
  [enable_tests=no])

AC_CHECK_PROGS([OPENSSL], [openssl], [false])
AC_CHECK_PROGS([CERTUTIL], [certutil], [false])
AC_CHECK_PROGS([PK12UTIL], [pk12util], [false])

AM_CONDITIONAL([ENABLE_TESTS], [test "$enable_tests" = yes])


AC_CONFIG_FILES([Makefile engines/Makefile])
AC_CONFIG_FILES([tests/Makefile])

AC_OUTPUT
