AC_PREREQ([2.68])
m4_define([E_NSS_VERSION], [m4_translit(m4_esyscmd_s(awk '$ 2 == "NSS_ENG_VERSION" {print $ 3;}' engines/e_nss_int.h),")])

AC_INIT([e_nss], [E_NSS_VERSION])

AC_CONFIG_SRCDIR([engines/e_nss.c])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

AC_CANONICAL_HOST

LT_INIT([shared disable-static win32-dll])
LT_LANG([Windows Resource])

AC_PROG_CC

AC_CONFIG_FILES([Makefile engines/Makefile])
AC_OUTPUT
