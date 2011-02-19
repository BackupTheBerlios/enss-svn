enginesdir = $(libdir)/engines

engines_LTLIBRARIES = libe_nss.la

libe_nss_la_SOURCES = e_nss.c
EXTRA_libe_nss_la_SOURCES = \
	e_nss_int.h e_nss_cmd.c e_nss_ui.c e_nss_key.c \
	e_nss_rsa.c e_nss_dsa.c \
	e_nss_store.c e_nss_err.c

libe_nss_la_LIBADD = -lcrypto -lnss3 -lnspr4

libe_nss_la_LDFLAGS = -module -no-undefined -avoid-version

libe_nss_la_DEPENDENCIES = $(EXTRA_libe_nss_la_SOURCES)
