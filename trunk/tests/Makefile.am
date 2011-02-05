EXTRA_DIST = $(TESTS) \
 openssl.cnf keypassfile p12passfile nsspassfile

p12file = $(srcdir)/testid_rsa-dsa.p12

p12passfile = $(srcdir)/p12passfile
dbpassfile = $(srcdir)/nsspassfile

OPENSSL = openssl
p12pass = p12passfile
keypass = file:$(srcdir)/keypassfile
engine_name = e_nss
engine_in = -engine $(engine_name) -inform ENGINE
engine_key = -engine $(engine_name) -keyform ENGINE


nssroot = /work/OpenSSH/portable/.tests/ssh-nss/nss/3.12.7/nss-3.12.7/mozilla/dist/Linux2.6_x86_glibc_PTH_DBG.OBJ
CERTUTIL = $(nssroot)/bin/certutil
PK12UTIL = $(nssroot)/bin/pk12util
certdir = nssdb


TESTS_ENVIRONMENT = \
SHELL="$(SHELL)" CONFIG_SHELL="$(SHELL)" \
OPENSSL="$(OPENSSL)" \
OPENSSL_CONF="$(srcdir)"/openssl.cnf \
OPENSSL_ENGINES=../engines/.libs \
CONFIG_DIR=$(certdir) \
engine_name=$(engine_name)


TESTS = \
echo.test \
engine.test \
print.test \
list.test


$(TESTS): client-certificate.pem client-public.pem nssdb


client-certificate.pem: $(p12file)
	$(OPENSSL) pkcs12 -clcerts -in $(p12file) -nokeys \
	  -passin $(p12pass) > $@.tmp || rm $@.tmp
	test -f $@.tmp && \
	$(OPENSSL) x509 -in $@.tmp -text -nameopt RFC2253 \
	  > $@.tmp1 || rm $@.tmp1
	@rm -f $@.tmp
	@test -f $@.tmp1 && mv $@.tmp1 $@

client-public.pem: client-private.pem
	$(OPENSSL) rsa -in client-private.pem -pubout \
	  -passin $(keypass) \
	  > $@.tmp || rm $@.tmp
	@test -f $@.tmp && mv $@.tmp $@

client-private.pem: $(p12file)
	$(OPENSSL) pkcs12 -clcerts -in $(p12file) -nocerts \
	  -passin $(p12pass) -passout $(keypass) \
	  > $@.tmp || rm $@.tmp
	@test -f $@.tmp && mv $@.tmp $@


nssdb: $(certdir)/cert8.db

$(certdir)/cert8.db: $(p12file)
	rm -f $(certdir)/*.db
	@test -d $(certdir) || mkdir $(certdir)
	$(CERTUTIL) -N -d $(certdir) -f $(dbpassfile)
	$(PK12UTIL) -i $(p12file) -d $(certdir) -k $(dbpassfile) -w $(p12passfile)
	$(CERTUTIL) -L -d $(certdir)


clean-local:
	-rm -f client-*.pem *.tmp* *.out*
	-rm -f $(certdir)/*.db
	-rmdir $(certdir)
