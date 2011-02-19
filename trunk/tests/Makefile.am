EXTRA_DIST = $(TESTS) $(p12rsafile) $(p12dsafile) \
 openssl.cnf keypassfile p12passfile nsspassfile

p12rsafile = $(srcdir)/testid_rsa-dsa.p12
p12dsafile = $(srcdir)/testid_dsa-dsa.p12

p12passfile = $(srcdir)/p12passfile
dbpassfile = $(srcdir)/nsspassfile

OPENSSL = @OPENSSL@
p12pass = file:$(srcdir)/p12passfile
keypass = file:$(srcdir)/keypassfile
engine_name = e_nss
engine_in = -engine $(engine_name) -inform ENGINE
engine_key = -engine $(engine_name) -keyform ENGINE


CERTUTIL = @CERTUTIL@
PK12UTIL = @PK12UTIL@
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
print-rsa.test \
print-dsa.test \
list.test


if ENABLE_TESTS
$(TESTS): client-certificate.pem client-public.pem nssdb
endif


client-certificate.pem: $(p12rsafile)
	$(OPENSSL) pkcs12 -clcerts -in $(p12rsafile) -nokeys \
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

client-private.pem: $(p12rsafile)
	$(OPENSSL) pkcs12 -clcerts -in $(p12rsafile) -nocerts \
	  -passin $(p12pass) -passout $(keypass) \
	  > $@.tmp || rm $@.tmp
	@test -f $@.tmp && mv $@.tmp $@


nssdb: $(certdir)/cert8.db

$(certdir)/cert8.db: $(p12rsafile) $(p12dsafile)
	rm -f $(certdir)/*.db
	@test -d $(certdir) || mkdir $(certdir)
	$(CERTUTIL) -N -d $(certdir) -f $(dbpassfile)
	$(PK12UTIL) -i $(p12rsafile) -d $(certdir) -k $(dbpassfile) -w $(p12passfile)
	$(PK12UTIL) -i $(p12dsafile) -d $(certdir) -k $(dbpassfile) -w $(p12passfile)
	$(CERTUTIL) -L -d $(certdir)


clean-local:
	-rm -f client-*.pem *.tmp* *.out*
	-rm -f $(certdir)/*.db
	-rmdir $(certdir)
