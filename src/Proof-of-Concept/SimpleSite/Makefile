# Makefile to configure SimpleSite


## Create a simple self signed certificate for the simple site.
## For testing, that's ok.
## For production, you would want to use a longer key and publish the certificate with DNSSEC and DANE

## This uses the standard openssl.cnf from your operating system
DIR=demoCA
KEY=$(DIR)/server-key.pem
CERT=$(DIR)/server-cert.pem

##  File to test if the localCA is configured correctly.
CHAINED = ../localCA/subCA/chained.pem

setup: .dir  $(KEY)  $(CERT) $(CHAINED)
	@echo done

.dir:
	@echo creating root CA
	mkdir -p $(DIR)/certs  $(DIR)/crl  $(DIR)/newcerts  $(DIR)/private
	touch $(DIR)/index.txt
	echo '01' > $(DIR)/crlnumber
	touch .dir

$(KEY): .dir
	openssl genrsa -out $(KEY) 1024

$(CERT): $(KEY)
	openssl req -new -key $(KEY) -out simple-req.csr -subj /C=NL/ST=ZH/L=Rott/O=DemoOrg/OU=DemoSigner/CN=localhost
	openssl ca -create_serial -out $(CERT) -days 30 -keyfile $(KEY) -selfsign -extensions usr_cert -batch -infiles simple-req.csr
	-rm simple-req.csr

clean: stop
	-rm -r $(DIR) .dir temp 

######################################
# Nginx control
######################################

NGINX=/Users/guido/eccentric-authentication/bin/nginx/sbin/nginx
NGXPID=temp/nginx.pid
start:
	mkdir -p temp/logs
	test -f $(NGXPID) || $(NGINX) -p `pwd`/temp/ -c ../nginx.conf

reload:
	$(NGINX) -p `pwd`/temp/ -c ../nginx.conf -s reload

stop:
	-test -f $(NGXPID) && kill `cat $(NGXPID)`


######################################
# localCA chained certificate
######################################

$(CHAINED):
	$(MAKE) -C ../localCA -f Makefile setup start


######################################
# testrun
######################################

testrun: $(CHAINED) setup start
	$(MAKE) -C test -f Makefile test