## Create a simple self signed certificate for the localCA webserver.
## For testing, that's ok.
## For production, you would want to use a longer key and publish the certificate with DNSSEC and DANE

## This uses the standard openssl.cnf from your operating system, use your own for production.
DEMO=demoCA

## configure your nginx/webserver to use these for the server certificates
KEY=$(DEMO)/server-key.pem
CERT=$(DEMO)/server-cert.pem

setup: .demo  $(KEY)  $(CERT)
	@echo done setup demoCA

.demo:
	@echo creating demoCA
	mkdir -p $(DEMO)
	mkdir -p $(DEMO)/certs  $(DEMO)/crl  $(DEMO)/newcerts  $(DEMOE)/private
	touch $(DEMO)/index.txt
	echo '01' > $(DEMO)/crlnumber
	touch .demo

$(KEY): .demo
	openssl genrsa -out $(KEY) 1024

$(CERT): $(KEY)
	openssl req -new -key $(KEY) -out simple-req.csr -subj /C=NL/ST=ZH/L=Rott/O=DemoOrg/OU=DemoCA/CN=localhost
	openssl ca -create_serial -out $(CERT) -days 30 -keyfile $(KEY) -selfsign -extensions usr_cert -batch -infiles simple-req.csr
	-rm simple-req.csr

clean:
	-rm -r $(KEY) $(CERT) $(DEMO) .demo temp 

######################################
# Nginx and MemcacheDB control
######################################

NGINX=/Users/guido/eccentric-authentication/bin/nginx/sbin/nginx
MEMCPID = temp/memcachedb.pid
NGXPID = temp/logs/nginx.pid

start:	$(KEY)  $(CERT) 
	mkdir -p temp/logs
	memcachedb -d -l 127.0.0.1 -H `pwd`/temp -f data.db -P `pwd`/$(MEMCPID)
	$(NGINX) -p `pwd`/temp/ -c ../nginx.conf

reload:
	$(NGINX) -p `pwd`/temp/ -c ../nginx.conf -s reload

stop:
	-test -d temp && $(NGINX) -p `pwd`/temp/ -c ../nginx.conf -s stop
	-test -f $(MEMCPID) && kill `cat $(MEMCPID)`
	@-rm $(MEMCPID)

##############################
# test code
##############################

test:	
	@echo No tests for localCA/web at the moment