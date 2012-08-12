## Create a simple self signed certificate for the localCA webserver.
## For testing, that's ok.
## For production, you would want to use a longer key and publish the certificate with DNSSEC and DANE

## This uses the standard openssl.cnf from your operating system
DIR=demoCA
KEY=server-key.pem
CERT=server-cert.pem

setup: .dir  $(KEY)  $(CERT)
	@echo done

.dir:
	@echo creating demoCA
	mkdir -p $(DIR)
	mkdir -p $(DIR)/certs  $(DIR)/crl  $(DIR)/newcerts  $(DIR)/private
	touch $(DIR)/index.txt
	echo '01' > $(DIR)/crlnumber
	touch .dir

$(KEY): .dir
	openssl genrsa -out $(KEY) 1024

$(CERT): $(KEY)
	openssl req -new -key $(KEY) -out simple-req.csr -subj /C=NL/ST=ZH/L=Rott/O=DemoOrg/OU=DemoCA/CN=localhost
	openssl ca -create_serial -out $(CERT) -days 30 -keyfile $(KEY) -selfsign -extensions usr_cert -batch -infiles simple-req.csr
	-rm simple-req.csr

clean: 
	-rm -r $(DIR) $(KEY) $(CERT) .dir temp 

######################################
# Nginx and MemcacheDB control
######################################

NGINX=/Users/guido/eccentric-authentication/bin/nginx/sbin/nginx

start:
	mkdir -p temp/logs
	memcachedb -d -l 127.0.0.1 -H `pwd`/temp -f data.db -P `pwd`/temp/memcachedb.pid
	$(NGINX) -p `pwd`/temp/ -c ../nginx.conf

reload:
	$(NGINX) -p `pwd`/temp/ -c ../nginx.conf -s reload

stop:
	$(NGINX) -p `pwd`/temp/ -c ../nginx.conf -s stop
	kill `cat temp/memcachedb.pid`
	@-rm temp/memcachedb.pid
