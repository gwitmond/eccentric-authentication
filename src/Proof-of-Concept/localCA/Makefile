# Makefile to create the nested localCA

## Root CA configs
ROOT=rootCA
CONFIG=$(ROOT)/openssl-rootca.cnf
## CAKEY and CACERT must match the values in CONFIG
CAKEY=$(ROOT)/private/cakey.pem
CACERT=$(ROOT)/cacert.pem

## Sub CA configs
SUB=subCA
SUBCONFIG=$(SUB)/openssl-subca.cnf
## SUBCAKEY and SUBCACERT must match the values in SUBCONFIG
SUBCAKEY=$(SUB)/private/subcakey.pem
SUBCACERT=$(SUB)/subcacert.pem

## Chained certificate
CHAINED=$(SUB)/chained.pem


## create the rootCA structure. 
setup: $(CACERT) $(SUBCACERT) $(CHAINED)
	@echo done

########################
# Root CA              #
########################

# create a self signed rootCA certificate
.root_dir:
	@echo creating root CA
	mkdir -p $(ROOT)
	mkdir -p $(ROOT)/certs  $(ROOT)/crl  $(ROOT)/newcerts  $(ROOT)/private
	touch $(ROOT)/index.txt
	echo '01' > $(ROOT)/crlnumber
	cp default/openssl-rootca.cnf  $(CONFIG)
	touch .root_dir

$(CAKEY): .root_dir
	@echo creating root private key: $(CAKEY)
	openssl genrsa -out $(CAKEY) 1024 
# increase to 4096 bits for production.

$(CACERT): $(CAKEY)
	@echo creating self signing request
	openssl req -config $(CONFIG) -new -key $(CAKEY) -out root-req.csr
	openssl ca  -config $(CONFIG) -create_serial -out $(CACERT) -days 3650 -keyfile $(CAKEY) -selfsign -extensions v3_ca -batch -infiles root-req.csr
	rm root-req.csr

clean-root:
	-rm -r $(ROOT) .root_dir



########################
# Sub CA               #
########################



# create a self signed rootCA certificate.
.sub_dir:
	@echo creating sub CA
	mkdir -p $(SUB)
	mkdir -p $(SUB)/certs  $(SUB)/crl  $(SUB)/newcerts  $(SUB)/private
	touch $(SUB)/index.txt
	cp default/openssl-subca.cnf  $(SUBCONFIG)
	touch .sub_dir

$(SUBCAKEY): .sub_dir
	@echo creating sub private key: $(SUBCAKEY)
	openssl genrsa -out $(SUBCAKEY) 1024 
# increase to 2048/3072 bits for production.

$(SUBCACERT): $(CACERT) $(SUBCAKEY)
	@echo creating signing request to get sub signed by root
	openssl req -config $(SUBCONFIG) -new -key $(SUBCAKEY) -out sub-req.csr
	openssl ca  -config $(CONFIG)  -out $(SUBCACERT) -days 30 -keyfile $(CAKEY) -extensions v3_ca -batch -infiles sub-req.csr
	rm sub-req.csr

clean-sub:
	-rm -r $(SUB) .sub_dir


#######################
# chained pem         #
#######################

$(CHAINED): $(SUBCACERT) $(CACERT)
	cat $(SUBCACERT) $(CACERT) > $(CHAINED)


#######################
# testrun                #
#######################

# test in this order.
# first test lua with the ecca_lib.so file
# second, test the webserver nginx/memcacheDB combination
# then test the whole system with register.lua/ecca_lib.so memcacheDB
testrun: setup
	$(MAKE) -C ecca_lib -f Makefile test
	$(MAKE) -C web      -f Makefile start test
	$(MAKE) -C test     -f Makefile test

clean: 
	$(MAKE) -C web      -f Makefile stop clean
	$(MAKE) -C ecca_lib -f Makefile clean
	$(MAKE) clean-sub clean-root