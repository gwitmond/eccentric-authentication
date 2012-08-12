# Makefile to create the nested localCA

## Root CA configs
DIR=rootCA
CONFIG=$(DIR)/openssl-rootca.cnf
## CAKEY and CACERT must match the values in CONFIG
CAKEY=$(DIR)/private/cakey.pem
CACERT=$(DIR)/cacert.pem

## Sub CA configs
SUB=subCA
SUBCONFIG=$(SUB)/openssl-subca.cnf
## SUBCAKEY and SUBCACERT must match the values in SUBCONFIG
SUBCAKEY=$(SUB)/private/subcakey.pem
SUBCACERT=$(SUB)/subcacert.pem

## Chained certificate
CHAINED=$(DIR)/../chained.pem


## create the rootCA structure. 
setup: $(CACERT) $(SUBCACERT) $(CHAINED)
	@echo done

########################
# Root CA              #
########################

# create a self signed rootCA certificate
.root_dir:
	@echo creating root CA
	mkdir -p $(DIR)
	mkdir -p $(DIR)/certs  $(DIR)/crl  $(DIR)/newcerts  $(DIR)/private
	touch $(DIR)/index.txt
	echo '01' > $(DIR)/crlnumber
	cp default/openssl-rootca.cnf  $(CONFIG)
	touch .root_dir

$(CAKEY): .root_dir
	@echo creating root private key: $(CAKEY)
	openssl genrsa -out $(CAKEY) 1024 
# increate to 4096 bits for production.

$(CACERT): $(CAKEY)
	@echo creating self signing request
	openssl req -config $(CONFIG) -new -key $(CAKEY) -out root-req.csr
	openssl ca  -config $(CONFIG) -create_serial -out $(CACERT) -days 3650 -keyfile $(CAKEY) -selfsign -extensions v3_ca -batch -infiles root-req.csr
	rm root-req.csr

clean-root:
	-rm -r $(DIR) .root_dir



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
# increate to 2048/3072 bits for production.

$(SUBCACERT): $(CACERT) $(SUBCAKEY)
	@echo creating signing request to get sub signed by root
	openssl req -config $(SUBCONFIG) -new -key $(SUBCAKEY) -out sub-req.csr
	openssl ca  -config $(CONFIG)  -out $(SUBCACERT) -days 30 -keyfile $(CAKEY) -extensions v3_ca -batch -infiles sub-req.csr
	rm sub-req.csr

clean: clean-sub

clean-sub:
	-rm -r $(SUB) .sub_dir


#######################
# chained pem         #
#######################

$(CHAINED): $(SUBCACERT) $(CACERT)
	cat $(SUBCACERT) $(CACERT) > $(CHAINED)