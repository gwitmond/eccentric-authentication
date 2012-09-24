# Makefile for the Eccentric Authentication system

## choose your compiler
#CC=gcc
CC=clang


build test clean:
	$(MAKE) -C src $@

install:
	$(MAKE) -C src install

#	cp conf/nginx.conf                  $(DESTDIR)/etc/ecca
#	cp conf/openssl-rootca.cnf.example  $(DESTDIR)/etc/ecca/CA/rootCA/
#	cp conf/openssl-subca.cnf.example   $(DESTDIR)/etc/ecca/CA/subCA/
#	cp -r web scripts                   $(DESTDIR)/usr/share/ecca/

.PHONY: build test clean

