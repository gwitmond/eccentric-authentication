# Makefile for the Eccentric Authentication system

## choose your compiler
#CC=gcc
CC=clang

# build must be first

build test clean:
	$(MAKE) -C src $@

install:
	$(MAKE) -C src install
	mkdir -p $(DESTDIR)/etc/ecca
	mkdir -p $(DESTDIR)/usr/share/ecca/
	cp conf/nginx.conf  $(DESTDIR)/etc/ecca
	cp -r web scripts $(DESTDIR)/usr/share/ecca/

.PHONY: build test clean