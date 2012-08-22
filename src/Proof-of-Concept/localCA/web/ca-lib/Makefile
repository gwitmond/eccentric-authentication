# Makefile for ecca_lib.

T=ecca_lib

# configure openssl with: ./Configure darwin64-x86_64-cc -shared; make; make install
OPENSSL_BASE=/Users/guido/cc
OPENSSL_INCLUDE=$(OPENSSL_BASE)/include
OPENSSL_LIB=$(OPENSSL_BASE)/lib

LUA_BASE=/Users/guido/cc
LUA_INCLUDE=$(LUA_BASE)/include
#LUA_LIBDIR=$(LUA_BASE)/lib/lua/5.1

# OS dependent
#LIB_OPTION= -shared #for Linux
#for MacOS X
LIB_OPTION= -bundle -undefined dynamic_lookup 

LIBNAME= $T.so.$V

# Compilation directives
WARN= -O2 -Wall -fPIC -W -Waggregate-return -Wcast-align -Wmissing-prototypes -Wnested-externs -Wshadow -Wwrite-strings -pedantic
INCS=-I$(LUA_INCLUDE) -I$(OPENSSL_INCLUDE)
CFLAGS=$(WARN) $(INCS) 
LDFLAGS=$(WARN) 
#CC=gcc
CC=clang

OBJS=ecca_lib.o

.c.o:
	$(CC) $(INCS) -c -o $@ $?

all: $T.so

$T.so: $(OBJS)
	MACOSX_DEPLOYMENT_TARGET="10.3"; export MACOSX_DEPLOYMENT_TARGET; $(CC) $(LDFLAGS) $(LIB_OPTION) -o $T.so $(OBJS) -L$(OPENSSL_LIB) -lcrypto -lssl -ldl

install: all
	mkdir -p $(LUA_LIBDIR)
	cp $T.so $(LUA_LIBDIR)

clean:
	rm -f $T.so $(OBJS)


test:	all
	lua 01-ecca_lib.t

#lua -e "require 'ecca_lib'" -e 'ecca_lib.sign_csr()' < certificate-request.pem