# Makefile for ecca_lib.


T=ecca_lib

build:	$(T).so

OPENSSL_INCLUDE=/usr/include/openssl
#OPENSSL_LIB=$(OPENSSL_BASE)/lib
LUA_INCLUDE=/usr/include/lua5.1

LUA_LIBDIR=$(DESTDIR)/usr/lib/lua/5.1

# OS dependent
LIB_OPTION= -shared

LIBNAME= $T.so.$V

# Compilation directives
WARN= -O2 -Wall -fPIC -W -Waggregate-return -Wcast-align -Wmissing-prototypes -Wnested-externs -Wshadow -Wwrite-strings -pedantic

INCS=-I$(LUA_INCLUDE) -I$(OPENSSL_INCLUDE)
CFLAGS=$(WARN) $(INCS) 
LDFLAGS=$(WARN) 


OBJS=ecca_lib.o

.c.o:
	$(CC) $(INCS) -c -o $@ $?

all: $T.so

$T.so: $(OBJS)
	$(CC) $(LDFLAGS) $(LIB_OPTION) -o $T.so $(OBJS) -L$(OPENSSL_LIB) -lcrypto -lssl -ldl

install: all
	mkdir -p $(LUA_LIBDIR)
	cp $T.so $(LUA_LIBDIR)

clean:
	rm -f $T.so $(OBJS)


test:	$T.so
	lua 01-ecca_lib.t

