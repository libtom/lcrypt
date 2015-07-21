WHICH=\which
RM=\rm
CP=\cp

LUACPATH ?= /usr/lib/lua/5.1
INCDIR   ?= -I/usr/include/lua5.1
LIBDIR   ?= -L/usr/lib

CMOD = lcrypt.so
OBJS = lcrypt.o

CFLAGS += -include stddef.h -O3 -g -Wall -fPIC -DLITTLE_ENDIAN -DLTM_DESC -DLTC_SOURCE -DUSE_LTM
CFLAGS += -I/usr/local/include -I/usr/include $(INCDIR) -D_FILE_OFFSET_BITS=64
LDFLAGS += -L/usr/local/lib -L/usr/lib -L/usr/lib/x86_64-linux-gnu $(LIBDIR) -lm -lz -lutil -ltomcrypt -ltommath

.PHONY: all release clean

all: $(CMOD)

install: $(CMOD)
	$(if $(shell $(WHICH) ls), ls -lh $<)
	$(if $(shell $(WHICH) strip), strip $<)
	$(if $(shell $(WHICH) upx), upx --best $<)
	$(CP) $(CMOD) $(LUACPATH)

uninstall:
	$(RM) $(LUACPATH)/$(CMOD)

release: compress clean_obj

lcrypt.so: $(OBJS)
	$(CC) -o $@ $^ $(CFLAGS) -shared $(LDFLAGS)

lcrypt.o: lcrypt.c lcrypt_ciphers.c lcrypt_hashes.c lcrypt_math.c lcrypt_bits.c
	$(CC) -c lcrypt.c -o $@ $(CFLAGS)

clean_obj:
	$(RM) -f $(OBJS)

clean: clean_obj
	$(RM) -f $(CMOD)
