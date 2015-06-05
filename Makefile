WHICH=\which
RM=\rm
LUA_INC=/usr/include

#/usr/include
#/usr/local/include
#/

ifndef LUA
  LUA = /usr/include/
endif

ifndef TARGET
  TARGET = .
endif

CFLAGS += -include stddef.h -O3 -g -Wall -fPIC -DLITTLE_ENDIAN -DLTM_DESC -DLTC_SOURCE -DUSE_LTM
CFLAGS += -I/usr/local/include -I/usr/include -I$(LUA)src -D_FILE_OFFSET_BITS=64
LDFLAGS += -L/usr/local/lib -L/usr/lib -L/usr/lib/x86_64-linux-gnu -lm -lz -lutil -ltomcrypt -ltommath

.PHONY: all release clean

all: lcrypt.so

release: compress clean_obj

compress: lcrypt.so
	$(if $(shell $(WHICH) ls), ls -lh $<)
	$(if $(shell $(WHICH) strip), strip $<)
	$(if $(shell $(WHICH) upx), upx --best $<)

lcrypt.so: lcrypt.o
	$(CC) -o $@ $^ $(CFLAGS) -shared $(LDFLAGS)

lcrypt.o: lcrypt.c lcrypt_ciphers.c lcrypt_hashes.c lcrypt_math.c lcrypt_bits.c
	$(CC) -c lcrypt.c -o $@ $(CFLAGS)

clean_obj:
	$(RM) -f lcrypt.o

clean: clean_obj
	$(RM) -f lcrypt.so
