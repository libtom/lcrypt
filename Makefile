ifndef TOMCRYPT
  TOMCRYPT = /usr/include/tomcrypt/
endif

ifndef TOMMATH
  TOMMATH = /usr/include/tommath/
endif

ifndef LUA
  LUA = /usr/include/
endif

ifndef TARGET
  TARGET = .
endif

CFLAGS += -include stddef.h -O3 -g -Wall -fPIC -DLITTLE_ENDIAN -DLTM_DESC -DLTC_SOURCE -DUSE_LTM
CFLAGS += -I$(TOMCRYPT) -I$(TOMCRYPT)/src/headers -I$(TOMMATH) -I$(LUA) -I$(LUA)/src -D_FILE_OFFSET_BITS=64
LDFLAGS += -L$(TARGET)/lib -lm -lz -lutil -ltomcrypt -ltommath


CLEAN = lcrypt.o
ifneq ($(wildcard *.c),)
  CLEAN += lcrypt.so
endif

all: lcrypt.so

ifneq ($(wildcard *.c),)

lcrypt.so: lcrypt.o
	$(CC) $(CFLAGS) -shared $(LDFLAGS) lcrypt.o -o $@

lcrypt.o: lcrypt.c lcrypt_ciphers.c lcrypt_hashes.c lcrypt_math.c lcrypt_bits.c
	$(CC) $(CFLAGS) -c lcrypt.c -o $@

endif

clean:
	rm -f $(CLEAN)
