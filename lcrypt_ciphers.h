/**
 *
 * Copyright (c) 2011-2015 David Eder, InterTECH
 * Copyright (c) 2015 Simbiose
 *
 * License: https://www.gnu.org/licenses/lgpl-2.1.html LGPL version 2.1
 *
 */

#define LCRYPT_MODE_NONE  0
#define LCRYPT_MODE_ECB   1
#define LCRYPT_MODE_CBC   2
#define LCRYPT_MODE_CTR   3
#define LCRYPT_MODE_CFB   4
#define LCRYPT_MODE_OFB   5
#define LCRYPT_MODE_LRW   6
#define LCRYPT_MODE_F8    7

#define LCRYPT_MODE_MAX   7

typedef struct {
  int mode;
  int key_size;
  union {
    symmetric_ECB ecb;
    symmetric_CBC cbc;
    symmetric_CTR ctr;
    symmetric_CFB cfb;
    symmetric_OFB ofb;
    symmetric_LRW lrw;
    symmetric_F8  f8;
  } data;
} lcrypt_key_t;

