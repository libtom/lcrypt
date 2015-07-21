/**
 *
 * Copyright (c) 2011-2015 David Eder, InterTECH
 * Copyright (c) 2015 Simbiose
 *
 * License: https://www.gnu.org/licenses/lgpl-2.1.html LGPL version 2.1
 *
 */

#include "lcrypt_ciphers.h"

static int lcrypt_max_ciphers = 0;

static int lcrypt_key (lua_State *L) {
  int cipher = -1, mode = LCRYPT_MODE_NONE;
  /* get cipher */
  if (lua_isnumber(L, 1) == 1) {
    cipher = luaL_checkint(L, 1);
  } else {
    cipher = find_cipher(luaL_checkstring(L, 1));
  }

  if (cipher < 0 || cipher > lcrypt_max_ciphers) RETURN_STRING_ERROR(L, "Unknown cipher");

  /* get mode */
  if(lua_isnumber(L, 2) == 1) {
    mode = luaL_checkint(L, 2);
  } else {
    const char *m = luaL_checkstring(L, 2);
    if (strcmp(m, "ecb") == 0)
      mode = LCRYPT_MODE_ECB;
    else if (strcmp(m, "cbc") == 0)
      mode = LCRYPT_MODE_CBC;
    else if (strcmp(m, "ctr") == 0)
      mode = LCRYPT_MODE_CTR;
    else if (strcmp(m, "cfb") == 0)
      mode = LCRYPT_MODE_CFB;
    else if (strcmp(m, "ofb") == 0)
      mode = LCRYPT_MODE_OFB;
    else if (strcmp(m, "lrw") == 0)
      mode = LCRYPT_MODE_LRW;
    else if (strcmp(m, "f8") == 0)
      mode = LCRYPT_MODE_F8;
  }

  if(mode <= 0 || mode > LCRYPT_MODE_MAX) RETURN_STRING_ERROR(L, "Unknown mode");

  {
    size_t key_length = 0, iv_length = 0, extra_length = 0;
    const unsigned char *key = (const unsigned char*)luaL_checklstring(L, 3, &key_length);
    const unsigned char *iv = (const unsigned char*)luaL_optlstring(L, 4, "", &iv_length);
    const unsigned char *extra = (const unsigned char*)luaL_optlstring(L, 5, "", &extra_length);

    int klen = key_length;
    (void)lcrypt_check(L, cipher_descriptor[cipher].keysize(&klen));
    key_length = klen;

    /* prepare result */
    lcrypt_key_t *k = lua_newuserdata(L, sizeof(lcrypt_key_t));
    memset(k, 0, sizeof(lcrypt_key_t));
    luaL_getmetatable(L, "LCRYPT_KEY");
    (void)lua_setmetatable(L, -2);
    k->key_size = klen;

    #define IV_CHECK(name)                                                          \
      if (iv_length != cipher_descriptor[cipher].block_length)                      \
        RETURN_STRING_ERROR(L, "IV wrong length");                                  \

    switch (mode) {
      case LCRYPT_MODE_ECB:
        (void) lcrypt_check(L, ecb_start(cipher, key, key_length, 0, &k->data.ecb)); break;
      case LCRYPT_MODE_CBC: {
        IV_CHECK(cbc);
        (void) lcrypt_check(L, cbc_start(cipher, iv, key, key_length, 0, &k->data.cbc));
      } break;
      case LCRYPT_MODE_CTR: {
        IV_CHECK(ctr);
        if (strcmp((char*)extra, "le") == 0)
          (void) lcrypt_check(
            L, ctr_start(cipher, iv, key, key_length, 0, CTR_COUNTER_LITTLE_ENDIAN, &k->data.ctr)
          );
        else if (strcmp((char*)extra, "be") == 0)
          (void) lcrypt_check(
            L, ctr_start(cipher, iv, key, key_length, 0, CTR_COUNTER_BIG_ENDIAN,    &k->data.ctr)
          );
        else {
          RETURN_STRING_ERROR(L, "Unknown endian");
        }
      } break;
      case LCRYPT_MODE_CFB: {
        IV_CHECK(cfb);
        (void)lcrypt_check(L, cfb_start(cipher, iv, key, key_length, 0, &k->data.cfb));
      } break;
      case LCRYPT_MODE_OFB: {
        IV_CHECK(ofb);
        (void)lcrypt_check(L, ofb_start(cipher, iv, key, key_length, 0, &k->data.ofb));
      } break;
      case LCRYPT_MODE_LRW: {
        IV_CHECK(lrw);
        if(extra_length != 16) RETURN_STRING_ERROR(L, "Tweak must be 16 characters long");
        (void)lcrypt_check(L, lrw_start(cipher, iv, key, key_length, extra, 0, &k->data.lrw));
      } break;
      case LCRYPT_MODE_F8: {
        IV_CHECK(f8);
        (void) lcrypt_check(
          L, f8_start(cipher, iv, key, key_length, extra, extra_length, 0, &k->data.f8)
        );
      } break;
    }
    k->mode = mode;
  }

  #undef IV_CHECK
  return 1;
}

static int lcrypt_key_encrypt (lua_State *L) {
  lcrypt_key_t *key = luaL_checkudata(L, 1, "LCRYPT_KEY");
  size_t in_length  = 0;
  const unsigned char *in = (const unsigned char *)luaL_checklstring(L, 2, &in_length);
  #define STD_CHECK(name)                                                               \
    if (in_length % cipher_descriptor[key->data.name.cipher].block_length != 0) {       \
      RETURN_STRING_ERROR(L, "Data length must be a multiple of block size");           \
    }
  #define STD_ENCRYPT(name)                                                             \
  {                                                                                     \
    unsigned char *out = lcrypt_malloc(L, in_length);                                   \
    int err = name ## _encrypt(in, out, in_length, &key->data.name);                    \
    if (err != CRYPT_OK) {                                                              \
      free(out);                                                                        \
      RETURN_CRYPT_ERROR(L, err);                                                       \
    }                                                                                   \
    lua_pushlstring(L, (char*)out, in_length);                                          \
    free(out);                                                                          \
    return 1;                                                                           \
  }

  switch (key->mode) {
    case LCRYPT_MODE_ECB: STD_CHECK(ecb); STD_ENCRYPT(ecb); break;
    case LCRYPT_MODE_CBC: STD_CHECK(cbc); STD_ENCRYPT(cbc); break;
    case LCRYPT_MODE_CTR:                 STD_ENCRYPT(ctr); break;
    case LCRYPT_MODE_CFB:                 STD_ENCRYPT(cfb); break;
    case LCRYPT_MODE_OFB:                 STD_ENCRYPT(ofb); break;
    case LCRYPT_MODE_LRW:                 STD_ENCRYPT(lrw); break;
    case LCRYPT_MODE_F8:                  STD_ENCRYPT(f8);  break;
  }
  #undef STD_CHECK
  #undef STD_ENCRYPT
  return 0;
}

static int lcrypt_key_decrypt (lua_State *L) {
  lcrypt_key_t *key = luaL_checkudata(L, 1, "LCRYPT_KEY");
  size_t in_length  = 0;
  const unsigned char *in = (const unsigned char *)luaL_checklstring(L, 2, &in_length);
  #define STD_CHECK(name)                                                               \
    if (in_length % cipher_descriptor[key->data.name.cipher].block_length != 0) {       \
      RETURN_STRING_ERROR(L, "Data length must be a multiple of block size");           \
    }
  #define STD_DECRYPT(name)                                                             \
  {                                                                                     \
    unsigned char *out = lcrypt_malloc(L, in_length);                                   \
    int err = name ## _decrypt(in, out, in_length, &key->data.name);                    \
    if (err != CRYPT_OK) {                                                              \
      free(out);                                                                        \
      RETURN_CRYPT_ERROR(L, err);                                                       \
    }                                                                                   \
    lua_pushlstring(L, (char*)out, in_length);                                          \
    free(out);                                                                          \
    return 1;                                                                           \
  }

  switch (key->mode) {
    case LCRYPT_MODE_ECB: STD_CHECK(ecb); STD_DECRYPT(ecb); break;
    case LCRYPT_MODE_CBC: STD_CHECK(cbc); STD_DECRYPT(cbc); break;
    case LCRYPT_MODE_CTR:                 STD_DECRYPT(ctr); break;
    case LCRYPT_MODE_CFB:                 STD_DECRYPT(cfb); break;
    case LCRYPT_MODE_OFB:                 STD_DECRYPT(ofb); break;
    case LCRYPT_MODE_LRW:                 STD_DECRYPT(lrw); break;
    case LCRYPT_MODE_F8:                  STD_DECRYPT(f8);  break;
  }

  #undef STD_CHECK
  #undef STD_DECRYPT
  return 0;
}

static int lcrypt_key_index (lua_State *L) {
  lcrypt_key_t *key = luaL_checkudata(L, 1, "LCRYPT_KEY");
  const char *index = luaL_checkstring(L, 2);
  if (strcmp(index, "encrypt") == 0)  { lua_pushcfunction(L, lcrypt_key_encrypt);       return 1; }
  if (strcmp(index, "decrypt") == 0)  { lua_pushcfunction(L, lcrypt_key_decrypt);       return 1; }
  if (strcmp(index, "key_size") == 0) { lua_pushinteger(L, (lua_Integer)key->key_size); return 1; }

  #define STD_INDEX(_name)                                                                         \
    if (strcmp(index, "mode") == 0) {                                                              \
      lua_pushstring(L, #_name);                                                                   \
      return 1;                                                                                    \
    }                                                                                              \
    if (strcmp(index, "block_size") == 0) {                                                        \
      lua_pushinteger(L, (lua_Integer)cipher_descriptor[key->data._name.cipher].block_length);     \
      return 1;                                                                                    \
    }                                                                                              \
    if (strcmp(index, "cipher") == 0) {                                                            \
      lua_pushstring(L, cipher_descriptor[key->data._name.cipher].name);                           \
      return 1;                                                                                    \
    }                                                                                              \

  #define IV_INDEX(name)                                                                           \
    if(strcmp(index, "iv") == 0) {                                                                 \
      unsigned char iv[MAXBLOCKSIZE];                                                              \
      unsigned long length = MAXBLOCKSIZE;                                                         \
      memset(iv, 0, sizeof(iv));                                                                   \
      (void)lcrypt_check(L, name ## _getiv(iv, &length, &key->data.name));                         \
      lua_pushlstring(L, (char*)iv, (size_t)length);                                               \
      return 1;                                                                                    \
    }                                                                                              \

  switch (key->mode) {
    case LCRYPT_MODE_ECB: STD_INDEX(ecb);                break;
    case LCRYPT_MODE_CBC: STD_INDEX(cbc); IV_INDEX(cbc); break;
    case LCRYPT_MODE_CTR: STD_INDEX(ctr); IV_INDEX(ctr); break;
    case LCRYPT_MODE_CFB: STD_INDEX(cfb); IV_INDEX(cfb); break;
    case LCRYPT_MODE_OFB: STD_INDEX(ofb); IV_INDEX(ofb); break;
    case LCRYPT_MODE_LRW: STD_INDEX(lrw); IV_INDEX(lrw); break;
    case LCRYPT_MODE_F8:  STD_INDEX(f8);  IV_INDEX(f8);  break;
  }

  #undef STD_INDEX
  #undef IV_INDEX
  return 0;
}

static int lcrypt_key_newindex (lua_State *L) {
  lcrypt_key_t *key = luaL_checkudata(L, 1, "LCRYPT_KEY");
  const char *index = luaL_checkstring(L, 2);
  size_t v_length = 0;
  const unsigned char *v = (const unsigned char *)luaL_checklstring(L, 3, &v_length);

  if (strcmp(index, "iv") == 0) {
    switch (key->mode) {
      case LCRYPT_MODE_CBC:
        (void) lcrypt_check(L, cbc_setiv(v, (unsigned long)v_length, &key->data.cbc)); break;
      case LCRYPT_MODE_CTR:
        (void) lcrypt_check(L, ctr_setiv(v, (unsigned long)v_length, &key->data.ctr)); break;
      case LCRYPT_MODE_CFB:
        (void) lcrypt_check(L, cfb_setiv(v, (unsigned long)v_length, &key->data.cfb)); break;
      case LCRYPT_MODE_OFB:
        (void) lcrypt_check(L, ofb_setiv(v, (unsigned long)v_length, &key->data.ofb)); break;
      case LCRYPT_MODE_LRW:
        (void) lcrypt_check(L, lrw_setiv(v, (unsigned long)v_length, &key->data.lrw)); break;
      case LCRYPT_MODE_F8:
        (void) lcrypt_check(L, f8_setiv(v,  (unsigned long)v_length, &key->data.f8));  break;
    }
  }

  return 0;
}

static int lcrypt_key_gc (lua_State *L) {
  lcrypt_key_t *key = luaL_checkudata(L, 1, "LCRYPT_KEY");
  switch (key->mode) {
    case LCRYPT_MODE_ECB: (void)lcrypt_check(L, ecb_done(&key->data.ecb)); break;
    case LCRYPT_MODE_CBC: (void)lcrypt_check(L, cbc_done(&key->data.cbc)); break;
    case LCRYPT_MODE_CTR: (void)lcrypt_check(L, ctr_done(&key->data.ctr)); break;
    case LCRYPT_MODE_CFB: (void)lcrypt_check(L, cfb_done(&key->data.cfb)); break;
    case LCRYPT_MODE_OFB: (void)lcrypt_check(L, ofb_done(&key->data.ofb)); break;
    case LCRYPT_MODE_LRW: (void)lcrypt_check(L, lrw_done(&key->data.lrw)); break;
    case LCRYPT_MODE_F8:  (void)lcrypt_check(L, f8_done(&key->data.f8));   break;
  }

  key->mode     = LCRYPT_MODE_NONE;
  key->key_size = 0;
  return 0;
}

static int lcrypt_key_size (lua_State *L) {
  lcrypt_key_t *key = luaL_checkudata(L, 1, "LCRYPT_KEY");
  lua_pushinteger(L, key->key_size);
  return 0;
}

static const struct luaL_Reg lcrypt_key_flib[] = {
  {"__index",    &lcrypt_key_index},
  {"__newindex", &lcrypt_key_newindex},
  {"__gc",       &lcrypt_key_gc},
  {"__len",      &lcrypt_key_size},
  {NULL,         NULL}
};

static void lcrypt_start_ciphers (lua_State *L) {
  ADD_FUNCTION(L, key);
  (void)luaL_newmetatable(L, "LCRYPT_KEY");
  (void)luaL_register(L, NULL, lcrypt_key_flib);
  lua_pop(L, 1);
  lua_pushstring(L, "ciphers");
  lua_newtable(L);
  #define ADD_CIPHER(L, name)                                     \
  {                                                               \
    int c = register_cipher(&name ## _desc);                      \
    if(c > lcrypt_max_ciphers) lcrypt_max_ciphers = c;            \
    lua_pushstring(L, #name);                                     \
    lua_pushinteger(L, c);                                        \
    lua_settable(L, -3);                                          \
  }
  ADD_CIPHER(L, blowfish);  ADD_CIPHER(L, xtea);    ADD_CIPHER(L, rc2);     ADD_CIPHER(L, rc5);
  ADD_CIPHER(L, rc6);       ADD_CIPHER(L, saferp);  ADD_CIPHER(L, aes);     ADD_CIPHER(L, twofish);
  ADD_CIPHER(L, des);       ADD_CIPHER(L, des3);    ADD_CIPHER(L, cast5);   ADD_CIPHER(L, noekeon);
  ADD_CIPHER(L, skipjack);  ADD_CIPHER(L, anubis);  ADD_CIPHER(L, khazad);  ADD_CIPHER(L, kseed);
  ADD_CIPHER(L, kasumi);
  #undef ADD_CIPHER
  lua_settable(L, -3);

  #define ADD_MODE(name, value)                                   \
  {                                                               \
    lua_pushstring(L, #name);                                     \
    lua_pushinteger(L, value);                                    \
    lua_settable(L, -3);                                          \
  }
  lua_pushstring(L, "cipher_modes");
  lua_newtable(L);
  ADD_MODE(ecb, LCRYPT_MODE_ECB);  ADD_MODE(cbc, LCRYPT_MODE_CBC);  ADD_MODE(ctr, LCRYPT_MODE_CTR);
  ADD_MODE(cfb, LCRYPT_MODE_CFB);  ADD_MODE(ofb, LCRYPT_MODE_OFB);  ADD_MODE(f8,  LCRYPT_MODE_F8);
  ADD_MODE(lrw, LCRYPT_MODE_LRW);
  #undef ADD_MODE
  lua_settable(L, -3);
}
