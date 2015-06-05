/**
 *
 * Copyright (c) 2011-2015 David Eder, InterTECH
 * Copyright (c) 2015 Simbiose
 *
 * License: https://www.gnu.org/licenses/lgpl-2.1.html LGPL version 2.1
 *
 */

#define HASH_MODE_NONE  0
#define HASH_MODE_HASH  1
#define HASH_MODE_HMAC  2
#define HASH_MODE_OMAC  3

#define HASH_MODE_MAX   3

static int lcrypt_max_hashes = 0;

typedef struct {
  int mode;
  union {
    struct {
      int hash;
      hash_state state;
    } hash;
    hmac_state hmac;
    omac_state omac;
  } data;
} lcrypt_hash_t;

static int _lcrypt_hash_add (lua_State *L, lcrypt_hash_t *h) {
  size_t in_length = 0;
  const unsigned char *in = (const unsigned char*)luaL_optlstring(L, 2, "", &in_length);
  switch (h->mode) {
    case HASH_MODE_HASH: (void)lcrypt_check(L, hash_descriptor[h->data.hash.hash].process(&h->data.hash.state, in, (unsigned long)in_length)); break;
    case HASH_MODE_HMAC: (void)lcrypt_check(L, hmac_process(&h->data.hmac, in, (unsigned long)in_length)); break;
    case HASH_MODE_OMAC: (void)lcrypt_check(L, omac_process(&h->data.omac, in, (unsigned long)in_length)); break;
    default: RETURN_STRING_ERROR(L, "Unknown mode");
  }
  return 0;
}

static int lcrypt_hash_add (lua_State *L) {
  lcrypt_hash_t *h = luaL_checkudata(L, 1, "LCRYPT_HASH");
  return _lcrypt_hash_add(L, h);
}

static int lcrypt_hash_done (lua_State *L) {
  lcrypt_hash_t *h = luaL_checkudata(L, 1, "LCRYPT_HASH");
  (void)_lcrypt_hash_add(L, h);

  switch (h->mode) {
    case HASH_MODE_HASH: {
      unsigned char out[hash_descriptor[h->data.hash.hash].hashsize];
      memset(out, 0, (size_t)hash_descriptor[h->data.hash.hash].hashsize);
      (void)lcrypt_check(L, hash_descriptor[h->data.hash.hash].done(&h->data.hash.state, out));
      lua_pushlstring(L, (char*)out, (size_t)hash_descriptor[h->data.hash.hash].hashsize);
    } break;
    case HASH_MODE_HMAC: {
      unsigned long out_length = hash_descriptor[h->data.hmac.hash].hashsize;
      unsigned char out[out_length];
      memset(out, 0, (size_t)out_length);
      (void)lcrypt_check(L, hmac_done(&h->data.hmac, out, &out_length));
      lua_pushlstring(L, (char*)out, (size_t)out_length);
    } break;
    case HASH_MODE_OMAC: {
      unsigned long out_length = (unsigned long)cipher_descriptor[h->data.omac.cipher_idx].block_length;
      unsigned char out[out_length];
      memset(out, 0, (size_t)out_length);
      (void)lcrypt_check(L, omac_done(&h->data.omac, out, &out_length));
      lua_pushlstring(L, (char*)out, (size_t)out_length);
    } break;
    default:
      RETURN_STRING_ERROR(L, "Unknown mode");
  }

  memset(h, 0, sizeof(lcrypt_hash_t));
  return 1;
}

static int lcrypt_hash_gc (lua_State *L) {
  lcrypt_hash_t *h = luaL_checkudata(L, 1, "LCRYPT_HASH");

  switch (h->mode) {
    case HASH_MODE_HASH: {
      unsigned char out[hash_descriptor[h->data.hash.hash].hashsize];
      memset(out, 0, (size_t)hash_descriptor[h->data.hash.hash].hashsize);
      (void)lcrypt_check(L, hash_descriptor[h->data.hash.hash].done(&h->data.hash.state, out));
    } break;
    case HASH_MODE_HMAC: {
      unsigned long out_length = hash_descriptor[h->data.hmac.hash].hashsize;
      unsigned char out[out_length];
      memset(out, 0, (size_t)out_length);
      (void)lcrypt_check(L, hmac_done(&h->data.hmac, out, &out_length));
    } break;
    case HASH_MODE_OMAC: {
      unsigned long out_length = (unsigned long)cipher_descriptor[h->data.omac.cipher_idx].block_length;
      unsigned char out[out_length];
      memset(out, 0, (size_t)out_length);
      (void)lcrypt_check(L, omac_done(&h->data.omac, out, &out_length));
    } break;
  }

  return 0;
}

static int lcrypt_hash (lua_State *L) {
  int hash = -1, mode = HASH_MODE_NONE;
  /* get hash */
  if(lua_isnumber(L, 1) == 1) {
    hash = luaL_checkint(L, 1);
  } else {
    const char *h = luaL_checkstring(L, 1);
    hash = find_hash(h);
    if(hash < 0) hash = find_cipher(h);
  }
  if (hash < 0 || hash > lcrypt_max_hashes) RETURN_STRING_ERROR(L, "Unknown hash");

  /* get mode */
  if (lua_isnumber(L, 2) == 1) {
    mode = luaL_checkint(L, 2);
  } else {
    const char *m = luaL_checkstring(L, 2);
    if (strcmp(m, "hash") == 0)
      mode = HASH_MODE_HASH;
    else if (strcmp(m, "hmac") == 0)
      mode = HASH_MODE_HMAC;
    else if (strcmp(m, "omac") == 0)
      mode = HASH_MODE_OMAC;
  }
  if (mode <= 0 || mode > HASH_MODE_MAX) RETURN_STRING_ERROR(L, "Unknown mode");

  {
    /* get optional first data chunk */
    size_t in_length = 0, extra_length = 0;
    const unsigned char *in    = (const unsigned char*)luaL_optlstring(L, 3, "", &in_length);
    const unsigned char *extra = (const unsigned char*)luaL_optlstring(L, 4, "", &extra_length);

    /* prepare result */
    lcrypt_hash_t *h = lua_newuserdata(L, sizeof(lcrypt_hash_t));
    luaL_getmetatable(L, "LCRYPT_HASH");
    (void)lua_setmetatable(L, -2);
    memset(h, 0, sizeof(lcrypt_hash_t));

    switch (mode) {
      case HASH_MODE_HASH: {
        h->data.hash.hash = hash;
        (void)lcrypt_check(L, hash_descriptor[hash].init(&h->data.hash.state));
        h->mode = mode;
        (void)lcrypt_check(L, hash_descriptor[hash].process(&h->data.hash.state, in, (unsigned long)in_length));
      } break;
      case HASH_MODE_HMAC: {
        (void)lcrypt_check(L, hmac_init(&h->data.hmac, hash, extra, (unsigned long)extra_length));
        h->mode = mode;
        (void)lcrypt_check(L, hmac_process(&h->data.hmac, in, (unsigned long)in_length));
      } break;
      case HASH_MODE_OMAC: {
        (void)lcrypt_check(L, omac_init(&h->data.omac, hash, extra, (unsigned long)extra_length));
        h->mode = mode;
        (void)lcrypt_check(L, omac_process(&h->data.omac, in, (unsigned long)in_length));
      } break;
      default:
        RETURN_STRING_ERROR(L, "Unknown mode");
    }
  }

  return 1;
}

static int lcrypt_hash_size (lua_State *L) {
  lcrypt_hash_t *h = luaL_checkudata(L, 1, "LCRYPT_HASH");
  switch (h->mode) {
    case HASH_MODE_HASH: lua_pushinteger(L, (lua_Integer)hash_descriptor[h->data.hash.hash].hashsize); return 1;
    case HASH_MODE_HMAC: lua_pushinteger(L, (lua_Integer)hash_descriptor[h->data.hmac.hash].hashsize); return 1;
    case HASH_MODE_OMAC: lua_pushinteger(L, (lua_Integer)cipher_descriptor[h->data.omac.cipher_idx].block_length); return 1;
  }
  return 0;
}

static int lcrypt_hash_index (lua_State *L) {
  lcrypt_hash_t *h = luaL_checkudata(L, 1, "LCRYPT_HASH");
  const char *index = luaL_checkstring(L, 2);
  int hash_index = -1, cipher_index = -1;

  if (strcmp(index, "add") == 0)  { lua_pushcfunction(L, lcrypt_hash_add);  return 1; }
  if (strcmp(index, "done") == 0) { lua_pushcfunction(L, lcrypt_hash_done); return 1; }
  if (strcmp(index, "mode") == 0) {
    switch (h->mode) {
      case HASH_MODE_HASH: lua_pushstring(L, "hash"); return 1;
      case HASH_MODE_HMAC: lua_pushstring(L, "hmac"); return 1;
      case HASH_MODE_OMAC: lua_pushstring(L, "omac"); return 1;
    }
    return 0;
  }

  switch (h->mode) {
    case HASH_MODE_HASH: hash_index = h->data.hash.hash; break;
    case HASH_MODE_HMAC: hash_index = h->data.hmac.hash; break;
  }

  if (hash_index >= 0) {
    if (strcmp(index, "hash") == 0) { lua_pushstring(L, hash_descriptor[hash_index].name); return 1; }
    if (strcmp(index, "size") == 0) { lua_pushinteger(L, (lua_Integer)hash_descriptor[hash_index].hashsize); return 1; }
  }

  if (h->mode == HASH_MODE_OMAC) cipher_index = h->data.omac.cipher_idx;
  if (cipher_index >= 0) {
    if(strcmp(index, "cipher") == 0) { lua_pushstring(L, cipher_descriptor[cipher_index].name); return 1; }
    if(strcmp(index, "size") == 0) { lua_pushinteger(L, (lua_Integer)cipher_descriptor[cipher_index].block_length); return 1; }
  }

  return 0;
}

static const struct luaL_Reg lcrypt_hash_flib[] = {
  {"__index", &lcrypt_hash_index},
  {"__gc",    &lcrypt_hash_gc},
  {"__len",   &lcrypt_hash_size},
  {NULL,      NULL}
};

static void lcrypt_start_hashes(lua_State *L) {
  ADD_FUNCTION(L, hash);
  lua_pushstring(L, "hashes");
  lua_newtable(L);
  #define ADD_HASH(L,name)                                \
  {                                                       \
    int h = register_hash(&name ## _desc);                \
    if(h > lcrypt_max_hashes) lcrypt_max_hashes = h;      \
    lua_pushstring(L, #name);                             \
    lua_pushinteger(L, (lua_Integer)h);                   \
    lua_settable(L, -3);                                  \
  }
  ADD_HASH(L, whirlpool);  ADD_HASH(L, sha512);  ADD_HASH(L, sha384);  ADD_HASH(L, rmd320);
  ADD_HASH(L, sha256);     ADD_HASH(L, rmd256);  ADD_HASH(L, sha224);  ADD_HASH(L, tiger);
  ADD_HASH(L, sha1);       ADD_HASH(L, rmd160);  ADD_HASH(L, rmd128);  ADD_HASH(L, md5);
  ADD_HASH(L, md4);        ADD_HASH(L, md2);
  #undef ADD_HASH
  lua_settable(L, -3);

  lua_pushstring(L, "hash_modes");
  lua_newtable(L);
  #define ADD_MODE(L,name,value)                          \
  {                                                       \
    lua_pushstring(L, #name);                             \
    lua_pushinteger(L, value);                            \
    lua_settable(L, -3);                                  \
  }
  ADD_MODE(L, hash, HASH_MODE_HASH);  ADD_MODE(L, hmac, HASH_MODE_HMAC);  ADD_MODE(L, hmac, HASH_MODE_HMAC);
  #undef ADD_MODE
  lua_settable(L, -3);

  (void)luaL_newmetatable(L, "LCRYPT_HASH");
  (void)luaL_register(L, NULL, lcrypt_hash_flib);
  lua_pop(L, 1);
}
