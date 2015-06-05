/**
 *
 * Copyright (c) 2011-2015 David Eder, InterTECH
 * Copyright (c) 2015 Simbiose
 *
 * License: https://www.gnu.org/licenses/lgpl-2.1.html LGPL version 2.1
 *
 */

#ifdef USE_NCIPHER
  #include "simplebignum.h"
  #define SBIGINT_POSITIVE 0x00
  #define SBIGINT_NEGATIVE 0x80
  typedef struct {
    int sign;
    struct NFast_Bignum num;
  } sbigint;
  typedef sbigint lcrypt_bigint;
#else
  typedef void* lcrypt_bigint;
#endif

#ifdef USE_NCIPHER

#define TRANSACT(command, reply)                                                                                    \
{                                                                                                                   \
  M_Status rc;                                                                                                      \
  if((rc = NFastApp_Transact(nfast_conn, NULL, (command), (reply), NULL)) != Status_OK) return rc;                  \
  if((reply)->status != Status_OK) return (reply)->status;                                                          \
}

static int sbigint_create (sbigint *a, const unsigned char *data, int data_length) {
  int i;
  unsigned char *dst;
  const unsigned char *src;
  a->sign          = SBIGINT_POSITIVE;
  a->num.msb_first = a->num.msw_first = 0;

  while (data_length > 0 && *data == 0) {
    data++;
    data_length--;
  }

  if (data_length > sizeof(a->num.bytes)) {
    a->num.nbytes = 0;
    return Status_BufferFull;
  }

  a->num.nbytes = data_length + (4 - data_length % 4) % 4;
  src           = data + data_length - 1;
  dst           = a->num.bytes;

  for (i = 0; i < data_length; i++) *dst++ = *src--;
  for (; i < a->num.nbytes; i++) *dst++ = 0;
  return Status_OK;
}

static void sbigint_copy_bignum (sbigint *dst, M_Bignum src, int sign) {
  dst->sign = sign;
  memcpy(dst->num.bytes, src->bytes, src->nbytes);
  dst->num.nbytes    = src->nbytes;
  dst->num.msb_first = src->msb_first;
  dst->num.msw_first = src->msw_first;
}

static int sbigint_op (
    int op, sbigint *in_a, sbigint *in_b, sbigint *in_c, sbigint *out_a,
    int out_asign, sbigint *out_b, int out_bsign
  ) {

  M_Command command;
  M_Reply reply;
  M_StackOpVal ops[1] = {{op, 0}};
  M_Bignum nn[3]      = { &in_a->num, &in_b->num, &in_c->num };

  memset(&command, 0, sizeof(command));
  memset(&reply, 0, sizeof(reply));

  command.cmd                     = Cmd_BignumOp;
  command.args.bignumop.n_stackin = ((in_b == NULL) ? 1 : ((in_c == NULL) ? 2 : 3));
  command.args.bignumop.stackin   = nn;
  command.args.bignumop.n_ops     = 1;
  command.args.bignumop.ops       = ops;
  TRANSACT(&command, &reply);

  if (reply.reply.bignumop.n_stackout >= 1 && out_a != NULL) sbigint_copy_bignum(out_a, reply.reply.bignumop.stackout[0], out_asign);
  if (reply.reply.bignumop.n_stackout >= 2 && out_b != NULL) sbigint_copy_bignum(out_b, reply.reply.bignumop.stackout[1], out_bsign);

  NFastApp_Free_Reply(nfast_app, NULL, NULL, &reply);
  return Status_OK;
}

static int sbigint_cmp (const sbigint *a, const sbigint *b) {
  int i;
  if (a->num.nbytes > b->num.nbytes) return 1;
  if (a->num.nbytes < b->num.nbytes) return -1;

  for (i = a->num.nbytes - 1; i >= 0; --i) {
    if (a->num.bytes[i] < b->num.bytes[i]) return -1;
    if (a->num.bytes[i] > b->num.bytes[i]) return 1;
  }

  return 0;
}

static int sbigint_add (sbigint *a, sbigint *b, sbigint *c) {
  if (a->sign == b->sign) return sbigint_op(StackOp_Add, a, b, NULL, c, a->sign, NULL, 0);
  if (a->sign == SBIGINT_NEGATIVE) {
    if (sbigint_cmp(b, a) >= 0) return sbigint_op(StackOp_Sub, b, a, NULL, c, SBIGINT_POSITIVE, NULL, 0);
    return sbigint_op(StackOp_Sub, a, b, NULL, c, SBIGINT_NEGATIVE, NULL, 0);
  }
  if (sbigint_cmp(a, b) >= 0) return sbigint_op(StackOp_Sub, a, b, NULL, c, SBIGINT_POSITIVE, NULL, 0);
  return sbigint_op(StackOp_Sub, b, a, NULL, c, SBIGINT_NEGATIVE, NULL, 0);
}

static int sbigint_sub (sbigint *a, sbigint *b, sbigint *c) {
  b->sign = (b->sign == SBIGINT_POSITIVE) ? SBIGINT_NEGATIVE : SBIGINT_POSITIVE;
  int ret = sbigint_add(a, b, c);
  b->sign = (b->sign == SBIGINT_POSITIVE) ? SBIGINT_NEGATIVE : SBIGINT_POSITIVE;
  return ret;
}

static int sbigint_divmod (sbigint *a, sbigint *b, sbigint *c, sbigint *d) {
  return sbigint_op(StackOp_DivMod, a, b, NULL, c, (a->sign == b->sign) ? SBIGINT_POSITIVE : SBIGINT_NEGATIVE, d, SBIGINT_POSITIVE);
}

static int sbigint_mulmod (sbigint *a, sbigint *b, sbigint *n, sbigint *c) {
  M_Command command;
  M_Reply reply;
  M_StackOpVal ops[3] = {{StackOp_Mul,0},{StackOp_Rot,1},{StackOp_Mod,0}};
  M_Bignum nn[3]      = {&n->num,&a->num,&b->num};

  memset(&command, 0, sizeof(command));
  memset(&reply, 0, sizeof(reply));

  command.cmd                     = Cmd_BignumOp;
  command.args.bignumop.n_stackin = 3;
  command.args.bignumop.stackin   = nn;
  command.args.bignumop.n_ops     = 3;
  command.args.bignumop.ops       = ops;

  TRANSACT(&command, &reply);
  sbigint_copy_bignum(c, reply.reply.bignumop.stackout[0], SBIGINT_POSITIVE);
  NFastApp_Free_Reply(nfast_app, NULL, NULL, &reply);
  return Status_OK;
}

static void sbigint_tostring (sbigint *a, unsigned char *ret, int *length) {
  int i;
  *length = a->num.nbytes - 1;
  while (*length > 0 && a->num.bytes[*length] == 0) (*length)--;
  for (i = *length; i >= 0; i--) *ret++ = a->num.bytes[i];
  (*length)++;
}

#endif

static lcrypt_bigint* lcrypt_new_bigint (lua_State *L) {
  lcrypt_bigint *bi = lua_newuserdata(L, sizeof(lcrypt_bigint));
  luaL_getmetatable(L, "LCRYPT_BIGINT");
  (void)lua_setmetatable(L, -2);

  #ifdef USE_NCIPHER
  {
    int err;
    if ((err = sbigint_create(bi, NULL, 0)) != Status_OK) RETURN_NCIPHER_ERROR(L, err);
  }
  #else
    *bi = NULL;
    (void)lcrypt_check(L, ltc_mp.init(bi));
  #endif

  return bi;
}

static int lcrypt_bigint_add (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_add(bi_a, bi_b, bi));
  #else
    (void)lcrypt_check(L, ltc_mp.add(*bi_a, *bi_b, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_sub (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_sub(bi_a, bi_b, bi));
  #else
    (void)lcrypt_check(L, ltc_mp.sub(*bi_a, *bi_b, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_mul (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_op(StackOp_Mul, bi_a, bi_b, NULL, bi, (bi_a->sign == bi_b->sign) ? SBIGINT_POSITIVE : SBIGINT_NEGATIVE, NULL, 0));
  #else
    (void)lcrypt_check(L, ltc_mp.mul(*bi_a, *bi_b, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_div (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_divmod(bi_a, bi_b, bi, NULL));
  #else
    (void)lcrypt_check(L, ltc_mp.mpdiv(*bi_a, *bi_b, *bi, NULL));
  #endif

  return 1;
}

static int lcrypt_bigint_divmod (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_q = lcrypt_new_bigint(L);
  lcrypt_bigint *bi_r = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_divmod(bi_a, bi_b, bi_q, bi_r));
  #else
    (void)lcrypt_check(L, ltc_mp.mpdiv(*bi_a, *bi_b, *bi_q, *bi_r));
  #endif

  return 2;
}

static int lcrypt_bigint_mod (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_divmod(bi_a, bi_b, NULL, bi));
  #else
    (void)lcrypt_check(L, ltc_mp.mpdiv(*bi_a, *bi_b, NULL, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_invmod (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_op(StackOp_ModInv, bi_a, bi_b, NULL, bi, SBIGINT_POSITIVE, NULL, 0));
  #else
    (void)lcrypt_check(L, ltc_mp.invmod(*bi_a, *bi_b, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_mulmod (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_c = luaL_checkudata(L, 3, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_mulmod(bi_a, bi_b, bi_c, bi));
  #else
    (void)lcrypt_check(L, ltc_mp.mulmod(*bi_a, *bi_b, *bi_c, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_exptmod (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_c = luaL_checkudata(L, 3, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_op(StackOp_ModExp, bi_a, bi_b, bi_c, bi, SBIGINT_POSITIVE, NULL, 0));
  #else
    (void)lcrypt_check(L, ltc_mp.exptmod(*bi_a, *bi_b, *bi_c, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_gcd (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_op(StackOp_GCD, bi_a, bi_b, NULL, bi, SBIGINT_POSITIVE, NULL, 0));
  #else
    (void)lcrypt_check(L, ltc_mp.gcd(*bi_a, *bi_b, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_lcm (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    (void)ncipher_check(L, sbigint_op(StackOp_LCM, bi_a, bi_b, NULL, bi, SBIGINT_POSITIVE, NULL, 0));
  #else
    (void)lcrypt_check(L, ltc_mp.lcm(*bi_a, *bi_b, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_unm (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi   = lcrypt_new_bigint(L);

  #ifdef USE_NCIPHER
    sbigint_copy_bignum(bi, &bi_a->num, (bi_a->sign == SBIGINT_POSITIVE) ? SBIGINT_NEGATIVE : SBIGINT_POSITIVE);
  #else
    (void)lcrypt_check(L, ltc_mp.neg(*bi_a, *bi));
  #endif

  return 1;
}

static int lcrypt_bigint_eq (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");

  #ifdef USE_NCIPHER
    lua_pushboolean(L, (sbigint_cmp(bi_a, bi_b) == 0) ? 1 : 0);
  #else
    lua_pushboolean(L, (ltc_mp.compare(*bi_a, *bi_b) == LTC_MP_EQ) ? 1 : 0);
  #endif

  return 1;
}

static int lcrypt_bigint_lt (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");

  #ifdef USE_NCIPHER
    lua_pushboolean(L, (sbigint_cmp(bi_a, bi_b) < 0) ? 1 : 0);
  #else
    lua_pushboolean(L, (ltc_mp.compare(*bi_a, *bi_b) == LTC_MP_LT) ? 1 : 0);
  #endif
  return 1;
}

static int lcrypt_bigint_le (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  lcrypt_bigint *bi_b = luaL_checkudata(L, 2, "LCRYPT_BIGINT");

  #ifdef USE_NCIPHER
    lua_pushboolean(L, (sbigint_cmp(bi_a, bi_b) <= 0) ? 1 : 0);
  #else
    lua_pushboolean(L, (ltc_mp.compare(*bi_a, *bi_b) == LTC_MP_GT) ? 0 : 1);
  #endif

  return 1;
}

static int lcrypt_bigint_tostring (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");

  #ifdef USE_NCIPHER
    unsigned char out[4097];
    int length = sizeof(out);
    sbigint_tostring(bi_a, out + 1, &length);
    if (bi_a->sign == SBIGINT_NEGATIVE || (out[1] & 0x80) == 0x80) {
      out[0] = bi_a->sign;
      lua_pushlstring(L, (char*)out, length + 1);
    } else {
      lua_pushlstring(L, (char*)out + 1, length);
    }
  #else
    size_t out_length  = (size_t)ltc_mp.unsigned_size(*bi_a) + 1;
    unsigned char *out = lcrypt_malloc(L, out_length);
    int err;
    out[0] = (ltc_mp.compare_d(*bi_a, 0) == LTC_MP_LT) ? (unsigned char)0x80 : (unsigned char)0x00;
    if ((err = ltc_mp.unsigned_write(*bi_a, out+1)) != CRYPT_OK) {
      free(out);
      RETURN_CRYPT_ERROR(L, err);
    }
    if (out[0] == (unsigned char)0 && out[1] < (unsigned char)0x7f)
      lua_pushlstring(L, (char*)out+1, out_length-1);
    else
      lua_pushlstring(L, (char*)out, out_length);
    free(out);
  #endif

  return 1;
}

static int lcrypt_bigint_length (lua_State *L) {
  lcrypt_bigint *bi_a = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  #ifdef USE_NCIPHER
    unsigned char out[4097];
    int length = sizeof(out);
    sbigint_tostring(bi_a, out + 1, &length);
    if (bi_a->sign == SBIGINT_NEGATIVE || (out[1] & 0x80) == 0x80) {
      lua_pushinteger(L, length + 1);
    } else {
      lua_pushinteger(L, length);
    }
  #else
    size_t out_length = (size_t)ltc_mp.unsigned_size(*bi_a) + 1;
    unsigned char *out = lcrypt_malloc(L, out_length);
    int err;
    out[0] = (ltc_mp.compare_d(*bi_a, 0) == LTC_MP_LT) ? (unsigned char)0x80 : (unsigned char)0x00;
    if ((err = ltc_mp.unsigned_write(*bi_a, out+1)) != CRYPT_OK) {
      free(out);
      RETURN_CRYPT_ERROR(L, err);
    }
    if (out[0] == (unsigned char)0 && out[1] < (unsigned char)0x7f)
      lua_pushinteger(L, out_length-1);
    else
      lua_pushinteger(L, out_length);
    free(out);
  #endif

  return 1;
}

static int lcrypt_bigint_index (lua_State *L) {
  lcrypt_bigint *bi = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  const char *index = luaL_checkstring(L, 2);

  #ifdef USE_NCIPHER
    if (strcmp(index, "bits") == 0) {
      int len = bi->num.nbytes - 1;
      while (len > 0 && bi->num.bytes[len] == 0) len--;
      int bits = len * 8;
      if (bi->num.bytes[len] & 0x80) bits += 8;
      else if (bi->num.bytes[len] & 0x40) bits += 7;
      else if (bi->num.bytes[len] & 0x20) bits += 6;
      else if (bi->num.bytes[len] & 0x10) bits += 5;
      else if (bi->num.bytes[len] & 0x08) bits += 4;
      else if (bi->num.bytes[len] & 0x04) bits += 3;
      else if (bi->num.bytes[len] & 0x02) bits += 2;
      else bits++;
      lua_pushinteger(L, bits);
      return 1;
    }

    if(strcmp(index, "isprime") == 0) {
      sbigint c;
      int i, prime = 0;
      if (sbigint_op(StackOp_TestPrime, bi, NULL, NULL, &c, SBIGINT_POSITIVE, NULL, 0) != Status_OK) return 0;
      for (i = 0; i < c.num.nbytes; ++i) if (c.num.bytes[i] != 0) { prime = 1; break; }
      lua_pushboolean(L, prime);
      return 1;
    }
  #else
    if (strcmp(index, "bits") == 0) { lua_pushinteger(L, (lua_Integer)ltc_mp.count_bits(*bi)); return 1; }
    if (strcmp(index, "isprime") == 0) {
      int ret = LTC_MP_NO;
      (void)lcrypt_check(L, ltc_mp.isprime(*bi, &ret));
      lua_pushboolean(L, (ret == LTC_MP_YES) ? 1 : 0);
      return 1;
    }
  #endif

  if (strcmp(index, "add")     == 0) { lua_pushcfunction(L, lcrypt_bigint_add); return 1; }
  if (strcmp(index, "sub")     == 0) { lua_pushcfunction(L, lcrypt_bigint_sub); return 1; }
  if (strcmp(index, "mul")     == 0) { lua_pushcfunction(L, lcrypt_bigint_mul); return 1; }
  if (strcmp(index, "div")     == 0) { lua_pushcfunction(L, lcrypt_bigint_divmod); return 1; }
  if (strcmp(index, "mod")     == 0) { lua_pushcfunction(L, lcrypt_bigint_mod); return 1; }
  if (strcmp(index, "gcd")     == 0) { lua_pushcfunction(L, lcrypt_bigint_gcd); return 1; }
  if (strcmp(index, "lcm")     == 0) { lua_pushcfunction(L, lcrypt_bigint_lcm); return 1; }
  if (strcmp(index, "invmod")  == 0) { lua_pushcfunction(L, lcrypt_bigint_invmod); return 1; }
  if (strcmp(index, "mulmod")  == 0) { lua_pushcfunction(L, lcrypt_bigint_mulmod); return 1; }
  if (strcmp(index, "exptmod") == 0) { lua_pushcfunction(L, lcrypt_bigint_exptmod); return 1; }
  return 0;
}

static int lcrypt_bigint_gc (lua_State *L) {
  #ifdef USE_NCIPHER
    (void)luaL_checkudata(L, 1, "LCRYPT_BIGINT");
  #else
    lcrypt_bigint *bi = luaL_checkudata(L, 1, "LCRYPT_BIGINT");
    if(*bi != NULL) {
      ltc_mp.deinit(*bi);
      *bi = NULL;
    }
  #endif

  return 0;
}

static int lcrypt_bigint_create (lua_State *L) {
  #ifdef USE_NCIPHER
    if (lua_isnumber(L, 1) == 1) {
      long n = luaL_checknumber(L, 1);
      lcrypt_bigint *bi = lcrypt_new_bigint(L);
      if (n < 0) {
        bi->sign = SBIGINT_NEGATIVE;
        n = -n;
      }
      bi->num.nbytes = 0;
      while (n != 0 || bi->num.nbytes % 4 != 0) {
        bi->num.bytes[bi->num.nbytes++] = n & 0xff;
        n >>= 8;
      }
    } else {
      size_t n_length   = 0;
      unsigned char *n  = (unsigned char*)luaL_optlstring(L, 1, "", &n_length);
      lcrypt_bigint *bi = lua_newuserdata(L, sizeof(lcrypt_bigint));
      luaL_getmetatable(L, "LCRYPT_BIGINT");
      (void)lua_setmetatable(L, -2);
      (void)ncipher_check(L, sbigint_create(bi, n, n_length));
    }
  #else
    if (lua_isnumber(L, 1) == 1) {
      long n            = (long)luaL_checknumber(L, 1);
      lcrypt_bigint *bi = lcrypt_new_bigint(L);
      if (n < 0) {
        void *temp = NULL;
        int err    = CRYPT_OK;
        (void)lcrypt_check(L, ltc_mp.init(&temp));
        if ((err = ltc_mp.set_int(temp, (unsigned long)-n)) == CRYPT_OK) {
          err = ltc_mp.neg(temp, *bi);
        }
        ltc_mp.deinit(temp);
        (void)lcrypt_check(L, err);
      } else {
        (void)lcrypt_check(L, ltc_mp.set_int(*bi, (unsigned long)n));
      }
    } else {
      size_t n_length   = 0;
      unsigned char *n  = (unsigned char*)luaL_optlstring(L, 1, "", &n_length);
      lcrypt_bigint *bi = lcrypt_new_bigint(L);
      (void)lcrypt_check(L, ltc_mp.unsigned_read(*bi, n, (unsigned long)n_length));
    }
  #endif

  return 1;
}

static const struct luaL_Reg lcrypt_bigint_flib[] = {
  {"__index",    &lcrypt_bigint_index},
  {"__add",      &lcrypt_bigint_add},
  {"__sub",      &lcrypt_bigint_sub},
  {"__mul",      &lcrypt_bigint_mul},
  {"__div",      &lcrypt_bigint_div},
  {"__mod",      &lcrypt_bigint_mod},
  {"__unm",      &lcrypt_bigint_unm},
  {"__eq",       &lcrypt_bigint_eq},
  {"__lt",       &lcrypt_bigint_lt},
  {"__le",       &lcrypt_bigint_le},
  {"__tostring", &lcrypt_bigint_tostring},
  {"__len",      &lcrypt_bigint_length},
  {"__gc",       &lcrypt_bigint_gc},
  {NULL,         NULL}
};

static void lcrypt_start_math (lua_State *L) {
  (void)luaL_newmetatable(L, "LCRYPT_BIGINT");
  (void)luaL_register(L, NULL, lcrypt_bigint_flib);
  lua_pop(L, 1);

  #ifndef USE_NCIPHER
    ltc_mp = ltm_desc;
  #endif

  lua_pushstring(L, "bigint");
  lua_pushcfunction(L, lcrypt_bigint_create);
  lua_settable(L, -3);
}