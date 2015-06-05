/**
 *
 * Copyright (c) 2011-2015 David Eder, InterTECH
 * Copyright (c) 2015 Simbiose
 *
 * License: https://www.gnu.org/licenses/lgpl-2.1.html LGPL version 2.1
 *
 */

#include <stdint.h>

static void copy_bits (
    uint8_t *out, unsigned int out_pos, const uint8_t *in, unsigned int in_pos, unsigned int length
  ) {
  unsigned int offset, chunk_size;
  uint8_t temp, mask;

  if(((out_pos | in_pos | length) & 0x07) == 0) { // everything byte aligned?
    out += out_pos >> 3;
    in  += in_pos >> 3;
    for (length >>= 3; length > 0; --length) *out++ = *in++;
    return;
  }

  /* skip untouched out bytes */
  offset  =  out_pos / 8;
  out     += offset;
  out_pos -= offset * 8;

  /* skip untouched in bytes */
  offset =  in_pos / 8;
  in     += offset;
  in_pos -= offset * 8;

  while (length > 0) {
    chunk_size = (in_pos < out_pos) ? 8 - out_pos : 8 - in_pos;
    if (chunk_size == 0) chunk_size = 8;
    if (chunk_size > length) chunk_size = length;

    temp =   (uint8_t)((*in) << in_pos);
    temp >>= out_pos;
    mask =   (uint8_t)(0xff << (8 - chunk_size));
    mask =   (uint8_t)(mask >> out_pos);
    *out |=  mask & temp;

    in_pos += chunk_size;
    if (in_pos >= 8) {
      ++in;
      in_pos -= 8;
    }
    out_pos += chunk_size;
    if (out_pos >= 8) {
      ++out;
      out_pos -= 8;
    }
    length -= chunk_size;
  }
}

static void reverse_data (uint8_t *a, int len) {
  int i;
  uint8_t temp;
  for (i = len / 2 - 1; i >= 0; --i) {
    temp       = a[i];
    a[i]       = a[len-1-i];
    a[len-1-i] = temp;
  }
}

static uint64_t reverse_bits (uint64_t a, int bits) {
  int i;
  uint64_t b = 0;
  for (i = 0; i < bits; ++i) {
    b =   (b << 1) | (a & 1);
    a >>= 1;
  }
  return b;
}

static int64_t sign_extend (uint64_t a, int bits) {
  int64_t sret;
  if ((a & (1 << (bits - 1))) != 0) {
    a = ((uint64_t)0xffffffffffffffffLL << bits) | a;
    memcpy(&sret, &a, 8);
    return sret;
  }
  return (int64_t)a;
}

#define B_SKIP  0
#define B_STR   1
#define B_INT   2
#define B_LSB   4
#define B_LE    8
#define B_SIGN  16

#define BSKIP   B_SKIP
#define BSTR    B_STR
#define BMSB    B_INT
#define BLSB    (B_INT|B_LSB)
#define BLE     (B_INT|B_LE)
#define BSMSB   (B_INT|B_SIGN)
#define BSLSB   (B_INT|B_LSB|B_SIGN)
#define BSLE    (B_INT|B_LE|B_SIGN)

#if BYTE_ORDER == LITTLE_ENDIAN
  #define BMO   BLE
  #define BSMO  BSLE
#else
  #define BMO   BMSB
  #define BSMO  BSMSB
#endif

static int lcrypt_bget (lua_State *L) {
  int count = 0, argc = lua_gettop(L);
  size_t length = 0;
  const unsigned char *in = (const unsigned char*)luaL_checklstring(L, 1, &length);
  int i, type, bits, offset = luaL_checkint(L, 2);
  length *= 8;

  for (i = 3; i <= argc && offset < (int)length; i += 2) {
    type = luaL_checkint(L, i);
    if (i+1 > argc)
      bits = (int)length;
    else
      bits = luaL_checkint(L, i+1);

    if (offset + bits > (int)length) bits = (int)length - offset;
    if (type == B_SKIP) {
      --count;
    } else if (type == B_STR) {
      int len = (bits + 7) / 8;
      uint8_t data[len];
      memset(data, 0, (size_t)len);
      copy_bits(data, 0, (uint8_t*)in, (unsigned int)offset, (unsigned int)bits);
      lua_pushlstring(L, (char*)data, (size_t)len);
    } else {
      /* integer */
      uint64_t ret = 0;
      if (bits > 64) return luaL_error(L, "Numbers must not exceed 64 bits");
      copy_bits((uint8_t*)&ret, (unsigned int)(sizeof(ret) * 8 - bits), (uint8_t*)in, (unsigned int)offset, (unsigned int)bits);
      #if BYTE_ORDER == LITTLE_ENDIAN
        reverse_data((uint8_t*)&ret, (int)sizeof(ret));
      #endif
      if ((type & B_LSB) == B_LSB) ret = reverse_bits(ret, bits);
      #if BYTE_ORDER == LITTLE_ENDIAN
        if ((type & B_LE) == B_LE) reverse_data((uint8_t*)&ret, (bits+7)/8);
      #else
        if ((type & B_LE) == B_LE) reverse_data((uint8_t*)&ret + 8-(bits+7)/8, (bits+7)/8);
      #endif
      if ((type & B_SIGN) == B_SIGN)
        lua_pushnumber(L, (lua_Number)sign_extend(ret, bits));
      else
        lua_pushnumber(L, (lua_Number)ret);
    }

    ++count;
    offset += bits;
  }
  return count;
}

static int lcrypt_bput (lua_State *L) {
  int argc = lua_gettop(L);
  int i, type, bits = 0, offset = 0, len = 0;
  size_t length = 0;

  for (i = 1; i <= argc; i += 3) {
    type = luaL_checkint(L, i+1);
    if (type == B_STR && lua_isnil(L, i+2)) {
      (void)luaL_checklstring(L, i, &length);
      bits = lua_isnil(L, i+2) ? (int)length * 8 : luaL_checkint(L, i+2);
      if (bits > (int)length * 8) bits = (int)length * 8;
    } else {
      bits = luaL_checkint(L, i+2);
    }
    len += bits;
  }

  len = (len + 7) / 8;

  {
    uint8_t ret[len];
    memset(ret, 0, (size_t)len);

    for (i = 1; i <= argc; i += 3) {
      type = luaL_checkint(L, i+1);
      if (type == B_STR) {
        const uint8_t *in = (const uint8_t *)luaL_checklstring(L, i, &length);
        bits = lua_isnil(L, i+2) ? (int)length * 8 : luaL_checkint(L, i+2);
        if (bits > (int)length * 8) bits = (int)length * 8;
        copy_bits(ret, (unsigned int)offset, in, 0, (unsigned int)bits);
      } else if(type != B_SKIP) { /* integer */
        uint64_t in;
        bits = luaL_checkint(L, i+2);
        if ((type & B_SIGN) == B_SIGN) {
          int64_t sin = (int64_t)luaL_checknumber(L, i);
          memcpy(&in, &sin, 8);
        } else {
          in = (uint64_t)luaL_checknumber(L, i);
        }
        #if BYTE_ORDER == LITTLE_ENDIAN
          reverse_data((uint8_t*)&in, (int)sizeof(in));
        #endif

        if ((type & B_LSB) == B_LSB) {
          in = reverse_bits(in, 64);
          copy_bits(ret, (unsigned int)offset, (uint8_t*)&in, 0, (unsigned int)bits);
        } else if((type & B_LE) == B_LE) {
          reverse_data((uint8_t*)&in, (int)sizeof(in));
          copy_bits(ret, (unsigned int)offset, (uint8_t*)&in, 0, (unsigned int)bits);
        } else {
          copy_bits(ret, (unsigned int)offset, (uint8_t*)&in, (unsigned int)(sizeof(in) * 8 - bits), (unsigned int)bits);
        }
      }
      offset += bits;
    }
    lua_pushlstring(L, (char*)ret, (size_t)len);
  }

  return 1;
}

static void lcrypt_start_bits (lua_State *L) {
  ADD_FUNCTION(L, bget);   ADD_FUNCTION(L, bput);
  ADD_CONSTANT(L, BSKIP);  ADD_CONSTANT(L, BSTR);   ADD_CONSTANT(L, BMSB);   ADD_CONSTANT(L, BLSB);
  ADD_CONSTANT(L, BLE);    ADD_CONSTANT(L, BSMSB);  ADD_CONSTANT(L, BSLSB);  ADD_CONSTANT(L, BSLE);
  ADD_CONSTANT(L, BMO);    ADD_CONSTANT(L, BSMO);
}
