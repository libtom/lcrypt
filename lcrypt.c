/**
 *
 * Copyright (c) 2011-2015 David Eder, InterTECH
 * Copyright (c) 2015 Simbiose
 *
 * License: https://www.gnu.org/licenses/lgpl-2.1.html LGPL version 2.1
 *
 */

#define LCRYPT_VERSION  "0.4.0.0"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stddef.h>
#include <errno.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/time.h>
#include <zlib.h>
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#if LUA_VERSION_NUM > 501
#define luaL_register(L,n,l)  (luaL_newlib(L,l))
#endif

/* ugly wchar fix for incompatibility between tomcrypt and some wchar implementations */
#define wchar_t hidden_wchar_t
#define LTC_NO_WCHAR
#include <tomcrypt.h>
#undef wchar_t

#ifdef USE_NCIPHER
  #include "nfastapp.h"
  #include "nfkm.h"
  #include "nfutil.h"
  extern NFastApp_Connection nfast_conn;
  extern NFast_AppHandle nfast_app;
#else
  #include <pty.h>
#endif

#define ADD_FUNCTION(L,name) { lua_pushstring(L, #name); lua_pushcfunction(L, lcrypt_ ## name); lua_settable(L, -3); }
#define ADD_CONSTANT(L,name) { lua_pushstring(L, #name); lua_pushinteger(L, (lua_Integer)name); lua_settable(L, -3); }

#define RETURN_STRING_ERROR(L, ...)  return luaL_error(L, __VA_ARGS__)
#define RETURN_CRYPT_ERROR(L, err)   RETURN_STRING_ERROR(L, "%s", error_to_string(err))
#define RETURN_Z_ERROR(L, err)       RETURN_STRING_ERROR(L, "%s", zError(err))
#define RETURN_LIBC_ERROR(L)         RETURN_STRING_ERROR(L, "%s", strerror(errno));

static int lcrypt_check (lua_State *L, int err) {
  if (err != CRYPT_OK) RETURN_CRYPT_ERROR(L, err);
  return 0;
}

#ifdef USE_NCIPHER
#define RETURN_NCIPHER_ERROR(L, err) RETURN_STRING_ERROR(L, NF_Lookup(err, NF_Status_enumtable))
static int ncipher_check (lua_State *L, int err) {
  if (err != CRYPT_OK) RETURN_NCIPHER_ERROR(L, err);
  return 0;
}
#endif

static void* lcrypt_malloc (lua_State *L, size_t size) {
  void *ret = malloc(size);
  if (ret == NULL)
    (void)luaL_error(L, "Out of memory");
  else
    memset(ret, 0, size);

  return ret;
}

#include "lcrypt_ciphers.c"
#include "lcrypt_hashes.c"
#include "lcrypt_math.c"
#include "lcrypt_bits.c"

static int lcrypt_tohex (lua_State *L) {
  const char digits[] = "0123456789ABCDEF";
  size_t in_length = 0, spacer_length = 0, prepend_length = 0;
  const unsigned char *in;
  const char *spacer, *prepend;
  int i, j, pos = 0;
  if (lua_isnil(L, 1)) { lua_pushlstring(L, "", 0); return 1; }
  in = (const unsigned char*)luaL_checklstring(L, 1, &in_length);
  if (in_length == 0) { lua_pushlstring(L, "", 0); return 1; }
  spacer = luaL_optlstring(L, 2, "", &spacer_length);
  prepend = luaL_optlstring(L, 3, "", &prepend_length);

  {
    char *result = lcrypt_malloc(L, prepend_length + in_length * 2 + (in_length - 1) * spacer_length);
    for (j = 0; j < (int)prepend_length; ++j) result[pos++] = prepend[j];
    result[pos++] = digits[((int)*in >> 4) & 0x0f];
    result[pos++] = digits[(int)*in++ & 0x0f];
    for (i = 1; i < (int)in_length; i++) {
      for (j = 0; j < (int)spacer_length; ++j) result[pos++] = spacer[j];
      result[pos++] = digits[((int)*in >> 4) & 0x0f];
      result[pos++] = digits[(int)*in++ & 0x0f];
    }
    lua_pushlstring(L, result, (size_t)pos);
    free(result);
  }

  return 1;
}

static int lcrypt_fromhex (lua_State *L) {
  size_t in_length = 0;
  const char *in = luaL_checklstring(L, 1, &in_length);
  unsigned char result[in_length / 2 + 1];
  int i, d = -1, e = -1, pos = 0;
  memset(result, 0, (size_t)(in_length / 2 + 1));

  for (i = 0; i < (int)in_length; ++i) {
    if (d == -1) {
      if (*in >= '0' && *in <= '9')
        d = (int)(*in - '0');
      else if (*in >= 'A' && *in <= 'F')
        d = (int)(*in - 'A') + 10;
      else if (*in >= 'a' && *in <= 'f')
        d = (int)(*in - 'a') + 10;
    } else if (e == -1) {
      if (*in >= '0' && *in <= '9')
        e = (int)(*in - '0');
      else if (*in >= 'A' && *in <= 'F')
        e = (int)(*in - 'A') + 10;
      else if (*in >= 'a' && *in <= 'f')
        e = (int)(*in - 'a') + 10;
    }

    if (d >= 0 && e >= 0) {
      result[pos++] = (unsigned char)(d << 4 | e);
      d = e = -1;
    }
    ++in;
  }

  lua_pushlstring(L, (char*)result, (size_t)pos);
  return 1;
}

static int lcrypt_compress (lua_State *L) {
  int err;
  size_t inlen = 0;
  const unsigned char *in = (const unsigned char*)luaL_checklstring(L, 1, &inlen);
  uLongf outlen = compressBound((uLong)inlen);
  unsigned char *out = lcrypt_malloc(L, (size_t)outlen);

  if ((err = compress(out, &outlen, in, (uLong)inlen)) != Z_OK) {
    free(out);
    RETURN_Z_ERROR(L, err);
  }

  lua_pushlstring(L, (char*)out, (size_t)outlen);
  free(out);
  return 1;
}

static int lcrypt_uncompress (lua_State *L) {
  int i, err;
  size_t inlen = 0;
  const unsigned char *in = (const unsigned char*)luaL_checklstring(L, 1, &inlen);
  uLongf outlen = (uLongf)(inlen << 1);
  unsigned char *out = NULL;

  for (i = 2; i < 16; ++i) {
    out = lcrypt_malloc(L, (size_t)outlen);
    if ((err = uncompress(out, &outlen, in, (uLong)inlen)) == Z_OK) break;
    if (err != Z_BUF_ERROR) {
      free(out);
      RETURN_Z_ERROR(L, err);
    }
    free(out);
    out = NULL;
    outlen = (uLongf)(inlen << i);
  }

  if (err == Z_BUF_ERROR) {
    free(out);
    RETURN_Z_ERROR(L, err);
  }

  lua_pushlstring(L, (char*)out, (size_t)outlen);
  free(out);
  return 1;
}

static int lcrypt_base64_encode (lua_State *L) {
  int err;
  size_t inlen = 0;
  const unsigned char *in = (const unsigned char*)luaL_checklstring(L, 1, &inlen);
  unsigned long outlen = (unsigned long)((inlen + 3) * 4 / 3);
  unsigned char *out = lcrypt_malloc(L, (size_t)outlen);

  if ((err = base64_encode(in, (unsigned long)inlen, out, &outlen)) != CRYPT_OK) {
    free(out);
    RETURN_CRYPT_ERROR(L, err);
  }

  lua_pushlstring(L, (char*)out, (size_t)outlen);
  free(out);
  return 1;
}

static int lcrypt_base64_decode (lua_State *L) {
  size_t inlen = 0;
  const unsigned char *in = (const unsigned char*)luaL_checklstring(L, 1, &inlen);
  unsigned long outlen = (unsigned long)(inlen * 3 / 4);
  unsigned char *out = lcrypt_malloc(L, (size_t)outlen);
  int err = base64_decode(in, (unsigned long)inlen, out, &outlen);

  if (err != CRYPT_OK) {
    free(out);
    RETURN_CRYPT_ERROR(L, err);
  }

  lua_pushlstring(L, (char*)out, (size_t)outlen);
  free(out);
  return 1;
}

static int lcrypt_crc32 (lua_State *L) {
  size_t inlen = 0;
  const unsigned char *in  = (const unsigned char*)luaL_checklstring(L, 1, &inlen);
  lua_pushnumber(L, crc32(0L, in, inlen) & 0xffffffff);
  return 1;
}

static int lcrypt_xor (lua_State *L) {
  int i;
  size_t a_length = 0, b_length = 0;
  const unsigned char *a = (const unsigned char*)luaL_checklstring(L, 1, &a_length);
  const unsigned char *b = (const unsigned char*)luaL_checklstring(L, 2, &b_length);
  unsigned char *c = NULL;

  if (a_length > b_length) {
    const unsigned char *t;
    size_t temp = a_length;
    a_length = b_length;
    b_length = temp;
    t = a; a = b; b = t;
  }

  c = lcrypt_malloc(L, b_length);
  for (i = 0; i < (int)a_length; ++i) c[i] = a[i] ^ b[i];
  for (; i < (int)b_length; ++i) c[i] = b[i];
  lua_pushlstring(L, (char*)c, b_length);
  free(c);
  return 1;
}

static int lcrypt_sleep (lua_State *L) {
  (void)usleep(1000000.0 * luaL_checknumber(L, 1));
  return(0);
}

static int lcrypt_time (lua_State *L) {
  struct timeval tv;
  memset(&tv, 0, sizeof(tv));
  if(gettimeofday(&tv, NULL) != 0) RETURN_LIBC_ERROR(L);
  lua_pushnumber(L, (double)tv.tv_sec + (double)tv.tv_usec / 1000000.0);
  return(1);
}

static int lcrypt_random (lua_State *L) {
  int len = luaL_checkint(L, 1);

  #ifdef USE_NCIPHER
    M_Command command;
    M_Reply reply;
    M_Status rc;
    memset(&command, 0, sizeof(command));
    memset(&reply, 0, sizeof(reply));
    command.cmd = Cmd_GenerateRandom;
    command.args.generaterandom.lenbytes = len;
    if ((rc = NFastApp_Transact(nfast_conn, NULL, &command, &reply, NULL)) != Status_OK)  RETURN_NCIPHER_ERROR(L, rc);
    if (reply.status != Status_OK) RETURN_NCIPHER_ERROR(L, reply.status);
    if (len != reply.reply.generaterandom.data.len) RETURN_STRING_ERROR(L, "Wrong length returned");
    lua_pushlstring(L, reply.reply.generaterandom.data.ptr, len);
    NFastApp_Free_Reply(nfast_app, NULL, NULL, &reply);
  #else
    FILE *fp;
    char *buffer = lcrypt_malloc(L, (size_t)len);
    if ((fp = fopen("/dev/urandom", "rb")) == NULL) {
      free(buffer);
      RETURN_STRING_ERROR(L, "Unable to open /dev/urandom.");
    }
    
    if (fread(buffer, (size_t)len, 1, fp) != 1) {
      free(buffer);
      (void)fclose(fp);
      RETURN_STRING_ERROR(L, "Unable to read /dev/urandom.");
    }

    (void)fclose(fp);
    lua_pushlstring(L, buffer, (size_t)len);
    free(buffer);
  #endif

  return 1;
}

static FILE *lgetfile (lua_State *L, int index) {
  FILE **fp = lua_touserdata(L, index);
  if (fp == NULL) return NULL;
  if (lua_getmetatable(L, index) != 0) {
    lua_getfield(L, LUA_REGISTRYINDEX, LUA_FILEHANDLE);
    if (lua_rawequal(L, -1, -2) != 0) {
      lua_pop(L, 2);
      return *fp;
    }
    lua_pop(L, 2);
  }
  return NULL;
}

static int lcrypt_tcsetattr (lua_State* L) {
  struct termios old, new;
  FILE *fp = lgetfile(L, 1);
  if (fp == NULL) RETURN_STRING_ERROR(L, "File not found");
  if (tcgetattr(fileno(fp), &old) != 0) RETURN_LIBC_ERROR(L);
  new = old;
  new.c_iflag = luaL_optint(L, 2, (lua_Integer)old.c_iflag);
  new.c_oflag = luaL_optint(L, 3, (lua_Integer)old.c_oflag);
  new.c_cflag = luaL_optint(L, 4, (lua_Integer)old.c_cflag);
  new.c_lflag = luaL_optint(L, 5, (lua_Integer)old.c_lflag);
  if (tcsetattr(fileno(fp), TCSAFLUSH, &new) != 0) RETURN_LIBC_ERROR(L);
  lua_pushinteger(L, (lua_Integer)new.c_iflag);
  lua_pushinteger(L, (lua_Integer)new.c_oflag);
  lua_pushinteger(L, (lua_Integer)new.c_cflag);
  lua_pushinteger(L, (lua_Integer)new.c_lflag);
  return 4;
}

static int lcrypt_flag_add (lua_State *L) {
  lua_Integer a = luaL_checkinteger(L, 1);
  lua_Integer b = luaL_checkinteger(L, 2);
  lua_pushinteger(L, a | b);
  return 1;
}

static int lcrypt_flag_remove (lua_State *L) {
  lua_Integer a = luaL_checkinteger(L, 1);
  lua_Integer b = luaL_checkinteger(L, 2);
  lua_pushinteger(L, a & ~b);
  return 1;
}

#ifndef USE_NCIPHER

typedef struct {
  int fd;
  pid_t pid;
  char *command;
} lcrypt_spawn_t;

static int lcrypt_spawn (lua_State *L) {
  int fd = -1, pid, argc;
  #define MAX_ARGUMENT 128
  const char *command = luaL_checkstring(L, 1); 
  char *cmd = strdup(command);
  char *pos = cmd, *p;
  char *argv[MAX_ARGUMENT];

  for (argc = 0; argc < MAX_ARGUMENT-1; ++argc) {
    /* eat whitespace */
    while (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == '\r') {
      if(*pos == '\\') for(p = pos; *p != '\0'; p++) *p = *(p + 1);
      ++pos;
    }
    /* start of argument found */
    argv[argc] = pos;
    if (*argv[argc] == '"' || *argv[argc] == '\'') { /* quoted argument */
      ++pos;
      while (*pos != *argv[argc] && *pos != '\0') {
        if(*pos == '\\') for(p = pos; *p != '\0'; p++) *p = *(p + 1);
        pos++;
      }
      argv[argc]++;
    } else { /* non-quoted argument */
      while (*pos != ' ' && *pos != '\t' && *pos != '\n' && *pos != '\r' && *pos != '\0') {
        if (*pos == '\\') for (p = pos; *p != '\0'; ++p) *p = *(p + 1);
        pos++;
      }
    }
    if (*pos == '\0') break;
    *pos++ = '\0';
  }

  if (argc == 0) return 0;

  argv[++argc] = NULL;

  errno = 0;
  pid = forkpty(&fd, NULL, NULL, NULL);
  if (pid == 0) { /* child */
    (void)execvp(argv[0], argv);
    /* if we get here, it's an error! */
    RETURN_LIBC_ERROR(L);
  }
  if (errno != 0) RETURN_LIBC_ERROR(L);

  lcrypt_spawn_t *lsp = lua_newuserdata(L, sizeof(lcrypt_spawn_t));
  memset(lsp, 0, sizeof(lcrypt_spawn_t));
  lsp->fd      = fd;
  lsp->pid     = (pid_t)pid;
  lsp->command = cmd;
  luaL_getmetatable(L, "LSPAWN");
  (void)lua_setmetatable(L, -2);
  return 1;
}

static int lcrypt_spawn_close (lua_State *L) {
  lcrypt_spawn_t *lsp = (lcrypt_spawn_t*)luaL_checkudata(L, 1, "LSPAWN");
  if (lsp->pid > 0) {
    (void)kill(lsp->pid, SIGQUIT);
    lsp->pid = -1;
  }
  if (lsp->fd >= 0) {
    (void)close(lsp->fd);
    lsp->fd = -1;
  }
  if (lsp->command != NULL) {
    free(lsp->command);
    lsp->command = NULL;
  }
  return 0;
}

static int lcrypt_spawn_read (lua_State *L) {
  lcrypt_spawn_t *lsp = (lcrypt_spawn_t*)luaL_checkudata(L, 1, "LSPAWN");
  size_t count = (size_t)luaL_optinteger(L, 2, 4096);
  char *buffer;
  if (lsp->fd < 0) RETURN_STRING_ERROR(L, "Spawn closed");
  buffer = lcrypt_malloc(L, count);
  count  = (size_t)read(lsp->fd, buffer, count);

  if (errno != 0) {
    free(buffer);
    RETURN_LIBC_ERROR(L);
  }

  lua_pushlstring(L, buffer, count);
  free(buffer);
  return 1;
}

static int lcrypt_spawn_write (lua_State *L) {
  lcrypt_spawn_t *lsp = (lcrypt_spawn_t*)luaL_checkudata(L, 1, "LSPAWN");
  size_t in_length = 0;
  const char* in = luaL_checklstring(L, 2, &in_length);
  if (lsp->fd < 0) RETURN_STRING_ERROR(L, "Closed");
  if (-1 == write(lsp->fd, in, in_length) || errno != 0) RETURN_LIBC_ERROR(L);
  return 0;
}

static int lcrypt_spawn_index (lua_State *L) {
  (void)luaL_checkudata(L, 1, "LSPAWN");
  {
    const char *index = luaL_checkstring(L, 2);
    if (strcmp(index, "read") == 0)
      lua_pushcfunction(L, lcrypt_spawn_read);
    else if (strcmp(index, "write") == 0)
      lua_pushcfunction(L, lcrypt_spawn_write);
    else if (strcmp(index, "close") == 0)
      lua_pushcfunction(L, lcrypt_spawn_close);
    else
      return 0;
  }
  return 1;
}

static const luaL_Reg lcrypt_spawn_flib[] = {
  {"__gc",  &lcrypt_spawn_close},
  {NULL,    NULL}
};

#endif

static const luaL_Reg lcryptlib[] = {
  {"tohex",         &lcrypt_tohex},         /* data = lcrypt.tohex(data, spacer, prepend)          */
  {"fromhex",       &lcrypt_fromhex},       /* data = lcrypt.fromhex(data)                         */
  {"compress",      &lcrypt_compress},      /* data = lcrypt.compress(data)                        */
  {"uncompress",    &lcrypt_uncompress},    /* data = lcrypt.uncompress(data)                      */
  {"base64_encode", &lcrypt_base64_encode}, /* data = lcrypt.base64_encode(data)                   */
  {"base64_decode", &lcrypt_base64_decode}, /* data = lcrypt.base64_decode(data)                   */
  {"crc32",         &lcrypt_crc32},         /* data = lcrypt.crc32(data)                           */
  {"xor",           &lcrypt_xor},           /* data = lcrypt.xor(data_a, data_b)                   */
  {"sleep",         &lcrypt_sleep},         /* lcrypt.sleep(seconds)                               */
  {"time",          &lcrypt_time},          /* now = lcrypt.time()                                 */
  {"random",        &lcrypt_random},        /* data = lcrypt.random(length)                        */
  {"tcsetattr",     &lcrypt_tcsetattr},     /* lcrypt.tcsetattr(file, iflag, oflag, cflag, lflag)  */
  {"flag_add",      &lcrypt_flag_add},      /* flags = lcrypt.flag_add(flags, flag)                */
  {"flag_remove",   &lcrypt_flag_remove},   /* flags = lcrypt.flag_remove(flags, flag)             */
  #ifndef USE_NCIPHER
    {"spawn",         &lcrypt_spawn},       /* spawn_handle = lcrypt.spawn(command)                */
  #endif
  {NULL,             NULL}
};

int luaopen_lcrypt(lua_State *L);
int luaopen_lcrypt(lua_State *L) {

  #ifndef USE_NCIPHER
    (void)luaL_newmetatable(L, "LSPAWN");
    lua_pushliteral(L, "__index");
    lua_pushcfunction(L, lcrypt_spawn_index);
    lua_rawset(L, -3);
    luaL_register(L, NULL, lcrypt_spawn_flib);
  #endif

  lcrypt_start_ciphers(L);
  lcrypt_start_hashes(L);
  lcrypt_start_math(L);
  lcrypt_start_bits(L);

  lua_pushstring(L, "iflag");
  lua_newtable(L);
  ADD_CONSTANT(L, IGNBRK);  ADD_CONSTANT(L, BRKINT);  ADD_CONSTANT(L, IGNPAR);  ADD_CONSTANT(L, PARMRK);
  ADD_CONSTANT(L, INPCK);   ADD_CONSTANT(L, ISTRIP);  ADD_CONSTANT(L, INLCR);   ADD_CONSTANT(L, IGNCR);
  ADD_CONSTANT(L, ICRNL);   ADD_CONSTANT(L, IXON);    ADD_CONSTANT(L, IXANY);   ADD_CONSTANT(L, IXOFF);
  lua_settable(L, -3);

  lua_pushstring(L, "oflag");
  lua_newtable(L);
  #ifdef OLCUC
    ADD_CONSTANT(L, OLCUC);
  #endif
  #ifdef OFILL
    ADD_CONSTANT(L, OFILL);
  #endif
  #ifdef OFDEL
    ADD_CONSTANT(L, OFDEL);
  #endif
  #ifdef NLDLY
    ADD_CONSTANT(L, NLDLY);
  #endif
  #ifdef CRDLY
    ADD_CONSTANT(L, CRDLY);
  #endif
  #ifdef TABDLY
    ADD_CONSTANT(L, TABDLY);
  #endif
  #ifdef BSDLY
    ADD_CONSTANT(L, BSDLY);
  #endif
  #ifdef VTDLY
    ADD_CONSTANT(L, VTDLY);
  #endif
  #ifdef FFDLY
    ADD_CONSTANT(L, FFDLY);
  #endif
  ADD_CONSTANT(L, OPOST);   ADD_CONSTANT(L, ONLCR);   ADD_CONSTANT(L, OCRNL);   ADD_CONSTANT(L, ONOCR);
  ADD_CONSTANT(L, ONLRET);
  lua_settable(L, -3);

  lua_pushstring(L, "cflag");
  lua_newtable(L);
  ADD_CONSTANT(L, CS5);     ADD_CONSTANT(L, CS6);     ADD_CONSTANT(L, CS7);     ADD_CONSTANT(L, CS8);
  ADD_CONSTANT(L, CSTOPB);  ADD_CONSTANT(L, CREAD);   ADD_CONSTANT(L, PARENB);  ADD_CONSTANT(L, PARODD);
  ADD_CONSTANT(L, HUPCL);   ADD_CONSTANT(L, CLOCAL);
  lua_settable(L, -3);

  lua_pushstring(L, "lflag");
  lua_newtable(L);
  ADD_CONSTANT(L, ISIG);    ADD_CONSTANT(L, ICANON);  ADD_CONSTANT(L, ECHO);    ADD_CONSTANT(L, ECHOE);
  ADD_CONSTANT(L, ECHOK);   ADD_CONSTANT(L, ECHONL);  ADD_CONSTANT(L, NOFLSH);  ADD_CONSTANT(L, TOSTOP);
  ADD_CONSTANT(L, IEXTEN);
  lua_settable(L, -3);

  lua_pushstring(L, "version"); lua_pushstring(L, LCRYPT_VERSION); lua_settable(L, -3);
  luaL_register(L, NULL, lcryptlib);

  return 1;
}