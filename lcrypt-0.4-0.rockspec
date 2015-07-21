package = "lcrypt"
version = "0.4-0"

description = {
  summary  = "Lua bindings to libtomcrypt and libtommath",
  detailed = [[
Symmetric ciphers, hashes, microtime, random strings, big integers, and zlib compression
  ]],
  homepage = "http://rocks.simbio.se/lcrypt",
  license = "LGPL v2.1"
}

source = {
  url    = "git://github.com/simbiose/lcrypt.git",
  branch = "v0.4"
}

dependencies = {"lua >= 5.1, < 5.3"}

external_dependencies = {
  platforms = {
    unix = {
      LIBTOMCRYPT = {header="tomcrypt.h", library="tomcrypt"},
      LIBTOMMATH  = {header="tommath.h",  library="tommath"},
      Z           = {header="zlib.h",     library="z"}
    }
  }
}

build = {
  type = "builtin",
  modules = {
    lcrypt = {
      sources   = {"lcrypt.c"},
      defines   = {"_FILE_OFFSET_BITS=64", "USE_LTM", "LTC_SOURCE", "LTM_DESC", "LITTLE_ENDIAN"},
      libraries = {"z", "tommath", "tomcrypt", "util", "m"},
      incdirs   = {"$(LIBTOMCRYPT_INCDIR)", "$(LIBTOMMATH_INCDIR)"},
      libdirs   = {"$(LIBTOMCRYPT_LIBDIR)", "$(LIBTOMMATH_LIBDIR)"}
    }
  }
}