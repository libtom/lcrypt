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
  url = "git@github.com:simbiose/lcrypt.git",
  dir = "lcrypt",
  tag = "v0.4"
}

dependencies = {"lua >= 5.1, < 5.3"}

external_dependencies = {
  platforms = {
    unix = {
      LIBTOMCRYPT = {header="tomcrypt.h", library="tomcrypt"},
      LIBTOMMATH  = {header="tommath.h",  library="tommath"},
      Z           = {header="z.h",        library="z"}
    }
  }
}

build = {
  type = "builtin",
  modules = {
    ["lcrypt"] = {
      sources   = {
        "lcrypt.c", "lcrypt_bits.c", "lcrypt_ciphers.c", "lcrypt_ciphers.h",
        "lcrypt_hashes.c", "lcrypt_math.c"
      },
      libraries = {"z", "tommath", "tomcrypt"},
    }
  }
}