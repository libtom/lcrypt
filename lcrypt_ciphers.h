/*
Copyright (C) 2011 David Eder, InterTECH

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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

