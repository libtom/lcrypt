local lcrypt = require('lcrypt')

local rsa = {}

function rsa:pkcs1_pad(data, out_length)
  local asn1 = string.char(0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14)
  return string.char(0x00, 0x01) .. string.char(0xff):rep(out_length - #asn1 - #data - 2) .. asn1 .. data
end

function rsa:encode_int(value, len)
  local ret = ''
  for i=1,len do
    ret = string.char(value % 256) .. ret
    value = math.floor(value / 256)
  end
  return ret
end

function rsa:oaep_g(data, out_length)
  local out,counter = '', 0
  while #out < out_length do
    out = out .. lcrypt.hash('sha1', 'hash', data .. self:encode_int(counter, 4)):done()
    counter = counter + 1
  end
  return out:sub(1, out_length)
end

function rsa:oaep_pad(data, param, out_length)
  out_length = out_length - 1
  local h_length = #data
  local g_length = out_length - h_length
  local seed = lcrypt.random(h_length)
  local c = lcrypt.hash('sha1', 'hash', param):done()
  c = c .. string.rep(string.char(0), g_length - h_length - 2 - #c) .. string.char(0, 1) .. data
  local x = lcrypt.xor(c, self:oaep_g(seed, g_length))
  local y = lcrypt.xor(seed, self:oaep_g(x, h_length))
  return string.char(0) .. x .. y
end

function rsa:oaep_unpad(data, param, out_length)
  data = data:sub(2, #data)
  local g_length = #data - out_length
  local x = data:sub(1, g_length)
  local seed = lcrypt.xor(self:oaep_g(x, out_length), data:sub(g_length +1, #data))
  local c = lcrypt.xor(x, self:oaep_g(seed, g_length))
  local v = lcrypt.hash('sha1', 'hash', param):done()
  if c:sub(1,#v) == v then return c:sub(g_length - out_length + 1, #c) end
end

function rsa:prime(bits)
  bits = math.floor(bits)
  if bits < 24 then return end
  local ret, high, bytes = nil, 1, math.floor((bits - 7) / 8)
  for i=1,bits-bytes*8-1 do high = 1 + high + high end
  high = string.char(high)
  low = lcrypt.random(1):byte()
  if low / 2 == math.floor(low / 2) then low = low + 1 end
  low = string.char(low)
  bytes = bytes - 1
  repeat
    ret = lcrypt.bigint(high .. lcrypt.random(bytes) .. low)
  until ret.isprime
  return ret
end

function rsa:gen_key(bits, e)
  local key,one,p1,q1 = { e=lcrypt.bigint(e) }, lcrypt.bigint(1), nil, nil
  bits = bits / 2
  repeat
    key.p = self:prime(bits)
    p1 = key.p - one
  until p1:gcd(key.e) == one
  repeat
    key.q = self:prime(bits)
    q1 = key.q - one
  until q1:gcd(key.e) == one
  key.d = key.e:invmod(p1:lcm(q1))
  key.n = key.p * key.q
  key.dp = key.d % p1
  key.dq = key.d % q1
  key.qp = key.q:invmod(key.p)
  return key
end

function rsa:private(msg, key)
  msg = lcrypt.bigint(msg)
  local a,b = msg:exptmod(key.dp, key.p), msg:exptmod(key.dq, key.q)
  local ret = tostring(key.qp:mulmod(a - b, key.p) * key.q + b)
  while #ret > key.n.bits / 8 and ret:byte(1) == 0 do ret = ret:sub(2, #ret) end
  while #ret < key.n.bits / 8 do ret = string.char(0) .. ret end
  return ret
end

function rsa:public(msg, key)
  local ret = tostring(lcrypt.bigint(msg):exptmod(key.e, key.n))
  while #ret > key.n.bits / 8 and ret:byte(1) == 0 do ret = ret:sub(2, #ret) end
  while #ret < key.n.bits / 8 do ret = string.char(0) .. ret end
  return ret
end

function rsa:sign_pkcs1(msg, key)
  return self:private(self:pkcs1_pad(lcrypt.hash('sha1', 'hash', msg):done(), key.n.bits / 8), key)
end

function rsa:verify_pkcs1(signature, msg, key)
  msg = lcrypt.hash('sha1', 'hash', msg):done()
  local tmp = self:public(signature, key)
  if tmp:sub(#tmp - #msg + 1, #tmp) == msg then return true end
end

function rsa:sign_oaep(msg, param, key)
  local padded = self:oaep_pad(lcrypt.hash('sha1', 'hash', msg):done(), param, key.n.bits / 8)
  return self:private(padded, key)
end

function rsa:verify_oaep(signature, msg, param, key)
  local padded = self:public(signature, key)
  local hash = lcrypt.hash('sha1', 'hash', msg):done()
  local h = self:oaep_unpad(padded, param, #hash)
  if h == hash then return true end
end



local bits = 2048

local key = rsa:gen_key(2048, 65537)
for k,v in pairs(key) do
  print(k.."=lcrypt.bigint(lcrypt.fromhex('"..lcrypt.tohex(tostring(v)).."'))")
end

local msg = lcrypt.random(bits/8 - 1)
local s   = rsa:sign_oaep(msg, 'test', key)
if rsa:verify_oaep(s, msg, 'test', key) then
  print('ok')
else
  print('doh!')
end

