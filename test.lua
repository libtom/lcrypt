local lcrypt = require('lcrypt')

local key, out, check

key   = lcrypt.key('aes', 'ecb', '0123456789abcdef')
out   = key:encrypt('0123456789abcdef0123456789abcdef')
check = key:decrypt(out)

print(out, check)

print( lcrypt.tohex( lcrypt.hash('md5', 'hash', 'bla bla'):done() ) )
