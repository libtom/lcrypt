local lcrypt = require('lcrypt')

key = lcrypt.key('aes', 'ecb', '0123456789abcdef')


out = key:encrypt('0123456789abcdef0123456789abcdef')

check = key:decrypt(out)

print(out, check)
